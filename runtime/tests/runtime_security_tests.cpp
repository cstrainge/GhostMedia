#include <ghostmedia/gm_core.h>
#include <ghostmedia/gm_runtime.h>
#include <ghostmedia/runtime/aes_gcm_provider.h>
#include <ghostmedia/runtime/identity_provider.h>
#include <ghostmedia/runtime/tls_provider.h>

#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <ctime>
#include <cstring>
#include <iostream>
#include <memory>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace {
using Certificate = std::unique_ptr<X509, decltype(&X509_free)>;
using DigestContext = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;
using PublicKey = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;

int failures = 0;

void check(bool condition, const char *message) {
    if (!condition) {
        std::cerr << "FAIL: " << message << '\n';
        ++failures;
    }
}

void check_status(gm_status actual, gm_status expected, const char *message) {
    if (actual != expected) {
        std::cerr << "FAIL: " << message << " expected " << gm_status_string(expected)
                  << " got " << gm_status_string(actual) << '\n';
        ++failures;
    }
}

uint8_t hex_nibble(char character) {
    if (character >= '0' && character <= '9') {
        return static_cast<uint8_t>(character - '0');
    }
    if (character >= 'a' && character <= 'f') {
        return static_cast<uint8_t>(character - 'a' + 10);
    }
    if (character >= 'A' && character <= 'F') {
        return static_cast<uint8_t>(character - 'A' + 10);
    }
    check(false, "hex fixture contains invalid character");
    return 0u;
}

std::vector<uint8_t> bytes_from_hex(std::string_view hex) {
    check(hex.size() % 2u == 0u, "hex fixture has even length");
    std::vector<uint8_t> bytes(hex.size() / 2u);
    for (size_t index = 0; index < bytes.size(); ++index) {
        bytes[index] = static_cast<uint8_t>((hex_nibble(hex[index * 2u]) << 4u) |
                                            hex_nibble(hex[index * 2u + 1u]));
    }
    return bytes;
}

std::string hex_from_bytes(const uint8_t *data, size_t size) {
    constexpr char digits[] = "0123456789abcdef";
    std::string hex;
    hex.reserve(size * 2u);
    for (size_t index = 0; index < size; ++index) {
        hex.push_back(digits[(data[index] >> 4u) & 0x0fu]);
        hex.push_back(digits[data[index] & 0x0fu]);
    }
    return hex;
}

template <size_t Size>
void copy_bytes(uint8_t (&destination)[Size], const std::vector<uint8_t> &source) {
    check(source.size() == Size, "fixture length matches destination");
    std::memcpy(destination, source.data(), Size);
}

gm_bytes vector_bytes(const std::vector<uint8_t> &bytes) {
    return gm_bytes{bytes.empty() ? nullptr : bytes.data(), bytes.size()};
}

std::vector<uint8_t> encode_certificate(X509 *certificate) {
    if (certificate == nullptr) {
        return {};
    }
    const int size = i2d_X509(certificate, nullptr);
    std::vector<uint8_t> der(size > 0 ? static_cast<size_t>(size) : 0u);
    unsigned char *cursor = der.data();
    if (size <= 0 || i2d_X509(certificate, &cursor) != size) {
        der.clear();
    }
    return der;
}

bool replace_extension(X509 *certificate, int nid, const char *value) {
    const int existing_index = X509_get_ext_by_NID(certificate, nid, -1);
    if (existing_index >= 0) {
        X509_EXTENSION_free(X509_delete_ext(certificate, existing_index));
    }
    X509_EXTENSION *extension =
        X509V3_EXT_conf_nid(nullptr, nullptr, nid, const_cast<char *>(value));
    if (extension == nullptr) {
        return false;
    }
    const bool added = X509_add_ext(certificate, extension, -1) == 1;
    X509_EXTENSION_free(extension);
    return added;
}

void test_known_empty_aes_gcm_vector() {
    const std::array<uint8_t, GM_CRYPTO_KEY_BYTES> zero_key{};
    const std::vector<uint8_t> empty_plaintext;
    const std::vector<uint8_t> empty_aad;
    const std::array<uint8_t, GM_MEDIA_NONCE_BYTES> zero_nonce{};
    std::vector<uint8_t> ciphertext;
    std::array<uint8_t, GM_MEDIA_TAG_BYTES> tag{};

    check_status(ghostmedia::runtime::aes256_gcm_encrypt(gm_bytes{zero_key.data(), zero_key.size()},
                                                     gm_bytes{zero_nonce.data(), zero_nonce.size()},
                                                     vector_bytes(empty_aad), vector_bytes(empty_plaintext),
                                                     ciphertext, tag),
                 GM_OK, "Windows AES-GCM adapter encrypts the empty known-answer vector");
    check(ciphertext.empty(), "empty known-answer vector has empty ciphertext");
    check(hex_from_bytes(tag.data(), tag.size()) == "530f8afbc74536b9a963b4f1c4cb738b",
          "Windows AES-GCM adapter empty tag matches NIST vector");
}

void test_media_aead_round_trip_and_tamper() {
    const std::array<uint8_t, GM_CRYPTO_KEY_BYTES> zero_key{};
    const std::vector<uint8_t> session_id = bytes_from_hex("00112233445566778899aabbccddeeff");
    gm_media_header header{};
    header.struct_size = sizeof(header);
    header.abi_version = GM_ABI_VERSION;
    header.kind = GM_MEDIA_KIND_PATH_CHALLENGE;
    copy_bytes(header.session_id, session_id);
    header.stream_id = 1u;
    header.direction = GM_MEDIA_DIRECTION_WIN_TO_APPLE;
    header.key_epoch = 1u;
    header.sequence = 1u;
    header.payload_length = 12u;

    std::array<uint8_t, GM_MEDIA_HEADER_BYTES> aad{};
    std::array<uint8_t, GM_MEDIA_NONCE_BYTES> nonce{};
    size_t written = 0u;
    check_status(gm_media_build_aad(&header, gm_mut_bytes{aad.data(), aad.size()}, &written), GM_OK,
                 "media AAD builds through shared core");
    check_status(gm_media_build_nonce(header.key_epoch, header.sequence, gm_mut_bytes{nonce.data(), nonce.size()}), GM_OK,
                 "media nonce builds through shared core");

    const std::vector<uint8_t> aad_bytes(aad.begin(), aad.end());
    const std::vector<uint8_t> plaintext = bytes_from_hex("000102030405060708090a0b");
    std::vector<uint8_t> ciphertext;
    std::array<uint8_t, GM_MEDIA_TAG_BYTES> tag{};
    check_status(gm_crypto_validate_aead_inputs(gm_bytes{nullptr, GM_CRYPTO_KEY_BYTES}, gm_bytes{nonce.data(), nonce.size()},
                                                gm_bytes{aad.data(), aad.size()}, gm_bytes{plaintext.data(), plaintext.size()},
                                                gm_bytes{tag.data(), tag.size()}),
                 GM_BAD_ARGUMENT, "shared core rejects a missing key pointer before provider use");

    check_status(ghostmedia::runtime::aes256_gcm_encrypt(gm_bytes{zero_key.data(), zero_key.size()},
                                                     gm_bytes{nonce.data(), nonce.size()}, vector_bytes(aad_bytes),
                                                     vector_bytes(plaintext), ciphertext, tag),
                 GM_OK, "Windows AES-GCM adapter encrypts media-shaped input");
    check(hex_from_bytes(ciphertext.data(), ciphertext.size()) == "66b08ccab7604f63c2a92e01",
          "Windows AES-GCM adapter media ciphertext matches locked vector");
    check(hex_from_bytes(tag.data(), tag.size()) == "d85931d533d9a35a11712f140821b2f4",
          "Windows AES-GCM adapter media tag matches locked vector");
    std::vector<uint8_t> recovered;
    check_status(ghostmedia::runtime::aes256_gcm_decrypt(gm_bytes{zero_key.data(), zero_key.size()},
                                                     gm_bytes{nonce.data(), nonce.size()}, vector_bytes(aad_bytes),
                                                     vector_bytes(ciphertext), gm_bytes{tag.data(), tag.size()}, recovered),
                 GM_OK, "Windows AES-GCM adapter decrypts authenticated media-shaped input");
    check(recovered == plaintext, "decrypted plaintext matches original payload");

    std::array<uint8_t, GM_MEDIA_TAG_BYTES> altered_tag = tag;
    altered_tag[0] ^= 0x01u;
    check_status(ghostmedia::runtime::aes256_gcm_decrypt(gm_bytes{zero_key.data(), zero_key.size()},
                                                     gm_bytes{nonce.data(), nonce.size()}, vector_bytes(aad_bytes),
                                                     vector_bytes(ciphertext),
                                                     gm_bytes{altered_tag.data(), altered_tag.size()}, recovered),
                 GM_BAD_MESSAGE, "Windows AES-GCM adapter rejects altered tag");

    std::vector<uint8_t> altered_ciphertext = ciphertext;
    altered_ciphertext[0] ^= 0x01u;
    check_status(ghostmedia::runtime::aes256_gcm_decrypt(gm_bytes{zero_key.data(), zero_key.size()},
                                                     gm_bytes{nonce.data(), nonce.size()}, vector_bytes(aad_bytes),
                                                     vector_bytes(altered_ciphertext), gm_bytes{tag.data(), tag.size()},
                                                     recovered),
                 GM_BAD_MESSAGE, "Windows AES-GCM adapter rejects altered ciphertext");

    std::vector<uint8_t> altered_aad = aad_bytes;
    altered_aad[0] ^= 0x01u;
    check_status(ghostmedia::runtime::aes256_gcm_decrypt(gm_bytes{zero_key.data(), zero_key.size()},
                                                     gm_bytes{nonce.data(), nonce.size()}, vector_bytes(altered_aad),
                                                     vector_bytes(ciphertext), gm_bytes{tag.data(), tag.size()}, recovered),
                 GM_BAD_MESSAGE, "Windows AES-GCM adapter rejects altered AAD");
}

void test_ed25519_identity_profile() {
    std::unique_ptr<ghostmedia::runtime::Ed25519Identity> identity;
    check_status(ghostmedia::runtime::Ed25519Identity::generate(identity), GM_OK,
                 "OpenSSL provider generates an Ed25519 identity");
    check(identity != nullptr, "generated Ed25519 identity is available");
    if (!identity) {
        return;
    }

    std::vector<uint8_t> certificate_der;
    check_status(identity->certificate_der(certificate_der), GM_OK,
                 "Ed25519 identity exports its leaf certificate");
    const unsigned char *certificate_data = certificate_der.data();
    Certificate certificate(d2i_X509(nullptr, &certificate_data, static_cast<long>(certificate_der.size())), X509_free);
    check(certificate != nullptr, "generated certificate is valid DER");
    if (!certificate) {
        return;
    }

    PublicKey public_key(X509_get_pubkey(certificate.get()), EVP_PKEY_free);
    check(public_key != nullptr && EVP_PKEY_id(public_key.get()) == EVP_PKEY_ED25519,
          "generated certificate contains an Ed25519 public key");
    check(X509_verify(certificate.get(), public_key.get()) == 1,
          "generated certificate has a valid Ed25519 self-signature");
    check(X509_get_version(certificate.get()) == 2L, "generated certificate is X.509v3");
    check(certificate_der.size() <= 8192u, "generated certificate fits the protocol DER limit");
    check(ASN1_STRING_length(X509_get_serialNumber(certificate.get())) >= 8,
          "generated certificate serial contains at least 64 bits");
    check(X509_get_ext_by_NID(certificate.get(), NID_subject_alt_name, -1) == -1,
          "generated certificate does not contain a subject alternative name");

    int validity_days = 0;
    int validity_seconds = 0;
    check(ASN1_TIME_diff(&validity_days, &validity_seconds,
                         X509_get0_notBefore(certificate.get()), X509_get0_notAfter(certificate.get())) == 1 &&
              validity_days <= 825 && (validity_days < 825 || validity_seconds == 0),
          "generated certificate validity does not exceed 825 days");

    int critical = 0;
    BASIC_CONSTRAINTS *basic_constraints = static_cast<BASIC_CONSTRAINTS *>(
        X509_get_ext_d2i(certificate.get(), NID_basic_constraints, &critical, nullptr));
    check(basic_constraints != nullptr && critical == 1 && basic_constraints->ca == 0,
          "generated certificate has critical CA=FALSE basic constraints");
    BASIC_CONSTRAINTS_free(basic_constraints);

    ASN1_BIT_STRING *key_usage = static_cast<ASN1_BIT_STRING *>(
        X509_get_ext_d2i(certificate.get(), NID_key_usage, &critical, nullptr));
    check(key_usage != nullptr && critical == 1 && ASN1_BIT_STRING_get_bit(key_usage, 0) == 1,
          "generated certificate has critical digitalSignature key usage");
    ASN1_BIT_STRING_free(key_usage);

    EXTENDED_KEY_USAGE *extended_key_usage = static_cast<EXTENDED_KEY_USAGE *>(
        X509_get_ext_d2i(certificate.get(), NID_ext_key_usage, &critical, nullptr));
    bool has_client_auth = false;
    bool has_server_auth = false;
    if (extended_key_usage != nullptr) {
        for (int index = 0; index < sk_ASN1_OBJECT_num(extended_key_usage); ++index) {
            const int nid = OBJ_obj2nid(sk_ASN1_OBJECT_value(extended_key_usage, index));
            has_client_auth = has_client_auth || nid == NID_client_auth;
            has_server_auth = has_server_auth || nid == NID_server_auth;
        }
    }
    check(extended_key_usage != nullptr && has_client_auth && has_server_auth,
          "generated certificate permits client and server authentication");
    EXTENDED_KEY_USAGE_free(extended_key_usage);

    std::vector<uint8_t> spki;
    std::array<uint8_t, GM_SPKI_DIGEST_BYTES> digest{};
    check_status(identity->public_key_spki_der(spki), GM_OK, "identity exports canonical SPKI DER");
    check_status(identity->spki_sha256(digest), GM_OK, "identity computes its SPKI SHA-256 digest");
    check(!spki.empty() && digest != std::array<uint8_t, GM_SPKI_DIGEST_BYTES>{},
          "SPKI identity material is non-empty");

        std::array<uint8_t, GM_PEER_ID_BASE32_BYTES + 1u> peer_id{};
        size_t peer_id_written = 0u;
        check_status(gm_identity_encode_peer_id(gm_bytes{digest.data(), digest.size()},
                                  gm_mut_bytes{peer_id.data(), peer_id.size()}, &peer_id_written),
                 GM_OK, "generated identity digest encodes through the shared peer ID helper");
        check(peer_id_written == peer_id.size() && peer_id.back() == 0u,
            "generated identity peer ID is lowercase base32 text with terminator");

    const std::vector<uint8_t> message = bytes_from_hex("00112233445566778899aabbccddeeff");
    std::vector<uint8_t> signature;
    check_status(identity->sign(vector_bytes(message), signature), GM_OK,
                 "Ed25519 identity signs a test message");
    DigestContext verify_context(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    check(verify_context &&
              EVP_DigestVerifyInit(verify_context.get(), nullptr, nullptr, nullptr, public_key.get()) == 1 &&
              EVP_DigestVerify(verify_context.get(), signature.data(), signature.size(),
                               message.data(), message.size()) == 1,
          "generated Ed25519 signature verifies with the certificate public key");

    std::vector<uint8_t> private_key;
    check_status(identity->private_key_pkcs8(private_key), GM_OK,
                 "identity exports PKCS#8 private-key bytes");
    std::unique_ptr<ghostmedia::runtime::Ed25519Identity> restored;
    check_status(
        ghostmedia::runtime::Ed25519Identity::load(
            vector_bytes(private_key),
            vector_bytes(certificate_der),
            restored),
        GM_OK,
        "identity reloads from protected-storage bytes");
    std::array<uint8_t, GM_SPKI_DIGEST_BYTES> restored_digest{};
    check(restored != nullptr &&
              restored->spki_sha256(restored_digest) == GM_OK &&
              restored_digest == digest,
          "reloaded identity retains the same SPKI digest");

    std::vector<uint8_t> private_key_raw;
    check_status(identity->private_key_raw(private_key_raw), GM_OK,
                 "identity exports the legacy raw private-key form");
    std::unique_ptr<ghostmedia::runtime::Ed25519Identity> migrated;
    check_status(
        ghostmedia::runtime::Ed25519Identity::load_raw_private_key(
            vector_bytes(private_key_raw),
            vector_bytes(certificate_der),
            migrated),
        GM_OK,
        "legacy raw Ed25519 material migrates into a runtime identity");
    std::array<uint8_t, GM_SPKI_DIGEST_BYTES> migrated_digest{};
    check(migrated != nullptr &&
              migrated->spki_sha256(migrated_digest) == GM_OK &&
              migrated_digest == digest,
          "legacy identity migration preserves the SPKI digest");

    PublicKey private_key_handle(
        EVP_PKEY_new_raw_private_key(
            EVP_PKEY_ED25519,
            nullptr,
            private_key_raw.data(),
            private_key_raw.size()),
        EVP_PKEY_free);
    check(private_key_handle != nullptr,
          "legacy raw private key reloads for certificate-profile fixtures");
    if (!private_key_handle) {
        return;
    }

    Certificate critical_eku(X509_dup(certificate.get()), X509_free);
    check(critical_eku != nullptr &&
              replace_extension(
                  critical_eku.get(),
                  NID_ext_key_usage,
                  "critical,clientAuth,serverAuth") &&
              X509_sign(critical_eku.get(), private_key_handle.get(), nullptr) > 0,
          "critical EKU certificate fixture builds");
    std::unique_ptr<ghostmedia::runtime::Ed25519Identity> critical_eku_identity;
    const std::vector<uint8_t> critical_eku_der = encode_certificate(critical_eku.get());
    check_status(
        ghostmedia::runtime::Ed25519Identity::load(
            vector_bytes(private_key),
            vector_bytes(critical_eku_der),
            critical_eku_identity),
        GM_OK,
        "certificate profile accepts an exact critical extended key usage");

    Certificate extra_key_usage(X509_dup(certificate.get()), X509_free);
    check(extra_key_usage != nullptr &&
              replace_extension(
                  extra_key_usage.get(),
                  NID_key_usage,
                  "critical,digitalSignature,keyEncipherment") &&
              X509_sign(extra_key_usage.get(), private_key_handle.get(), nullptr) > 0,
          "extra key-usage certificate fixture builds");
    std::unique_ptr<ghostmedia::runtime::Ed25519Identity> invalid_usage_identity;
    const std::vector<uint8_t> extra_key_usage_der =
        encode_certificate(extra_key_usage.get());
    check_status(
        ghostmedia::runtime::Ed25519Identity::load(
            vector_bytes(private_key),
            vector_bytes(extra_key_usage_der),
            invalid_usage_identity),
        GM_BAD_MESSAGE,
        "certificate profile rejects key usage beyond digitalSignature");

    Certificate expired(X509_dup(certificate.get()), X509_free);
    check(expired != nullptr &&
              X509_gmtime_adj(X509_getm_notBefore(expired.get()), -172800L) != nullptr &&
              X509_gmtime_adj(X509_getm_notAfter(expired.get()), -86400L) != nullptr &&
              X509_sign(expired.get(), private_key_handle.get(), nullptr) > 0,
          "expired certificate fixture builds");
    std::unique_ptr<ghostmedia::runtime::Ed25519Identity> expired_identity;
    const std::vector<uint8_t> expired_der = encode_certificate(expired.get());
    check_status(
        ghostmedia::runtime::Ed25519Identity::load(
            vector_bytes(private_key),
            vector_bytes(expired_der),
            expired_identity),
        GM_STATE_CONFLICT,
        "expired identity requests certificate renewal");
    std::unique_ptr<ghostmedia::runtime::Ed25519Identity> expired_legacy_identity;
    check_status(
        ghostmedia::runtime::Ed25519Identity::load_raw_private_key(
            vector_bytes(private_key_raw),
            vector_bytes(expired_der),
            expired_legacy_identity),
        GM_STATE_CONFLICT,
        "expired legacy identity requests certificate renewal");
    std::unique_ptr<ghostmedia::runtime::Ed25519Identity> renewed;
    check_status(
        ghostmedia::runtime::Ed25519Identity::renew_certificate(
            vector_bytes(private_key),
            renewed),
        GM_OK,
        "expired identity renews from its existing PKCS#8 key");
    std::array<uint8_t, GM_SPKI_DIGEST_BYTES> renewed_digest{};
    check(renewed != nullptr &&
              renewed->spki_sha256(renewed_digest) == GM_OK &&
              renewed_digest == digest,
          "certificate renewal preserves the SPKI digest");
    std::unique_ptr<ghostmedia::runtime::Ed25519Identity> renewed_legacy;
    check_status(
        ghostmedia::runtime::Ed25519Identity::renew_raw_private_key(
            vector_bytes(private_key_raw),
            renewed_legacy),
        GM_OK,
        "expired legacy identity renews from its raw private key");
    std::array<uint8_t, GM_SPKI_DIGEST_BYTES> renewed_legacy_digest{};
    check(renewed_legacy != nullptr &&
              renewed_legacy->spki_sha256(renewed_legacy_digest) == GM_OK &&
              renewed_legacy_digest == digest,
          "legacy certificate renewal preserves the SPKI digest");

    std::vector<uint8_t> oversized_certificate(
        GM_IDENTITY_LEAF_DER_MAX_BYTES + 1u,
        0u);
    std::unique_ptr<ghostmedia::runtime::Ed25519Identity> oversized_identity;
    check_status(
        ghostmedia::runtime::Ed25519Identity::load(
            vector_bytes(private_key),
            vector_bytes(oversized_certificate),
            oversized_identity),
        GM_BAD_ARGUMENT,
        "persisted certificates larger than the protocol limit are rejected");
}

void test_tls13_mutual_auth_and_exporter() {
    std::unique_ptr<ghostmedia::runtime::Ed25519Identity> client;
    std::unique_ptr<ghostmedia::runtime::Ed25519Identity> server;
    check_status(ghostmedia::runtime::Ed25519Identity::generate(client), GM_OK,
                 "TLS test client identity generates");
    check_status(ghostmedia::runtime::Ed25519Identity::generate(server), GM_OK,
                 "TLS test server identity generates");
    if (!client || !server) {
        return;
    }

    std::array<uint8_t, GM_TLS_EXPORTER_CONTEXT_BYTES> context{};
    for (size_t index = 0; index < context.size(); ++index) {
        context[index] = static_cast<uint8_t>(index);
    }
    std::array<uint8_t, GM_TLS_EXPORTER_OUTPUT_BYTES> client_output{};
    std::array<uint8_t, GM_TLS_EXPORTER_OUTPUT_BYTES> server_output{};
    check_status(
        ghostmedia::runtime::tls13_exporter_pair(
            *client,
            *server,
            gm_bytes{context.data(), context.size()},
            client_output,
            server_output),
        GM_OK,
        "OpenSSL runtime completes pinned mutual TLS 1.3");
    check(client_output == server_output,
          "both TLS peers produce identical exporter output");
    check(client_output != std::array<uint8_t, GM_TLS_EXPORTER_OUTPUT_BYTES>{},
          "TLS exporter output is nonzero");

    std::array<uint8_t, GM_SPKI_DIGEST_BYTES> client_digest{};
    std::array<uint8_t, GM_SPKI_DIGEST_BYTES> server_digest{};
    check_status(client->spki_sha256(client_digest), GM_OK,
                 "TLS client digest is available");
    check_status(server->spki_sha256(server_digest), GM_OK,
                 "TLS server digest is available");
    server_digest[0] ^= 0x01u;
    check_status(
        ghostmedia::runtime::tls13_exporter_pair_with_pins(
            *client,
            *server,
            gm_bytes{server_digest.data(), server_digest.size()},
            gm_bytes{client_digest.data(), client_digest.size()},
            gm_bytes{context.data(), context.size()},
            client_output,
            server_output),
        GM_UNAUTHORIZED,
        "mutual TLS rejects a mismatched server SPKI pin");
}

void test_tcp_loopback() {
    gm_runtime_tcp_socket *listener = nullptr;
    check_status(gm_runtime_tcp_listen_ipv4(0u, 5000u, &listener), GM_OK,
                 "runtime TCP listener binds an ephemeral port");
    if (listener == nullptr) {
        return;
    }
    uint16_t port = 0u;
    check_status(gm_runtime_tcp_local_port(listener, &port), GM_OK,
                 "runtime TCP listener reports its bound port");
    check(port != 0u, "runtime TCP listener receives a nonzero ephemeral port");

    gm_status server_status = GM_INTERNAL;
    std::thread server_thread([&] {
        gm_runtime_tcp_socket *accepted = nullptr;
        server_status = gm_runtime_tcp_accept(listener, 5000u, &accepted);
        if (server_status != GM_OK || accepted == nullptr) {
            return;
        }
        std::array<uint8_t, 4> request{};
        server_status = gm_runtime_tcp_receive_exact(
            accepted,
            gm_mut_bytes{request.data(), request.size()});
        if (server_status == GM_OK && request == std::array<uint8_t, 4>{'p', 'i', 'n', 'g'}) {
            constexpr std::array<uint8_t, 4> response{'p', 'o', 'n', 'g'};
            server_status = gm_runtime_tcp_send_all(
                accepted,
                gm_bytes{response.data(), response.size()});
        } else if (server_status == GM_OK) {
            server_status = GM_BAD_MESSAGE;
        }
        gm_runtime_tcp_socket_destroy(accepted);
    });

    gm_runtime_tcp_socket *client = nullptr;
    check_status(gm_runtime_tcp_connect("127.0.0.1", port, 5000u, &client), GM_OK,
                 "runtime TCP client connects to the listener");
    if (client != nullptr) {
        constexpr std::array<uint8_t, 4> request{'p', 'i', 'n', 'g'};
        check_status(
            gm_runtime_tcp_send_all(client, gm_bytes{request.data(), request.size()}),
            GM_OK,
            "runtime TCP client sends a complete payload");
        std::array<uint8_t, 4> response{};
        check_status(
            gm_runtime_tcp_receive_exact(
                client,
                gm_mut_bytes{response.data(), response.size()}),
            GM_OK,
            "runtime TCP client receives a complete payload");
        check(response == std::array<uint8_t, 4>{'p', 'o', 'n', 'g'},
              "runtime TCP loopback preserves bytes");
        gm_runtime_tcp_socket_destroy(client);
    }
    server_thread.join();
    check_status(server_status, GM_OK, "runtime TCP server completes loopback");
    gm_runtime_tcp_socket_destroy(listener);
}

void test_tcp_accept_timeout() {
    gm_runtime_tcp_socket *listener = nullptr;
    check_status(gm_runtime_tcp_listen_ipv4(0u, 5000u, &listener), GM_OK,
                 "timeout test listener binds");
    if (listener == nullptr) {
        return;
    }
    const auto started = std::chrono::steady_clock::now();
    gm_runtime_tcp_socket *accepted = nullptr;
    check_status(gm_runtime_tcp_accept(listener, 50u, &accepted), GM_INTERNAL,
                 "runtime TCP accept reports its deadline");
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - started);
    check(accepted == nullptr, "timed-out accept does not produce a connection");
    check(elapsed.count() >= 20 && elapsed.count() < 1000,
          "runtime TCP accept returns near the requested deadline");
    gm_runtime_tcp_socket_destroy(listener);
}

void test_tls13_over_runtime_tcp() {
    std::unique_ptr<ghostmedia::runtime::Ed25519Identity> client_identity;
    std::unique_ptr<ghostmedia::runtime::Ed25519Identity> server_identity;
    check_status(ghostmedia::runtime::Ed25519Identity::generate(client_identity), GM_OK,
                 "network TLS client identity generates");
    check_status(ghostmedia::runtime::Ed25519Identity::generate(server_identity), GM_OK,
                 "network TLS server identity generates");
    if (!client_identity || !server_identity) {
        return;
    }

    std::array<uint8_t, GM_SPKI_DIGEST_BYTES> client_digest{};
    std::array<uint8_t, GM_SPKI_DIGEST_BYTES> server_digest{};
    check_status(client_identity->spki_sha256(client_digest), GM_OK,
                 "network TLS client digest is available");
    check_status(server_identity->spki_sha256(server_digest), GM_OK,
                 "network TLS server digest is available");

    gm_runtime_tcp_socket *listener = nullptr;
    check_status(gm_runtime_tcp_listen_ipv4(0u, 5000u, &listener), GM_OK,
                 "network TLS listener binds");
    if (listener == nullptr) {
        return;
    }
    uint16_t port = 0u;
    check_status(gm_runtime_tcp_local_port(listener, &port), GM_OK,
                 "network TLS listener reports its port");

    std::array<uint8_t, GM_TLS_EXPORTER_CONTEXT_BYTES> context{};
    for (size_t index = 0; index < context.size(); ++index) {
        context[index] = static_cast<uint8_t>(0xa0u + index);
    }
    std::array<uint8_t, GM_TLS_EXPORTER_OUTPUT_BYTES> server_exporter{};
    gm_status server_status = GM_INTERNAL;
    std::thread server_thread([&] {
        gm_runtime_tcp_socket *accepted = nullptr;
        server_status = gm_runtime_tcp_accept(listener, 5000u, &accepted);
        std::unique_ptr<ghostmedia::runtime::TlsSession> tls;
        if (server_status == GM_OK) {
            server_status = ghostmedia::runtime::TlsSession::create_server(
                accepted,
                *server_identity,
                gm_bytes{client_digest.data(), client_digest.size()},
                tls);
        }
        if (server_status == GM_OK) {
            server_status = tls->handshake();
        }
        if (server_status == GM_OK) {
            server_status = tls->exporter(
                gm_bytes{context.data(), context.size()},
                server_exporter);
        }
        std::array<uint8_t, 4> request{};
        if (server_status == GM_OK) {
            server_status = tls->receive_exact(
                gm_mut_bytes{request.data(), request.size()});
        }
        if (server_status == GM_OK &&
            request == std::array<uint8_t, 4>{'p', 'i', 'n', 'g'}) {
            constexpr std::array<uint8_t, 4> response{'p', 'o', 'n', 'g'};
            server_status = tls->send_all(
                gm_bytes{response.data(), response.size()});
        } else if (server_status == GM_OK) {
            server_status = GM_BAD_MESSAGE;
        }
        tls.reset();
        gm_runtime_tcp_socket_destroy(accepted);
    });

    gm_runtime_tcp_socket *client_socket = nullptr;
    check_status(gm_runtime_tcp_connect("127.0.0.1", port, 5000u, &client_socket), GM_OK,
                 "network TLS client connects");
    std::unique_ptr<ghostmedia::runtime::TlsSession> client_tls;
    check_status(
        ghostmedia::runtime::TlsSession::create_client(
            client_socket,
            *client_identity,
            gm_bytes{server_digest.data(), server_digest.size()},
            client_tls),
        GM_OK,
        "network TLS client session initializes");
    if (client_tls) {
        check_status(client_tls->handshake(), GM_OK,
                     "network TLS client handshake completes");
        std::array<uint8_t, GM_TLS_EXPORTER_OUTPUT_BYTES> client_exporter{};
        check_status(
            client_tls->exporter(
                gm_bytes{context.data(), context.size()},
                client_exporter),
            GM_OK,
            "network TLS client exports keying material");
        constexpr std::array<uint8_t, 4> request{'p', 'i', 'n', 'g'};
        check_status(
            client_tls->send_all(gm_bytes{request.data(), request.size()}),
            GM_OK,
            "network TLS client sends encrypted application data");
        std::array<uint8_t, 4> response{};
        check_status(
            client_tls->receive_exact(
                gm_mut_bytes{response.data(), response.size()}),
            GM_OK,
            "network TLS client receives encrypted application data");
        check(response == std::array<uint8_t, 4>{'p', 'o', 'n', 'g'},
              "network TLS preserves application bytes");
        server_thread.join();
        check_status(server_status, GM_OK,
                     "network TLS server completes handshake and I/O");
        check(client_exporter == server_exporter,
              "network TLS peers produce identical exporter output");
    } else {
        server_thread.join();
    }
    client_tls.reset();
    gm_runtime_tcp_socket_destroy(client_socket);
    gm_runtime_tcp_socket_destroy(listener);
}
}

int main() {
    test_known_empty_aes_gcm_vector();
    test_media_aead_round_trip_and_tamper();
    test_ed25519_identity_profile();
    test_tls13_mutual_auth_and_exporter();
    test_tcp_loopback();
    test_tcp_accept_timeout();
    test_tls13_over_runtime_tcp();

    if (failures != 0) {
        std::cerr << failures << " failure(s)\n";
        return 1;
    }
    return 0;
}