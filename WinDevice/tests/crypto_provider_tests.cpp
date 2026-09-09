#include <ghostmedia/gm_core.h>
#include <ghostmedia/win/aes_gcm_provider.h>
#include <ghostmedia/win/identity_provider.h>

#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <ctime>
#include <cstring>
#include <iostream>
#include <memory>
#include <string>
#include <string_view>
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

void test_known_empty_aes_gcm_vector() {
    const std::array<uint8_t, GM_CRYPTO_KEY_BYTES> zero_key{};
    const std::vector<uint8_t> empty_plaintext;
    const std::vector<uint8_t> empty_aad;
    const std::array<uint8_t, GM_MEDIA_NONCE_BYTES> zero_nonce{};
    std::vector<uint8_t> ciphertext;
    std::array<uint8_t, GM_MEDIA_TAG_BYTES> tag{};

    check_status(ghostmedia::win::aes256_gcm_encrypt(gm_bytes{zero_key.data(), zero_key.size()},
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

    check_status(ghostmedia::win::aes256_gcm_encrypt(gm_bytes{zero_key.data(), zero_key.size()},
                                                     gm_bytes{nonce.data(), nonce.size()}, vector_bytes(aad_bytes),
                                                     vector_bytes(plaintext), ciphertext, tag),
                 GM_OK, "Windows AES-GCM adapter encrypts media-shaped input");
    check(hex_from_bytes(ciphertext.data(), ciphertext.size()) == "66b08ccab7604f63c2a92e01",
          "Windows AES-GCM adapter media ciphertext matches locked vector");
    check(hex_from_bytes(tag.data(), tag.size()) == "d85931d533d9a35a11712f140821b2f4",
          "Windows AES-GCM adapter media tag matches locked vector");
    std::vector<uint8_t> recovered;
    check_status(ghostmedia::win::aes256_gcm_decrypt(gm_bytes{zero_key.data(), zero_key.size()},
                                                     gm_bytes{nonce.data(), nonce.size()}, vector_bytes(aad_bytes),
                                                     vector_bytes(ciphertext), gm_bytes{tag.data(), tag.size()}, recovered),
                 GM_OK, "Windows AES-GCM adapter decrypts authenticated media-shaped input");
    check(recovered == plaintext, "decrypted plaintext matches original payload");

    std::array<uint8_t, GM_MEDIA_TAG_BYTES> altered_tag = tag;
    altered_tag[0] ^= 0x01u;
    check_status(ghostmedia::win::aes256_gcm_decrypt(gm_bytes{zero_key.data(), zero_key.size()},
                                                     gm_bytes{nonce.data(), nonce.size()}, vector_bytes(aad_bytes),
                                                     vector_bytes(ciphertext),
                                                     gm_bytes{altered_tag.data(), altered_tag.size()}, recovered),
                 GM_BAD_MESSAGE, "Windows AES-GCM adapter rejects altered tag");

    std::vector<uint8_t> altered_ciphertext = ciphertext;
    altered_ciphertext[0] ^= 0x01u;
    check_status(ghostmedia::win::aes256_gcm_decrypt(gm_bytes{zero_key.data(), zero_key.size()},
                                                     gm_bytes{nonce.data(), nonce.size()}, vector_bytes(aad_bytes),
                                                     vector_bytes(altered_ciphertext), gm_bytes{tag.data(), tag.size()},
                                                     recovered),
                 GM_BAD_MESSAGE, "Windows AES-GCM adapter rejects altered ciphertext");

    std::vector<uint8_t> altered_aad = aad_bytes;
    altered_aad[0] ^= 0x01u;
    check_status(ghostmedia::win::aes256_gcm_decrypt(gm_bytes{zero_key.data(), zero_key.size()},
                                                     gm_bytes{nonce.data(), nonce.size()}, vector_bytes(altered_aad),
                                                     vector_bytes(ciphertext), gm_bytes{tag.data(), tag.size()}, recovered),
                 GM_BAD_MESSAGE, "Windows AES-GCM adapter rejects altered AAD");
}

void test_ed25519_identity_profile() {
    std::unique_ptr<ghostmedia::win::Ed25519Identity> identity;
    check_status(ghostmedia::win::Ed25519Identity::generate(identity), GM_OK,
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
}
}

int main() {
    test_known_empty_aes_gcm_vector();
    test_media_aead_round_trip_and_tamper();
    test_ed25519_identity_profile();

    if (failures != 0) {
        std::cerr << failures << " failure(s)\n";
        return 1;
    }
    return 0;
}