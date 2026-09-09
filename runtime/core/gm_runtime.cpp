#include <ghostmedia/gm_runtime.h>
#include <ghostmedia/runtime/aes_gcm_provider.h>
#include <ghostmedia/runtime/identity_provider.h>
#include <ghostmedia/runtime/tls_provider.h>

#include <array>
#include <cstring>
#include <memory>
#include <new>
#include <vector>

struct gm_runtime_identity {
    std::unique_ptr<ghostmedia::runtime::Ed25519Identity> value;
};

struct gm_runtime_tls_session {
    std::unique_ptr<ghostmedia::runtime::TlsSession> value;
};

namespace {
gm_status copy_output(const std::vector<uint8_t> &source, gm_mut_bytes output, size_t *written) {
    if (written == nullptr || (output.size != 0u && output.data == nullptr)) {
        return GM_BAD_ARGUMENT;
    }
    *written = source.size();
    if (output.size < source.size()) {
        return GM_BUFFER_TOO_SMALL;
    }
    if (!source.empty()) {
        std::memcpy(output.data, source.data(), source.size());
    }
    return GM_OK;
}
}

extern "C" {

gm_status gm_runtime_identity_generate(gm_runtime_identity **out_identity) {
    if (out_identity == nullptr) {
        return GM_BAD_ARGUMENT;
    }
    *out_identity = nullptr;
    std::unique_ptr<ghostmedia::runtime::Ed25519Identity> identity;
    const gm_status status = ghostmedia::runtime::Ed25519Identity::generate(identity);
    if (status != GM_OK) {
        return status;
    }
    auto handle = std::unique_ptr<gm_runtime_identity>(new (std::nothrow) gm_runtime_identity());
    if (!handle) {
        return GM_INTERNAL;
    }
    handle->value = std::move(identity);
    *out_identity = handle.release();
    return GM_OK;
}

gm_status gm_runtime_identity_load(gm_bytes private_key_pkcs8, gm_bytes certificate_der,
                                   gm_runtime_identity **out_identity) {
    if (out_identity == nullptr) {
        return GM_BAD_ARGUMENT;
    }
    *out_identity = nullptr;
    std::unique_ptr<ghostmedia::runtime::Ed25519Identity> identity;
    const gm_status status = ghostmedia::runtime::Ed25519Identity::load(
        private_key_pkcs8, certificate_der, identity);
    if (status != GM_OK) {
        return status;
    }
    auto handle = std::unique_ptr<gm_runtime_identity>(new (std::nothrow) gm_runtime_identity());
    if (!handle) {
        return GM_INTERNAL;
    }
    handle->value = std::move(identity);
    *out_identity = handle.release();
    return GM_OK;
}

gm_status gm_runtime_identity_load_raw_ed25519(gm_bytes private_key_raw,
                                               gm_bytes certificate_der,
                                               gm_runtime_identity **out_identity) {
    if (out_identity == nullptr) {
        return GM_BAD_ARGUMENT;
    }
    *out_identity = nullptr;
    std::unique_ptr<ghostmedia::runtime::Ed25519Identity> identity;
    const gm_status status =
        ghostmedia::runtime::Ed25519Identity::load_raw_private_key(
            private_key_raw,
            certificate_der,
            identity);
    if (status != GM_OK) {
        return status;
    }
    auto handle = std::unique_ptr<gm_runtime_identity>(
        new (std::nothrow) gm_runtime_identity());
    if (!handle) {
        return GM_INTERNAL;
    }
    handle->value = std::move(identity);
    *out_identity = handle.release();
    return GM_OK;
}

gm_status gm_runtime_identity_renew_certificate(gm_bytes private_key_pkcs8,
                                                gm_runtime_identity **out_identity) {
    if (out_identity == nullptr) {
        return GM_BAD_ARGUMENT;
    }
    *out_identity = nullptr;
    std::unique_ptr<ghostmedia::runtime::Ed25519Identity> identity;
    const gm_status status = ghostmedia::runtime::Ed25519Identity::renew_certificate(
        private_key_pkcs8,
        identity);
    if (status != GM_OK) {
        return status;
    }
    auto handle = std::unique_ptr<gm_runtime_identity>(
        new (std::nothrow) gm_runtime_identity());
    if (!handle) {
        return GM_INTERNAL;
    }
    handle->value = std::move(identity);
    *out_identity = handle.release();
    return GM_OK;
}

gm_status gm_runtime_identity_renew_raw_ed25519(gm_bytes private_key_raw,
                                                gm_runtime_identity **out_identity) {
    if (out_identity == nullptr) {
        return GM_BAD_ARGUMENT;
    }
    *out_identity = nullptr;
    std::unique_ptr<ghostmedia::runtime::Ed25519Identity> identity;
    const gm_status status =
        ghostmedia::runtime::Ed25519Identity::renew_raw_private_key(
            private_key_raw,
            identity);
    if (status != GM_OK) {
        return status;
    }
    auto handle = std::unique_ptr<gm_runtime_identity>(
        new (std::nothrow) gm_runtime_identity());
    if (!handle) {
        return GM_INTERNAL;
    }
    handle->value = std::move(identity);
    *out_identity = handle.release();
    return GM_OK;
}

void gm_runtime_identity_destroy(gm_runtime_identity *identity) {
    delete identity;
}

gm_status gm_runtime_identity_private_key_pkcs8(const gm_runtime_identity *identity,
                                                gm_mut_bytes output, size_t *written) {
    if (identity == nullptr || !identity->value) {
        return GM_BAD_ARGUMENT;
    }
    std::vector<uint8_t> bytes;
    const gm_status status = identity->value->private_key_pkcs8(bytes);
    return status == GM_OK ? copy_output(bytes, output, written) : status;
}

gm_status gm_runtime_identity_certificate_der(const gm_runtime_identity *identity,
                                              gm_mut_bytes output, size_t *written) {
    if (identity == nullptr || !identity->value) {
        return GM_BAD_ARGUMENT;
    }
    std::vector<uint8_t> bytes;
    const gm_status status = identity->value->certificate_der(bytes);
    return status == GM_OK ? copy_output(bytes, output, written) : status;
}

gm_status gm_runtime_identity_spki_der(const gm_runtime_identity *identity,
                                      gm_mut_bytes output, size_t *written) {
    if (identity == nullptr || !identity->value) {
        return GM_BAD_ARGUMENT;
    }
    std::vector<uint8_t> bytes;
    const gm_status status = identity->value->public_key_spki_der(bytes);
    return status == GM_OK ? copy_output(bytes, output, written) : status;
}

gm_status gm_runtime_identity_spki_sha256(const gm_runtime_identity *identity,
                                         gm_mut_bytes output) {
    if (identity == nullptr || !identity->value ||
        output.data == nullptr || output.size != GM_SPKI_DIGEST_BYTES) {
        return GM_BAD_ARGUMENT;
    }
    std::array<uint8_t, GM_SPKI_DIGEST_BYTES> digest{};
    const gm_status status = identity->value->spki_sha256(digest);
    if (status == GM_OK) {
        std::memcpy(output.data, digest.data(), digest.size());
    }
    return status;
}

gm_status gm_runtime_identity_sign(const gm_runtime_identity *identity, gm_bytes message,
                                   gm_mut_bytes output, size_t *written) {
    if (identity == nullptr || !identity->value) {
        return GM_BAD_ARGUMENT;
    }
    std::vector<uint8_t> signature;
    const gm_status status = identity->value->sign(message, signature);
    return status == GM_OK ? copy_output(signature, output, written) : status;
}

gm_status gm_runtime_aes256_gcm_encrypt(gm_bytes key, gm_bytes nonce, gm_bytes aad,
                                       gm_bytes plaintext, gm_mut_bytes ciphertext,
                                       gm_mut_bytes tag) {
    if ((ciphertext.size != 0u && ciphertext.data == nullptr) ||
        tag.data == nullptr || ciphertext.size != plaintext.size ||
        tag.size != GM_MEDIA_TAG_BYTES) {
        return GM_BAD_ARGUMENT;
    }
    std::vector<uint8_t> encrypted;
    std::array<uint8_t, GM_MEDIA_TAG_BYTES> generated_tag{};
    const gm_status status = ghostmedia::runtime::aes256_gcm_encrypt(
        key, nonce, aad, plaintext, encrypted, generated_tag);
    if (status == GM_OK) {
        if (!encrypted.empty()) {
            std::memcpy(ciphertext.data, encrypted.data(), encrypted.size());
        }
        std::memcpy(tag.data, generated_tag.data(), generated_tag.size());
    }
    return status;
}

gm_status gm_runtime_aes256_gcm_decrypt(gm_bytes key, gm_bytes nonce, gm_bytes aad,
                                       gm_bytes ciphertext, gm_bytes tag,
                                       gm_mut_bytes plaintext) {
    if ((plaintext.size != 0u && plaintext.data == nullptr) ||
        plaintext.size != ciphertext.size) {
        return GM_BAD_ARGUMENT;
    }
    std::vector<uint8_t> decrypted;
    const gm_status status = ghostmedia::runtime::aes256_gcm_decrypt(
        key, nonce, aad, ciphertext, tag, decrypted);
    if (status == GM_OK && !decrypted.empty()) {
        std::memcpy(plaintext.data, decrypted.data(), decrypted.size());
    }
    return status;
}

gm_status gm_runtime_tls13_exporter_pair(const gm_runtime_identity *client_identity,
                                        const gm_runtime_identity *server_identity,
                                        gm_bytes client_expected_server_spki,
                                        gm_bytes server_expected_client_spki,
                                        gm_bytes exporter_context,
                                        gm_mut_bytes client_output,
                                        gm_mut_bytes server_output) {
    if (client_identity == nullptr || !client_identity->value ||
        server_identity == nullptr || !server_identity->value ||
        client_output.data == nullptr ||
        client_output.size != GM_TLS_EXPORTER_OUTPUT_BYTES ||
        server_output.data == nullptr ||
        server_output.size != GM_TLS_EXPORTER_OUTPUT_BYTES) {
        return GM_BAD_ARGUMENT;
    }
    std::array<uint8_t, GM_TLS_EXPORTER_OUTPUT_BYTES> client_bytes{};
    std::array<uint8_t, GM_TLS_EXPORTER_OUTPUT_BYTES> server_bytes{};
    const gm_status status = ghostmedia::runtime::tls13_exporter_pair_with_pins(
        *client_identity->value,
        *server_identity->value,
        client_expected_server_spki,
        server_expected_client_spki,
        exporter_context,
        client_bytes,
        server_bytes);
    if (status == GM_OK) {
        std::memcpy(client_output.data, client_bytes.data(), client_bytes.size());
        std::memcpy(server_output.data, server_bytes.data(), server_bytes.size());
    }
    return status;
}

gm_status gm_runtime_tls_client_create(gm_runtime_tcp_socket *connection,
                                       const gm_runtime_identity *identity,
                                       gm_bytes expected_server_spki,
                                       gm_runtime_tls_session **out_session) {
    if (identity == nullptr || !identity->value || out_session == nullptr) {
        return GM_BAD_ARGUMENT;
    }
    *out_session = nullptr;
    std::unique_ptr<ghostmedia::runtime::TlsSession> session;
    const gm_status status = ghostmedia::runtime::TlsSession::create_client(
        connection,
        *identity->value,
        expected_server_spki,
        session);
    if (status != GM_OK) {
        return status;
    }
    auto handle = std::unique_ptr<gm_runtime_tls_session>(
        new (std::nothrow) gm_runtime_tls_session());
    if (!handle) {
        return GM_INTERNAL;
    }
    handle->value = std::move(session);
    *out_session = handle.release();
    return GM_OK;
}

gm_status gm_runtime_tls_server_create(gm_runtime_tcp_socket *connection,
                                       const gm_runtime_identity *identity,
                                       gm_bytes expected_client_spki,
                                       gm_runtime_tls_session **out_session) {
    if (identity == nullptr || !identity->value || out_session == nullptr) {
        return GM_BAD_ARGUMENT;
    }
    *out_session = nullptr;
    std::unique_ptr<ghostmedia::runtime::TlsSession> session;
    const gm_status status = ghostmedia::runtime::TlsSession::create_server(
        connection,
        *identity->value,
        expected_client_spki,
        session);
    if (status != GM_OK) {
        return status;
    }
    auto handle = std::unique_ptr<gm_runtime_tls_session>(
        new (std::nothrow) gm_runtime_tls_session());
    if (!handle) {
        return GM_INTERNAL;
    }
    handle->value = std::move(session);
    *out_session = handle.release();
    return GM_OK;
}

gm_status gm_runtime_tls_handshake(gm_runtime_tls_session *session) {
    return session != nullptr && session->value
        ? session->value->handshake()
        : GM_BAD_ARGUMENT;
}

gm_status gm_runtime_tls_send_all(gm_runtime_tls_session *session,
                                  gm_bytes plaintext) {
    return session != nullptr && session->value
        ? session->value->send_all(plaintext)
        : GM_BAD_ARGUMENT;
}

gm_status gm_runtime_tls_receive(gm_runtime_tls_session *session,
                                 gm_mut_bytes output,
                                 size_t *received) {
    if (session == nullptr || !session->value || received == nullptr) {
        return GM_BAD_ARGUMENT;
    }
    return session->value->receive(output, *received);
}

gm_status gm_runtime_tls_receive_exact(gm_runtime_tls_session *session,
                                       gm_mut_bytes output) {
    return session != nullptr && session->value
        ? session->value->receive_exact(output)
        : GM_BAD_ARGUMENT;
}

gm_status gm_runtime_tls_export(gm_runtime_tls_session *session,
                                gm_bytes context,
                                gm_mut_bytes output) {
    if (session == nullptr || !session->value ||
        output.data == nullptr ||
        output.size != GM_TLS_EXPORTER_OUTPUT_BYTES) {
        return GM_BAD_ARGUMENT;
    }
    std::array<uint8_t, GM_TLS_EXPORTER_OUTPUT_BYTES> exported{};
    const gm_status status = session->value->exporter(context, exported);
    if (status == GM_OK) {
        std::memcpy(output.data, exported.data(), exported.size());
    }
    return status;
}

void gm_runtime_tls_session_destroy(gm_runtime_tls_session *session) {
    delete session;
}

}
