#include <ghostmedia/runtime/tls_provider.h>
#include <ghostmedia/gm_runtime.h>

#include "certificate_profile.h"
#include "socket_provider_internal.h"

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <memory>

namespace {
using SSLContext = std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)>;
using SSLConnection = std::unique_ptr<SSL, decltype(&SSL_free)>;

constexpr unsigned char kAlpnWire[] = {
    GM_TLS_ALPN_BYTES,
    'g', 'h', 'o', 's', 't', 'm', 'e', 'd', 'i', 'a', '/', '1',
};
constexpr auto kHandshakeTimeout = std::chrono::seconds(5);
constexpr size_t kMaximumPreHandshakeBytes = 32u * 1024u;

int expected_digest_index() {
    static const int index = SSL_CTX_get_ex_new_index(0, nullptr, nullptr, nullptr, nullptr);
    return index;
}

int verify_peer_certificate(int, X509_STORE_CTX *store) {
    SSL *ssl = static_cast<SSL *>(
        X509_STORE_CTX_get_ex_data(store, SSL_get_ex_data_X509_STORE_CTX_idx()));
    SSL_CTX *context = ssl == nullptr ? nullptr : SSL_get_SSL_CTX(ssl);
    const auto *expected_digest = context == nullptr
        ? nullptr
        : static_cast<const std::array<uint8_t, GM_SPKI_DIGEST_BYTES> *>(
              SSL_CTX_get_ex_data(context, expected_digest_index()));
    STACK_OF(X509) *chain = X509_STORE_CTX_get0_chain(store);
    X509 *certificate = X509_STORE_CTX_get_current_cert(store);
    std::array<uint8_t, GM_SPKI_DIGEST_BYTES> actual_digest{};
    const bool accepted =
        expected_digest != nullptr &&
        X509_STORE_CTX_get_error_depth(store) == 0 &&
        chain != nullptr &&
        sk_X509_num(chain) == 1 &&
        ghostmedia::runtime::detail::certificate_profile(certificate) ==
            ghostmedia::runtime::detail::CertificateProfileResult::valid &&
        ghostmedia::runtime::detail::certificate_spki_digest(certificate, actual_digest) &&
        CRYPTO_memcmp(
            actual_digest.data(),
            expected_digest->data(),
            actual_digest.size()) == 0;
    X509_STORE_CTX_set_error(
        store,
        accepted ? X509_V_OK : X509_V_ERR_CERT_REJECTED);
    return accepted ? 1 : 0;
}

int select_alpn(SSL *, const unsigned char **output, unsigned char *output_length,
                const unsigned char *input, unsigned int input_length, void *) {
    if (SSL_select_next_proto(
            const_cast<unsigned char **>(output),
            output_length,
            kAlpnWire,
            sizeof(kAlpnWire),
            input,
            input_length) != OPENSSL_NPN_NEGOTIATED) {
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }
    return SSL_TLSEXT_ERR_OK;
}

SSLContext make_context(
    bool server,
    EVP_PKEY *private_key,
    X509 *certificate,
    const std::array<uint8_t, GM_SPKI_DIGEST_BYTES> &expected_digest) {
    SSLContext context(SSL_CTX_new(TLS_method()), SSL_CTX_free);
    if (!context ||
        SSL_CTX_set_min_proto_version(context.get(), TLS1_3_VERSION) != 1 ||
        SSL_CTX_set_max_proto_version(context.get(), TLS1_3_VERSION) != 1 ||
        SSL_CTX_use_certificate(context.get(), certificate) != 1 ||
        SSL_CTX_use_PrivateKey(context.get(), private_key) != 1 ||
        SSL_CTX_check_private_key(context.get()) != 1 ||
        SSL_CTX_set_ex_data(
            context.get(),
            expected_digest_index(),
            const_cast<std::array<uint8_t, GM_SPKI_DIGEST_BYTES> *>(&expected_digest)) != 1) {
        return SSLContext(nullptr, SSL_CTX_free);
    }
    SSL_CTX_set_options(
        context.get(),
        SSL_OP_NO_TICKET | SSL_OP_NO_COMPRESSION | SSL_OP_NO_RENEGOTIATION);
    SSL_CTX_set_num_tickets(context.get(), 0);
    SSL_CTX_set_max_early_data(context.get(), 0);
    SSL_CTX_set_verify(
        context.get(),
        SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
        verify_peer_certificate);
    if (server) {
        SSL_CTX_set_alpn_select_cb(context.get(), select_alpn, nullptr);
    }
    return context;
}

bool handshake_complete(SSL *connection, bool &complete) {
    if (complete) {
        return true;
    }
    const int result = SSL_do_handshake(connection);
    if (result == 1) {
        complete = true;
        return true;
    }
    const int error = SSL_get_error(connection, result);
    return error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE;
}

bool negotiated_required_alpn(SSL *connection) {
    const unsigned char *selected = nullptr;
    unsigned int selected_length = 0;
    SSL_get0_alpn_selected(connection, &selected, &selected_length);
    return selected_length == GM_TLS_ALPN_BYTES &&
           selected != nullptr &&
           std::memcmp(selected, "ghostmedia/1", GM_TLS_ALPN_BYTES) == 0;
}

gm_status apply_deadline(
    gm_runtime_tcp_socket *socket,
    const std::chrono::steady_clock::time_point *deadline) {
    if (deadline == nullptr) {
        return GM_OK;
    }
    const auto now = std::chrono::steady_clock::now();
    if (now >= *deadline) {
        return GM_LIMIT_EXCEEDED;
    }
    const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
        *deadline - now);
    const uint32_t timeout_ms = static_cast<uint32_t>(
        std::max<int64_t>(1, remaining.count()));
    return ghostmedia::runtime::detail::tcp_socket_set_io_timeout(
        socket,
        timeout_ms);
}

gm_status drain_encrypted_output(
    SSL *connection,
    gm_runtime_tcp_socket *socket,
    const std::chrono::steady_clock::time_point *deadline = nullptr) {
    BIO *write_bio = SSL_get_wbio(connection);
    std::array<uint8_t, 16 * 1024> buffer{};
    while (BIO_ctrl_pending(write_bio) != 0u) {
        const int read = BIO_read(
            write_bio,
            buffer.data(),
            static_cast<int>(buffer.size()));
        if (read <= 0) {
            return GM_INTERNAL;
        }
        const gm_status deadline_status = apply_deadline(socket, deadline);
        if (deadline_status != GM_OK) {
            return deadline_status;
        }
        const gm_status status = gm_runtime_tcp_send_all(
            socket,
            gm_bytes{buffer.data(), static_cast<size_t>(read)});
        if (status != GM_OK) {
            return status;
        }
    }
    return GM_OK;
}

gm_status receive_encrypted_input(
    SSL *connection,
    gm_runtime_tcp_socket *socket,
    const std::chrono::steady_clock::time_point *deadline = nullptr,
    size_t *total_received = nullptr) {
    std::array<uint8_t, 16 * 1024> buffer{};
    size_t received = 0u;
    const gm_status deadline_status = apply_deadline(socket, deadline);
    if (deadline_status != GM_OK) {
        return deadline_status;
    }
    const gm_status status = gm_runtime_tcp_receive(
        socket,
        gm_mut_bytes{buffer.data(), buffer.size()},
        &received);
    if (status != GM_OK) {
        return status;
    }
    if (total_received != nullptr) {
        *total_received += received;
        if (*total_received > kMaximumPreHandshakeBytes) {
            return GM_LIMIT_EXCEEDED;
        }
    }
    BIO *read_bio = SSL_get_rbio(connection);
    return BIO_write(read_bio, buffer.data(), static_cast<int>(received)) ==
                   static_cast<int>(received)
        ? GM_OK
        : GM_INTERNAL;
}
}

namespace ghostmedia::runtime {

struct TlsSession::Impl {
    std::array<uint8_t, GM_SPKI_DIGEST_BYTES> expected_digest{};
    SSLContext context{nullptr, SSL_CTX_free};
    SSLConnection connection{nullptr, SSL_free};
    gm_runtime_tcp_socket *socket = nullptr;
    std::chrono::steady_clock::time_point handshake_deadline{};
    uint32_t default_timeout_ms = 0u;
};

TlsSession::TlsSession(std::unique_ptr<Impl> impl) : impl_(std::move(impl)) {}
TlsSession::~TlsSession() = default;
TlsSession::TlsSession(TlsSession &&) noexcept = default;
TlsSession &TlsSession::operator=(TlsSession &&) noexcept = default;

gm_status TlsSession::create(
    bool server,
    gm_runtime_tcp_socket *connection,
    const Ed25519Identity &identity,
    gm_bytes expected_peer_spki,
    std::unique_ptr<TlsSession> &session) {
    session.reset();
    if (connection == nullptr ||
        expected_peer_spki.data == nullptr ||
        expected_peer_spki.size != GM_SPKI_DIGEST_BYTES) {
        return GM_BAD_ARGUMENT;
    }

    auto impl = std::make_unique<TlsSession::Impl>();
    std::memcpy(
        impl->expected_digest.data(),
        expected_peer_spki.data,
        impl->expected_digest.size());
    impl->context = make_context(
        server,
        static_cast<EVP_PKEY *>(identity.native_private_key()),
        static_cast<X509 *>(identity.native_certificate()),
        impl->expected_digest);
    impl->connection = SSLConnection(
        impl->context ? SSL_new(impl->context.get()) : nullptr,
        SSL_free);
    if (!impl->connection) {
        return GM_INTERNAL;
    }

    BIO *read_bio = BIO_new(BIO_s_mem());
    BIO *write_bio = BIO_new(BIO_s_mem());
    if (read_bio == nullptr || write_bio == nullptr) {
        BIO_free(read_bio);
        BIO_free(write_bio);
        return GM_INTERNAL;
    }
    BIO_set_mem_eof_return(read_bio, -1);
    BIO_set_mem_eof_return(write_bio, -1);
    SSL_set_bio(impl->connection.get(), read_bio, write_bio);
    impl->socket = connection;
    impl->handshake_deadline =
        detail::tcp_socket_opened_at(connection) + kHandshakeTimeout;
    impl->default_timeout_ms = detail::tcp_socket_default_timeout_ms(connection);
    if (server) {
        SSL_set_accept_state(impl->connection.get());
    } else {
        SSL_set_connect_state(impl->connection.get());
        if (SSL_set_alpn_protos(
                impl->connection.get(),
                kAlpnWire,
                sizeof(kAlpnWire)) != 0) {
            return GM_INTERNAL;
        }
    }
    session.reset(new TlsSession(std::move(impl)));
    return GM_OK;
}

gm_status TlsSession::create_client(
    gm_runtime_tcp_socket *connection,
    const Ed25519Identity &identity,
    gm_bytes expected_server_spki,
    std::unique_ptr<TlsSession> &session) {
    return create(false, connection, identity, expected_server_spki, session);
}

gm_status TlsSession::create_server(
    gm_runtime_tcp_socket *connection,
    const Ed25519Identity &identity,
    gm_bytes expected_client_spki,
    std::unique_ptr<TlsSession> &session) {
    return create(true, connection, identity, expected_client_spki, session);
}

gm_status TlsSession::handshake() {
    if (!impl_ || !impl_->connection || impl_->socket == nullptr) {
        return GM_BAD_ARGUMENT;
    }
    size_t encrypted_bytes_received = 0u;
    for (int iteration = 0; iteration < 256; ++iteration) {
        if (std::chrono::steady_clock::now() >= impl_->handshake_deadline) {
            return GM_LIMIT_EXCEEDED;
        }
        const int result = SSL_do_handshake(impl_->connection.get());
        const gm_status drain_status =
            drain_encrypted_output(
                impl_->connection.get(),
                impl_->socket,
                &impl_->handshake_deadline);
        if (drain_status != GM_OK) {
            return drain_status;
        }
        if (result == 1) {
            if (impl_->default_timeout_ms != 0u) {
                const gm_status timeout_status = detail::tcp_socket_set_io_timeout(
                    impl_->socket,
                    impl_->default_timeout_ms);
                if (timeout_status != GM_OK) {
                    return timeout_status;
                }
            }
            return SSL_get_verify_result(impl_->connection.get()) == X509_V_OK &&
                    negotiated_required_alpn(impl_->connection.get())
                ? GM_OK : GM_UNAUTHORIZED;
        }
        const int error = SSL_get_error(impl_->connection.get(), result);
        if (error == SSL_ERROR_WANT_WRITE) {
            continue;
        }
        if (error != SSL_ERROR_WANT_READ) {
            return GM_UNAUTHORIZED;
        }
        const gm_status receive_status =
            receive_encrypted_input(
                impl_->connection.get(),
                impl_->socket,
                &impl_->handshake_deadline,
                &encrypted_bytes_received);
        if (receive_status != GM_OK) {
            return receive_status;
        }
    }
    return GM_LIMIT_EXCEEDED;
}

gm_status TlsSession::send_all(gm_bytes plaintext) {
    if (!impl_ || !impl_->connection || impl_->socket == nullptr ||
        (plaintext.size != 0u && plaintext.data == nullptr) ||
        SSL_is_init_finished(impl_->connection.get()) != 1) {
        return GM_BAD_ARGUMENT;
    }
    size_t written_total = 0u;
    while (written_total < plaintext.size) {
        size_t written = 0u;
        const int result = SSL_write_ex(
            impl_->connection.get(),
            plaintext.data + written_total,
            plaintext.size - written_total,
            &written);
        const gm_status drain_status =
            drain_encrypted_output(impl_->connection.get(), impl_->socket);
        if (drain_status != GM_OK) {
            return drain_status;
        }
        if (result == 1) {
            written_total += written;
            continue;
        }
        const int error = SSL_get_error(impl_->connection.get(), result);
        if (error == SSL_ERROR_WANT_WRITE) {
            continue;
        }
        if (error == SSL_ERROR_WANT_READ) {
            const gm_status receive_status =
                receive_encrypted_input(impl_->connection.get(), impl_->socket);
            if (receive_status != GM_OK) {
                return receive_status;
            }
            continue;
        }
        return GM_INTERNAL;
    }
    return GM_OK;
}

gm_status TlsSession::receive(gm_mut_bytes output, size_t &received) {
    received = 0u;
    if (!impl_ || !impl_->connection || impl_->socket == nullptr ||
        output.data == nullptr || output.size == 0u ||
        SSL_is_init_finished(impl_->connection.get()) != 1) {
        return GM_BAD_ARGUMENT;
    }
    for (int iteration = 0; iteration < 256; ++iteration) {
        size_t plaintext_size = 0u;
        const int result = SSL_read_ex(
            impl_->connection.get(),
            output.data,
            output.size,
            &plaintext_size);
        const gm_status drain_status =
            drain_encrypted_output(impl_->connection.get(), impl_->socket);
        if (drain_status != GM_OK) {
            return drain_status;
        }
        if (result == 1) {
            received = plaintext_size;
            return GM_OK;
        }
        const int error = SSL_get_error(impl_->connection.get(), result);
        if (error == SSL_ERROR_WANT_WRITE) {
            continue;
        }
        if (error == SSL_ERROR_WANT_READ) {
            const gm_status receive_status =
                receive_encrypted_input(impl_->connection.get(), impl_->socket);
            if (receive_status != GM_OK) {
                return receive_status;
            }
            continue;
        }
        return error == SSL_ERROR_ZERO_RETURN ? GM_STATE_CONFLICT : GM_BAD_MESSAGE;
    }
    return GM_LIMIT_EXCEEDED;
}

gm_status TlsSession::receive_exact(gm_mut_bytes output) {
    if (output.size != 0u && output.data == nullptr) {
        return GM_BAD_ARGUMENT;
    }
    size_t received_total = 0u;
    while (received_total < output.size) {
        size_t received = 0u;
        const gm_status status = receive(
            gm_mut_bytes{
                output.data + received_total,
                output.size - received_total,
            },
            received);
        if (status != GM_OK) {
            return status;
        }
        received_total += received;
    }
    return GM_OK;
}

gm_status TlsSession::exporter(
    gm_bytes context,
    std::array<uint8_t, GM_TLS_EXPORTER_OUTPUT_BYTES> &output) {
    output.fill(0u);
    if (!impl_ || !impl_->connection ||
        context.data == nullptr ||
        context.size != GM_TLS_EXPORTER_CONTEXT_BYTES ||
        SSL_is_init_finished(impl_->connection.get()) != 1) {
        return GM_BAD_ARGUMENT;
    }
    const char *label = gm_tls_exporter_label();
    return SSL_export_keying_material(
               impl_->connection.get(),
               output.data(),
               output.size(),
               label,
               std::strlen(label),
               context.data,
               context.size,
               1) == 1
        ? GM_OK
        : GM_INTERNAL;
}

gm_status tls13_exporter_pair(
    const Ed25519Identity &client_identity,
    const Ed25519Identity &server_identity,
    gm_bytes exporter_context,
    std::array<uint8_t, GM_TLS_EXPORTER_OUTPUT_BYTES> &client_output,
    std::array<uint8_t, GM_TLS_EXPORTER_OUTPUT_BYTES> &server_output) {
    client_output.fill(0u);
    server_output.fill(0u);
    if (exporter_context.data == nullptr ||
        exporter_context.size != GM_TLS_EXPORTER_CONTEXT_BYTES) {
        return GM_BAD_ARGUMENT;
    }

    std::array<uint8_t, GM_SPKI_DIGEST_BYTES> client_digest{};
    std::array<uint8_t, GM_SPKI_DIGEST_BYTES> server_digest{};
    if (client_identity.spki_sha256(client_digest) != GM_OK ||
        server_identity.spki_sha256(server_digest) != GM_OK) {
        return GM_INTERNAL;
    }
    return tls13_exporter_pair_with_pins(
        client_identity,
        server_identity,
        gm_bytes{server_digest.data(), server_digest.size()},
        gm_bytes{client_digest.data(), client_digest.size()},
        exporter_context,
        client_output,
        server_output);
}

gm_status tls13_exporter_pair_with_pins(
    const Ed25519Identity &client_identity,
    const Ed25519Identity &server_identity,
    gm_bytes client_expected_server_spki,
    gm_bytes server_expected_client_spki,
    gm_bytes exporter_context,
    std::array<uint8_t, GM_TLS_EXPORTER_OUTPUT_BYTES> &client_output,
    std::array<uint8_t, GM_TLS_EXPORTER_OUTPUT_BYTES> &server_output) {
    client_output.fill(0u);
    server_output.fill(0u);
    if (exporter_context.data == nullptr ||
        exporter_context.size != GM_TLS_EXPORTER_CONTEXT_BYTES ||
        client_expected_server_spki.data == nullptr ||
        client_expected_server_spki.size != GM_SPKI_DIGEST_BYTES ||
        server_expected_client_spki.data == nullptr ||
        server_expected_client_spki.size != GM_SPKI_DIGEST_BYTES) {
        return GM_BAD_ARGUMENT;
    }
    std::array<uint8_t, GM_SPKI_DIGEST_BYTES> client_digest{};
    std::array<uint8_t, GM_SPKI_DIGEST_BYTES> server_digest{};
    std::memcpy(
        server_digest.data(),
        client_expected_server_spki.data,
        server_digest.size());
    std::memcpy(
        client_digest.data(),
        server_expected_client_spki.data,
        client_digest.size());

    SSLContext client_context = make_context(
        false,
        static_cast<EVP_PKEY *>(client_identity.native_private_key()),
        static_cast<X509 *>(client_identity.native_certificate()),
        server_digest);
    SSLContext server_context = make_context(
        true,
        static_cast<EVP_PKEY *>(server_identity.native_private_key()),
        static_cast<X509 *>(server_identity.native_certificate()),
        client_digest);
    SSLConnection client(client_context ? SSL_new(client_context.get()) : nullptr, SSL_free);
    SSLConnection server(server_context ? SSL_new(server_context.get()) : nullptr, SSL_free);
    if (!client || !server ||
        SSL_set_alpn_protos(client.get(), kAlpnWire, sizeof(kAlpnWire)) != 0) {
        return GM_INTERNAL;
    }

    BIO *client_bio = nullptr;
    BIO *server_bio = nullptr;
    if (BIO_new_bio_pair(&client_bio, 0, &server_bio, 0) != 1) {
        return GM_INTERNAL;
    }
    SSL_set_bio(client.get(), client_bio, client_bio);
    SSL_set_bio(server.get(), server_bio, server_bio);
    SSL_set_connect_state(client.get());
    SSL_set_accept_state(server.get());

    bool client_complete = false;
    bool server_complete = false;
    for (int iteration = 0;
         iteration < 128 && (!client_complete || !server_complete);
         ++iteration) {
        if (!handshake_complete(client.get(), client_complete) ||
            !handshake_complete(server.get(), server_complete)) {
            return GM_UNAUTHORIZED;
        }
    }
    if (!client_complete || !server_complete ||
        SSL_get_verify_result(client.get()) != X509_V_OK ||
        SSL_get_verify_result(server.get()) != X509_V_OK ||
        !negotiated_required_alpn(client.get()) ||
        !negotiated_required_alpn(server.get())) {
        return GM_UNAUTHORIZED;
    }

    const char *label = gm_tls_exporter_label();
    const size_t label_size = std::strlen(label);
    if (SSL_export_keying_material(
            client.get(),
            client_output.data(),
            client_output.size(),
            label,
            label_size,
            exporter_context.data,
            exporter_context.size,
            1) != 1 ||
        SSL_export_keying_material(
            server.get(),
            server_output.data(),
            server_output.size(),
            label,
            label_size,
            exporter_context.data,
            exporter_context.size,
            1) != 1) {
        client_output.fill(0u);
        server_output.fill(0u);
        return GM_INTERNAL;
    }
    if (client_output != server_output) {
        client_output.fill(0u);
        server_output.fill(0u);
        return GM_INTERNAL;
    }
    return GM_OK;
}

}
