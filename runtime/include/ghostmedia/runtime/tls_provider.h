#ifndef GHOSTMEDIA_RUNTIME_TLS_PROVIDER_H
#define GHOSTMEDIA_RUNTIME_TLS_PROVIDER_H

#include <ghostmedia/gm_core.h>
#include <ghostmedia/runtime/identity_provider.h>

#include <array>
#include <memory>
#include <vector>

struct gm_runtime_tcp_socket;

namespace ghostmedia::runtime {

class TlsSession final {
public:
    ~TlsSession();

    TlsSession(const TlsSession &) = delete;
    TlsSession &operator=(const TlsSession &) = delete;
    TlsSession(TlsSession &&) noexcept;
    TlsSession &operator=(TlsSession &&) noexcept;

    static gm_status create_client(
        gm_runtime_tcp_socket *connection,
        const Ed25519Identity &identity,
        gm_bytes expected_server_spki,
        std::unique_ptr<TlsSession> &session);
    static gm_status create_server(
        gm_runtime_tcp_socket *connection,
        const Ed25519Identity &identity,
        gm_bytes expected_client_spki,
        std::unique_ptr<TlsSession> &session);

    gm_status handshake();
    gm_status send_all(gm_bytes plaintext);
    gm_status receive(gm_mut_bytes output, size_t &received);
    gm_status receive_exact(gm_mut_bytes output);
    gm_status exporter(gm_bytes context,
                       std::array<uint8_t, GM_TLS_EXPORTER_OUTPUT_BYTES> &output);

private:
    static gm_status create(
        bool server,
        gm_runtime_tcp_socket *connection,
        const Ed25519Identity &identity,
        gm_bytes expected_peer_spki,
        std::unique_ptr<TlsSession> &session);

    struct Impl;
    explicit TlsSession(std::unique_ptr<Impl> impl);

    std::unique_ptr<Impl> impl_;
};

gm_status tls13_exporter_pair(
    const Ed25519Identity &client_identity,
    const Ed25519Identity &server_identity,
    gm_bytes exporter_context,
    std::array<uint8_t, GM_TLS_EXPORTER_OUTPUT_BYTES> &client_output,
    std::array<uint8_t, GM_TLS_EXPORTER_OUTPUT_BYTES> &server_output);

gm_status tls13_exporter_pair_with_pins(
    const Ed25519Identity &client_identity,
    const Ed25519Identity &server_identity,
    gm_bytes client_expected_server_spki,
    gm_bytes server_expected_client_spki,
    gm_bytes exporter_context,
    std::array<uint8_t, GM_TLS_EXPORTER_OUTPUT_BYTES> &client_output,
    std::array<uint8_t, GM_TLS_EXPORTER_OUTPUT_BYTES> &server_output);

}

#endif
