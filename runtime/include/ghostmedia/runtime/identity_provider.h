#ifndef GHOSTMEDIA_RUNTIME_IDENTITY_PROVIDER_H
#define GHOSTMEDIA_RUNTIME_IDENTITY_PROVIDER_H

#include <ghostmedia/gm_core.h>

#include <array>
#include <cstdint>
#include <memory>
#include <vector>

namespace ghostmedia::runtime {

class Ed25519Identity final {
public:
    ~Ed25519Identity();

    Ed25519Identity(const Ed25519Identity &) = delete;
    Ed25519Identity &operator=(const Ed25519Identity &) = delete;
    Ed25519Identity(Ed25519Identity &&) noexcept;
    Ed25519Identity &operator=(Ed25519Identity &&) noexcept;

    static gm_status generate(std::unique_ptr<Ed25519Identity> &identity);
    static gm_status load(gm_bytes private_key_pkcs8, gm_bytes certificate_der,
                          std::unique_ptr<Ed25519Identity> &identity);
    static gm_status load_raw_private_key(gm_bytes private_key_raw,
                                          gm_bytes certificate_der,
                                          std::unique_ptr<Ed25519Identity> &identity);
    static gm_status renew_raw_private_key(
        gm_bytes private_key_raw,
        std::unique_ptr<Ed25519Identity> &identity);
    static gm_status renew_certificate(gm_bytes private_key_pkcs8,
                                       std::unique_ptr<Ed25519Identity> &identity);

    gm_status private_key_pkcs8(std::vector<uint8_t> &der) const;
    gm_status private_key_raw(std::vector<uint8_t> &bytes) const;
    gm_status certificate_der(std::vector<uint8_t> &der) const;
    gm_status public_key_spki_der(std::vector<uint8_t> &der) const;
    gm_status spki_sha256(std::array<uint8_t, GM_SPKI_DIGEST_BYTES> &digest) const;
    gm_status sign(gm_bytes message, std::vector<uint8_t> &signature) const;

private:
    friend class TlsSession;
    friend gm_status tls13_exporter_pair(const Ed25519Identity &client_identity,
                                         const Ed25519Identity &server_identity,
                                         gm_bytes exporter_context,
                                         std::array<uint8_t, GM_TLS_EXPORTER_OUTPUT_BYTES> &client_output,
                                         std::array<uint8_t, GM_TLS_EXPORTER_OUTPUT_BYTES> &server_output);
    friend gm_status tls13_exporter_pair_with_pins(
        const Ed25519Identity &client_identity,
        const Ed25519Identity &server_identity,
        gm_bytes client_expected_server_spki,
        gm_bytes server_expected_client_spki,
        gm_bytes exporter_context,
        std::array<uint8_t, GM_TLS_EXPORTER_OUTPUT_BYTES> &client_output,
        std::array<uint8_t, GM_TLS_EXPORTER_OUTPUT_BYTES> &server_output);

    void *native_private_key() const;
    void *native_certificate() const;

    struct Impl;
    explicit Ed25519Identity(std::unique_ptr<Impl> impl);

    std::unique_ptr<Impl> impl_;
};

}

#endif
