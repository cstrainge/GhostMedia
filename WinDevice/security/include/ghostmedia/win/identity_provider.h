#ifndef GHOSTMEDIA_WIN_IDENTITY_PROVIDER_H
#define GHOSTMEDIA_WIN_IDENTITY_PROVIDER_H

#include <ghostmedia/gm_core.h>

#include <array>
#include <cstdint>
#include <memory>
#include <vector>

namespace ghostmedia::win {

class Ed25519Identity final {
public:
    ~Ed25519Identity();

    Ed25519Identity(const Ed25519Identity &) = delete;
    Ed25519Identity &operator=(const Ed25519Identity &) = delete;
    Ed25519Identity(Ed25519Identity &&) noexcept;
    Ed25519Identity &operator=(Ed25519Identity &&) noexcept;

    static gm_status generate(std::unique_ptr<Ed25519Identity> &identity);

    gm_status certificate_der(std::vector<uint8_t> &der) const;
    gm_status public_key_spki_der(std::vector<uint8_t> &der) const;
    gm_status spki_sha256(std::array<uint8_t, GM_SPKI_DIGEST_BYTES> &digest) const;
    gm_status sign(gm_bytes message, std::vector<uint8_t> &signature) const;

private:
    struct Impl;
    explicit Ed25519Identity(std::unique_ptr<Impl> impl);

    std::unique_ptr<Impl> impl_;
};

}

#endif
