#ifndef GHOSTMEDIA_RUNTIME_CERTIFICATE_PROFILE_H
#define GHOSTMEDIA_RUNTIME_CERTIFICATE_PROFILE_H

#include <ghostmedia/gm_core.h>

#include <openssl/x509.h>

#include <array>

namespace ghostmedia::runtime::detail {

enum class CertificateProfileResult {
    valid,
    not_yet_valid,
    expired,
    invalid,
};

CertificateProfileResult certificate_profile(X509 *certificate);
bool certificate_spki_digest(
    X509 *certificate,
    std::array<uint8_t, GM_SPKI_DIGEST_BYTES> &digest);

}

#endif
