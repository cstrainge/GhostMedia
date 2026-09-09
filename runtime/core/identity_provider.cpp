#include <ghostmedia/runtime/identity_provider.h>

#include "certificate_profile.h"

#include <openssl/asn1.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <array>
#include <climits>
#include <ctime>
#include <memory>
#include <utility>

namespace {
using BigNumber = std::unique_ptr<BIGNUM, decltype(&BN_free)>;
using DigestContext = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;
using Extension = std::unique_ptr<X509_EXTENSION, decltype(&X509_EXTENSION_free)>;
using KeyContext = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;
using PKCS8Info = std::unique_ptr<PKCS8_PRIV_KEY_INFO, decltype(&PKCS8_PRIV_KEY_INFO_free)>;
using PrivateKey = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using PublicKey = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using Certificate = std::unique_ptr<X509, decltype(&X509_free)>;

constexpr int kCertificateValidityDays = 825;

bool add_extension(X509 *certificate, int nid, const char *value) {
    Extension extension(X509V3_EXT_conf_nid(nullptr, nullptr, nid, const_cast<char *>(value)),
                        X509_EXTENSION_free);
    return extension && X509_add_ext(certificate, extension.get(), -1) == 1;
}

bool set_random_serial(X509 *certificate) {
    std::array<uint8_t, 16> serial_bytes{};
    if (RAND_bytes(serial_bytes.data(), static_cast<int>(serial_bytes.size())) != 1) {
        return false;
    }
    serial_bytes[0] &= 0x7fu;
    serial_bytes[0] |= 0x40u;

    BigNumber serial_number(BN_bin2bn(serial_bytes.data(), static_cast<int>(serial_bytes.size()), nullptr), BN_free);
    if (!serial_number) {
        return false;
    }
    return BN_to_ASN1_INTEGER(serial_number.get(), X509_get_serialNumber(certificate)) != nullptr;
}

bool encode_certificate(X509 *certificate, std::vector<uint8_t> &der) {
    const int size = i2d_X509(certificate, nullptr);
    if (size <= 0) {
        return false;
    }
    der.resize(static_cast<size_t>(size));
    unsigned char *output = der.data();
    return i2d_X509(certificate, &output) == size;
}

bool encode_spki(EVP_PKEY *key, std::vector<uint8_t> &der) {
    const int size = i2d_PUBKEY(key, nullptr);
    if (size <= 0) {
        return false;
    }
    der.resize(static_cast<size_t>(size));
    unsigned char *output = der.data();
    return i2d_PUBKEY(key, &output) == size;
}

bool encode_private_key(EVP_PKEY *key, std::vector<uint8_t> &der) {
    PKCS8Info info(EVP_PKEY2PKCS8(key), PKCS8_PRIV_KEY_INFO_free);
    if (!info) {
        return false;
    }
    const int size = i2d_PKCS8_PRIV_KEY_INFO(info.get(), nullptr);
    if (size <= 0) {
        return false;
    }
    der.resize(static_cast<size_t>(size));
    unsigned char *output = der.data();
    return i2d_PKCS8_PRIV_KEY_INFO(info.get(), &output) == size;
}

Certificate make_certificate(EVP_PKEY *key) {
    Certificate certificate(X509_new(), X509_free);
    std::time_t now = std::time(nullptr);
    if (!certificate || X509_set_version(certificate.get(), 2L) != 1 ||
        !set_random_serial(certificate.get()) ||
        now == static_cast<std::time_t>(-1) ||
        X509_time_adj_ex(X509_getm_notBefore(certificate.get()), 0, 0L, &now) == nullptr ||
        X509_time_adj_ex(
            X509_getm_notAfter(certificate.get()),
            kCertificateValidityDays,
            0L,
            &now) == nullptr ||
        X509_set_pubkey(certificate.get(), key) != 1) {
        return Certificate(nullptr, X509_free);
    }

    X509_NAME *subject = X509_get_subject_name(certificate.get());
    constexpr unsigned char common_name[] = "GhostMedia";
    if (subject == nullptr ||
        X509_NAME_add_entry_by_NID(
            subject,
            NID_commonName,
            MBSTRING_ASC,
            common_name,
            -1,
            -1,
            0) != 1 ||
        X509_set_issuer_name(certificate.get(), subject) != 1 ||
        !add_extension(certificate.get(), NID_basic_constraints, "critical,CA:FALSE") ||
        !add_extension(certificate.get(), NID_key_usage, "critical,digitalSignature") ||
        !add_extension(certificate.get(), NID_ext_key_usage, "clientAuth,serverAuth") ||
        X509_sign(certificate.get(), key, nullptr) <= 0) {
        return Certificate(nullptr, X509_free);
    }
    return certificate;
}

PrivateKey decode_pkcs8(gm_bytes private_key_pkcs8) {
    if (private_key_pkcs8.data == nullptr || private_key_pkcs8.size == 0u ||
        private_key_pkcs8.size > static_cast<size_t>(LONG_MAX)) {
        return PrivateKey(nullptr, EVP_PKEY_free);
    }
    const unsigned char *key_data = private_key_pkcs8.data;
    PKCS8Info key_info(
        d2i_PKCS8_PRIV_KEY_INFO(
            nullptr,
            &key_data,
            static_cast<long>(private_key_pkcs8.size)),
        PKCS8_PRIV_KEY_INFO_free);
    PrivateKey key(key_info ? EVP_PKCS82PKEY(key_info.get()) : nullptr, EVP_PKEY_free);
    if (!key ||
        key_data != private_key_pkcs8.data + private_key_pkcs8.size ||
        EVP_PKEY_id(key.get()) != EVP_PKEY_ED25519) {
        return PrivateKey(nullptr, EVP_PKEY_free);
    }
    return key;
}
}

namespace ghostmedia::runtime {

struct Ed25519Identity::Impl {
    Impl(PrivateKey key_value, Certificate certificate_value)
        : key(std::move(key_value)), certificate(std::move(certificate_value)) {}

    PrivateKey key;
    Certificate certificate;
};

Ed25519Identity::Ed25519Identity(std::unique_ptr<Impl> impl) : impl_(std::move(impl)) {}
Ed25519Identity::~Ed25519Identity() = default;
Ed25519Identity::Ed25519Identity(Ed25519Identity &&) noexcept = default;
Ed25519Identity &Ed25519Identity::operator=(Ed25519Identity &&) noexcept = default;

gm_status Ed25519Identity::generate(std::unique_ptr<Ed25519Identity> &identity) {
    identity.reset();

    KeyContext key_context(EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr), EVP_PKEY_CTX_free);
    EVP_PKEY *raw_key = nullptr;
    if (!key_context || EVP_PKEY_keygen_init(key_context.get()) != 1 ||
        EVP_PKEY_keygen(key_context.get(), &raw_key) != 1) {
        return GM_INTERNAL;
    }
    PrivateKey key(raw_key, EVP_PKEY_free);
    Certificate certificate = make_certificate(key.get());
    if (!certificate) {
        return GM_INTERNAL;
    }

    identity.reset(new Ed25519Identity(
        std::make_unique<Impl>(std::move(key), std::move(certificate))));
    return GM_OK;
}

gm_status Ed25519Identity::load(gm_bytes private_key_pkcs8, gm_bytes certificate_der,
                                std::unique_ptr<Ed25519Identity> &identity) {
    identity.reset();
    if (private_key_pkcs8.data == nullptr || private_key_pkcs8.size == 0u ||
        certificate_der.data == nullptr || certificate_der.size == 0u ||
        private_key_pkcs8.size > static_cast<size_t>(LONG_MAX) ||
        certificate_der.size > GM_IDENTITY_LEAF_DER_MAX_BYTES) {
        return GM_BAD_ARGUMENT;
    }

    PrivateKey key = decode_pkcs8(private_key_pkcs8);
    const unsigned char *certificate_data = certificate_der.data;
    Certificate certificate(
        d2i_X509(nullptr, &certificate_data, static_cast<long>(certificate_der.size)),
        X509_free);
    PublicKey certificate_key(
        certificate ? X509_get_pubkey(certificate.get()) : nullptr,
        EVP_PKEY_free);
    if (!key || !certificate || !certificate_key ||
        certificate_data != certificate_der.data + certificate_der.size ||
        EVP_PKEY_eq(key.get(), certificate_key.get()) != 1) {
        return GM_BAD_MESSAGE;
    }
    const detail::CertificateProfileResult profile =
        detail::certificate_profile(certificate.get());
    if (profile == detail::CertificateProfileResult::expired) {
        return GM_STATE_CONFLICT;
    }
    if (profile != detail::CertificateProfileResult::valid) {
        return GM_BAD_MESSAGE;
    }

    identity.reset(new Ed25519Identity(
        std::make_unique<Impl>(std::move(key), std::move(certificate))));
    return GM_OK;
}

gm_status Ed25519Identity::load_raw_private_key(
    gm_bytes private_key_raw,
    gm_bytes certificate_der,
    std::unique_ptr<Ed25519Identity> &identity) {
    identity.reset();
    if (private_key_raw.data == nullptr || private_key_raw.size != 32u ||
        certificate_der.data == nullptr || certificate_der.size == 0u ||
        certificate_der.size > GM_IDENTITY_LEAF_DER_MAX_BYTES) {
        return GM_BAD_ARGUMENT;
    }
    PrivateKey key(
        EVP_PKEY_new_raw_private_key(
            EVP_PKEY_ED25519,
            nullptr,
            private_key_raw.data,
            private_key_raw.size),
        EVP_PKEY_free);
    const unsigned char *certificate_data = certificate_der.data;
    Certificate certificate(
        d2i_X509(nullptr, &certificate_data, static_cast<long>(certificate_der.size)),
        X509_free);
    PublicKey certificate_key(
        certificate ? X509_get_pubkey(certificate.get()) : nullptr,
        EVP_PKEY_free);
    if (!key || !certificate || !certificate_key ||
        certificate_data != certificate_der.data + certificate_der.size ||
        EVP_PKEY_eq(key.get(), certificate_key.get()) != 1) {
        return GM_BAD_MESSAGE;
    }
    const detail::CertificateProfileResult profile =
        detail::certificate_profile(certificate.get());
    if (profile == detail::CertificateProfileResult::expired) {
        return GM_STATE_CONFLICT;
    }
    if (profile != detail::CertificateProfileResult::valid) {
        return GM_BAD_MESSAGE;
    }
    identity.reset(new Ed25519Identity(
        std::make_unique<Impl>(std::move(key), std::move(certificate))));
    return GM_OK;
}

gm_status Ed25519Identity::renew_raw_private_key(
    gm_bytes private_key_raw,
    std::unique_ptr<Ed25519Identity> &identity) {
    identity.reset();
    if (private_key_raw.data == nullptr || private_key_raw.size != 32u) {
        return GM_BAD_ARGUMENT;
    }
    PrivateKey key(
        EVP_PKEY_new_raw_private_key(
            EVP_PKEY_ED25519,
            nullptr,
            private_key_raw.data,
            private_key_raw.size),
        EVP_PKEY_free);
    if (!key) {
        return GM_BAD_MESSAGE;
    }
    Certificate certificate = make_certificate(key.get());
    if (!certificate) {
        return GM_INTERNAL;
    }
    identity.reset(new Ed25519Identity(
        std::make_unique<Impl>(std::move(key), std::move(certificate))));
    return GM_OK;
}

gm_status Ed25519Identity::renew_certificate(
    gm_bytes private_key_pkcs8,
    std::unique_ptr<Ed25519Identity> &identity) {
    identity.reset();
    PrivateKey key = decode_pkcs8(private_key_pkcs8);
    if (!key) {
        return GM_BAD_MESSAGE;
    }
    Certificate certificate = make_certificate(key.get());
    if (!certificate) {
        return GM_INTERNAL;
    }
    identity.reset(new Ed25519Identity(
        std::make_unique<Impl>(std::move(key), std::move(certificate))));
    return GM_OK;
}

gm_status Ed25519Identity::private_key_pkcs8(std::vector<uint8_t> &der) const {
    der.clear();
    return impl_ && encode_private_key(impl_->key.get(), der) ? GM_OK : GM_INTERNAL;
}

gm_status Ed25519Identity::private_key_raw(std::vector<uint8_t> &bytes) const {
    bytes.clear();
    if (!impl_) {
        return GM_BAD_ARGUMENT;
    }
    size_t size = 0u;
    if (EVP_PKEY_get_raw_private_key(impl_->key.get(), nullptr, &size) != 1 ||
        size != 32u) {
        return GM_INTERNAL;
    }
    bytes.resize(size);
    return EVP_PKEY_get_raw_private_key(impl_->key.get(), bytes.data(), &size) == 1 &&
                   size == bytes.size()
        ? GM_OK
        : GM_INTERNAL;
}

gm_status Ed25519Identity::certificate_der(std::vector<uint8_t> &der) const {
    der.clear();
    return impl_ && encode_certificate(impl_->certificate.get(), der) ? GM_OK : GM_INTERNAL;
}

gm_status Ed25519Identity::public_key_spki_der(std::vector<uint8_t> &der) const {
    der.clear();
    return impl_ && encode_spki(impl_->key.get(), der) ? GM_OK : GM_INTERNAL;
}

gm_status Ed25519Identity::spki_sha256(std::array<uint8_t, GM_SPKI_DIGEST_BYTES> &digest) const {
    std::vector<uint8_t> spki;
    if (public_key_spki_der(spki) != GM_OK ||
        SHA256(spki.data(), spki.size(), digest.data()) == nullptr) {
        digest.fill(0u);
        return GM_INTERNAL;
    }
    return GM_OK;
}

gm_status Ed25519Identity::sign(gm_bytes message, std::vector<uint8_t> &signature) const {
    signature.clear();
    if (!impl_ || (message.size != 0u && message.data == nullptr)) {
        return GM_BAD_ARGUMENT;
    }

    DigestContext context(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    size_t signature_size = 0u;
    if (!context || EVP_DigestSignInit(context.get(), nullptr, nullptr, nullptr, impl_->key.get()) != 1 ||
        EVP_DigestSign(context.get(), nullptr, &signature_size, message.data, message.size) != 1) {
        return GM_INTERNAL;
    }

    signature.resize(signature_size);
    if (EVP_DigestSign(context.get(), signature.data(), &signature_size, message.data, message.size) != 1) {
        signature.clear();
        return GM_INTERNAL;
    }
    signature.resize(signature_size);
    return GM_OK;
}

void *Ed25519Identity::native_private_key() const {
    return impl_ ? impl_->key.get() : nullptr;
}

void *Ed25519Identity::native_certificate() const {
    return impl_ ? impl_->certificate.get() : nullptr;
}

}
