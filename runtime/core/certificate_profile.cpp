#include "certificate_profile.h"

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/x509v3.h>

#include <memory>
#include <vector>

namespace {
using PublicKey = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
}

namespace ghostmedia::runtime::detail {

bool certificate_spki_digest(
    X509 *certificate,
    std::array<uint8_t, GM_SPKI_DIGEST_BYTES> &digest) {
    PublicKey public_key(X509_get_pubkey(certificate), EVP_PKEY_free);
    if (!public_key) {
        return false;
    }
    const int size = i2d_PUBKEY(public_key.get(), nullptr);
    if (size <= 0) {
        return false;
    }
    std::vector<unsigned char> encoded(static_cast<size_t>(size));
    unsigned char *cursor = encoded.data();
    return i2d_PUBKEY(public_key.get(), &cursor) == size &&
           SHA256(encoded.data(), encoded.size(), digest.data()) != nullptr;
}

CertificateProfileResult certificate_profile(X509 *certificate) {
    int validity_days = 0;
    int validity_seconds = 0;
    const int certificate_size =
        certificate == nullptr ? -1 : i2d_X509(certificate, nullptr);
    if (certificate == nullptr ||
        certificate_size <= 0 ||
        certificate_size > static_cast<int>(GM_IDENTITY_LEAF_DER_MAX_BYTES) ||
        X509_get_version(certificate) != 2L) {
        return CertificateProfileResult::invalid;
    }
    if (X509_cmp_current_time(X509_get0_notBefore(certificate)) > 0) {
        return CertificateProfileResult::not_yet_valid;
    }
    if (X509_cmp_current_time(X509_get0_notAfter(certificate)) < 0) {
        return CertificateProfileResult::expired;
    }
    if (
        ASN1_TIME_diff(
            &validity_days,
            &validity_seconds,
            X509_get0_notBefore(certificate),
            X509_get0_notAfter(certificate)) != 1 ||
        validity_days > 825 ||
        (validity_days == 825 && validity_seconds > 0) ||
        ASN1_STRING_length(X509_get_serialNumber(certificate)) < 8 ||
        X509_get_ext_by_NID(certificate, NID_subject_alt_name, -1) != -1 ||
        X509_NAME_cmp(
            X509_get_subject_name(certificate),
            X509_get_issuer_name(certificate)) != 0) {
        return CertificateProfileResult::invalid;
    }

    PublicKey public_key(X509_get_pubkey(certificate), EVP_PKEY_free);
    if (!public_key || EVP_PKEY_id(public_key.get()) != EVP_PKEY_ED25519 ||
        X509_verify(certificate, public_key.get()) != 1 ||
        X509_get_signature_nid(certificate) != NID_ED25519) {
        return CertificateProfileResult::invalid;
    }

    int critical = 0;
    BASIC_CONSTRAINTS *basic_constraints = static_cast<BASIC_CONSTRAINTS *>(
        X509_get_ext_d2i(certificate, NID_basic_constraints, &critical, nullptr));
    const bool valid_basic_constraints =
        basic_constraints != nullptr && critical == 1 && basic_constraints->ca == 0;
    BASIC_CONSTRAINTS_free(basic_constraints);
    if (!valid_basic_constraints) {
        return CertificateProfileResult::invalid;
    }

    ASN1_BIT_STRING *key_usage = static_cast<ASN1_BIT_STRING *>(
        X509_get_ext_d2i(certificate, NID_key_usage, &critical, nullptr));
    bool valid_key_usage =
        key_usage != nullptr && critical == 1 && ASN1_BIT_STRING_get_bit(key_usage, 0) == 1;
    const int key_usage_bits =
        key_usage == nullptr ? 0 : ASN1_STRING_length(key_usage) * 8;
    for (int bit = 1; valid_key_usage && bit < key_usage_bits; ++bit) {
        valid_key_usage = ASN1_BIT_STRING_get_bit(key_usage, bit) == 0;
    }
    ASN1_BIT_STRING_free(key_usage);
    if (!valid_key_usage) {
        return CertificateProfileResult::invalid;
    }

    EXTENDED_KEY_USAGE *extended_key_usage = static_cast<EXTENDED_KEY_USAGE *>(
        X509_get_ext_d2i(certificate, NID_ext_key_usage, &critical, nullptr));
    int client_auth_count = 0;
    int server_auth_count = 0;
    bool has_other_usage = false;
    if (extended_key_usage != nullptr) {
        for (int index = 0; index < sk_ASN1_OBJECT_num(extended_key_usage); ++index) {
            const int nid = OBJ_obj2nid(sk_ASN1_OBJECT_value(extended_key_usage, index));
            client_auth_count += nid == NID_client_auth ? 1 : 0;
            server_auth_count += nid == NID_server_auth ? 1 : 0;
            has_other_usage = has_other_usage ||
                (nid != NID_client_auth && nid != NID_server_auth);
        }
    }
    const bool valid_extended_key_usage =
        extended_key_usage != nullptr &&
        client_auth_count == 1 &&
        server_auth_count == 1 &&
        !has_other_usage;
    EXTENDED_KEY_USAGE_free(extended_key_usage);
    if (!valid_extended_key_usage) {
        return CertificateProfileResult::invalid;
    }

    for (int index = 0; index < X509_get_ext_count(certificate); ++index) {
        X509_EXTENSION *extension = X509_get_ext(certificate, index);
        const int nid = OBJ_obj2nid(X509_EXTENSION_get_object(extension));
        if (X509_EXTENSION_get_critical(extension) == 1 &&
            nid != NID_basic_constraints &&
            nid != NID_key_usage &&
            nid != NID_ext_key_usage) {
            return CertificateProfileResult::invalid;
        }
    }
    return CertificateProfileResult::valid;
}

}
