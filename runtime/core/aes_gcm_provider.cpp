#include <ghostmedia/runtime/aes_gcm_provider.h>

#include <openssl/evp.h>

#include <climits>
#include <memory>

namespace {
using CipherContext = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;

gm_status validate_common(gm_bytes key, gm_bytes nonce, gm_bytes aad, gm_bytes payload, gm_bytes tag) {
    const gm_bytes values[] = {key, nonce, aad, payload, tag};
    for (const gm_bytes value : values) {
        if (value.size != 0u && value.data == nullptr) {
            return GM_BAD_ARGUMENT;
        }
    }
    if (key.size != GM_CRYPTO_KEY_BYTES || nonce.size != GM_MEDIA_NONCE_BYTES || tag.size != GM_MEDIA_TAG_BYTES ||
        aad.size > GM_MEDIA_HEADER_BYTES || payload.size > GM_MEDIA_MAX_PAYLOAD_BYTES ||
        aad.size > static_cast<size_t>(INT_MAX) || payload.size > static_cast<size_t>(INT_MAX)) {
        return GM_BAD_MESSAGE;
    }
    return GM_OK;
}
}

namespace ghostmedia::runtime {

gm_status aes256_gcm_encrypt(gm_bytes key, gm_bytes nonce, gm_bytes aad, gm_bytes plaintext,
                             std::vector<uint8_t> &ciphertext,
                             std::array<uint8_t, GM_MEDIA_TAG_BYTES> &tag) {
    const gm_status input_status = validate_common(key, nonce, aad, plaintext, gm_bytes{tag.data(), tag.size()});
    if (input_status != GM_OK) {
        return input_status;
    }

    CipherContext context(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!context ||
        EVP_EncryptInit_ex(context.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(nonce.size), nullptr) != 1 ||
        EVP_EncryptInit_ex(context.get(), nullptr, nullptr, key.data, nonce.data) != 1) {
        return GM_INTERNAL;
    }

    int bytes_done = 0;
    if (aad.size != 0u &&
        EVP_EncryptUpdate(context.get(), nullptr, &bytes_done, aad.data, static_cast<int>(aad.size)) != 1) {
        return GM_INTERNAL;
    }

    ciphertext.assign(plaintext.size, 0u);
    if (plaintext.size != 0u &&
        (EVP_EncryptUpdate(context.get(), ciphertext.data(), &bytes_done, plaintext.data,
                           static_cast<int>(plaintext.size)) != 1 ||
         bytes_done != static_cast<int>(plaintext.size))) {
        ciphertext.clear();
        return GM_INTERNAL;
    }

    std::array<uint8_t, 1> final_output{};
    int final_bytes = 0;
    if (EVP_EncryptFinal_ex(context.get(), final_output.data(), &final_bytes) != 1 || final_bytes != 0 ||
        EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_GCM_GET_TAG, static_cast<int>(tag.size()), tag.data()) != 1) {
        ciphertext.clear();
        return GM_INTERNAL;
    }
    return GM_OK;
}

gm_status aes256_gcm_decrypt(gm_bytes key, gm_bytes nonce, gm_bytes aad, gm_bytes ciphertext, gm_bytes tag,
                             std::vector<uint8_t> &plaintext) {
    const gm_status input_status = validate_common(key, nonce, aad, ciphertext, tag);
    if (input_status != GM_OK) {
        return input_status;
    }

    CipherContext context(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!context ||
        EVP_DecryptInit_ex(context.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(nonce.size), nullptr) != 1 ||
        EVP_DecryptInit_ex(context.get(), nullptr, nullptr, key.data, nonce.data) != 1) {
        return GM_INTERNAL;
    }

    int bytes_done = 0;
    if (aad.size != 0u &&
        EVP_DecryptUpdate(context.get(), nullptr, &bytes_done, aad.data, static_cast<int>(aad.size)) != 1) {
        return GM_INTERNAL;
    }

    plaintext.assign(ciphertext.size, 0u);
    if (ciphertext.size != 0u &&
        (EVP_DecryptUpdate(context.get(), plaintext.data(), &bytes_done, ciphertext.data,
                           static_cast<int>(ciphertext.size)) != 1 ||
         bytes_done != static_cast<int>(ciphertext.size))) {
        plaintext.clear();
        return GM_INTERNAL;
    }
    if (EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_GCM_SET_TAG, static_cast<int>(tag.size),
                            const_cast<uint8_t *>(tag.data)) != 1) {
        plaintext.clear();
        return GM_INTERNAL;
    }

    std::array<uint8_t, 1> final_output{};
    int final_bytes = 0;
    if (EVP_DecryptFinal_ex(context.get(), final_output.data(), &final_bytes) != 1) {
        plaintext.clear();
        return GM_BAD_MESSAGE;
    }
    if (final_bytes != 0) {
        plaintext.clear();
        return GM_INTERNAL;
    }
    return GM_OK;
}

}