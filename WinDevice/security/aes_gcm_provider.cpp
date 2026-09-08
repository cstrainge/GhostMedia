#include <ghostmedia/win/aes_gcm_provider.h>

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <bcrypt.h>

#include <cwchar>
#include <utility>

namespace {
bool nt_success(NTSTATUS status) {
    return status >= 0;
}

PUCHAR mutable_data(gm_bytes bytes) {
    return bytes.size == 0u ? nullptr : const_cast<PUCHAR>(bytes.data);
}

ULONG byte_count(gm_bytes bytes) {
    return static_cast<ULONG>(bytes.size);
}

class AlgorithmHandle {
public:
    explicit AlgorithmHandle(BCRYPT_ALG_HANDLE handle) : handle_(handle) {}

    AlgorithmHandle(const AlgorithmHandle &) = delete;
    AlgorithmHandle &operator=(const AlgorithmHandle &) = delete;
    AlgorithmHandle(AlgorithmHandle &&other) noexcept : handle_(std::exchange(other.handle_, nullptr)) {}
    AlgorithmHandle &operator=(AlgorithmHandle &&other) noexcept {
        if (this != &other) {
            if (handle_ != nullptr) {
                BCryptCloseAlgorithmProvider(handle_, 0);
            }
            handle_ = std::exchange(other.handle_, nullptr);
        }
        return *this;
    }

    ~AlgorithmHandle() {
        if (handle_ != nullptr) {
            BCryptCloseAlgorithmProvider(handle_, 0);
        }
    }

    BCRYPT_ALG_HANDLE get() const {
        return handle_;
    }

private:
    BCRYPT_ALG_HANDLE handle_ = nullptr;
};

class KeyHandle {
public:
    KeyHandle(BCRYPT_KEY_HANDLE handle, std::vector<uint8_t> object_storage)
        : handle_(handle), object_storage_(std::move(object_storage)) {}

    KeyHandle(const KeyHandle &) = delete;
    KeyHandle &operator=(const KeyHandle &) = delete;
    KeyHandle(KeyHandle &&other) noexcept
        : handle_(std::exchange(other.handle_, nullptr)), object_storage_(std::move(other.object_storage_)) {}
    KeyHandle &operator=(KeyHandle &&other) noexcept {
        if (this != &other) {
            if (handle_ != nullptr) {
                BCryptDestroyKey(handle_);
            }
            handle_ = std::exchange(other.handle_, nullptr);
            object_storage_ = std::move(other.object_storage_);
        }
        return *this;
    }

    ~KeyHandle() {
        if (handle_ != nullptr) {
            BCryptDestroyKey(handle_);
        }
    }

    BCRYPT_KEY_HANDLE get() const {
        return handle_;
    }
private:
    BCRYPT_KEY_HANDLE handle_ = nullptr;
    std::vector<uint8_t> object_storage_;
};

gm_status open_aes_gcm_algorithm(AlgorithmHandle &algorithm) {
    BCRYPT_ALG_HANDLE algorithm_handle = nullptr;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&algorithm_handle, BCRYPT_AES_ALGORITHM, nullptr, 0);
    if (!nt_success(status)) {
        return GM_INTERNAL;
    }
    algorithm = AlgorithmHandle(algorithm_handle);
    status = BCryptSetProperty(
        algorithm.get(),
        BCRYPT_CHAINING_MODE,
        reinterpret_cast<PUCHAR>(const_cast<wchar_t *>(BCRYPT_CHAIN_MODE_GCM)),
        static_cast<ULONG>((std::wcslen(BCRYPT_CHAIN_MODE_GCM) + 1u) * sizeof(wchar_t)),
        0
    );
    return nt_success(status) ? GM_OK : GM_INTERNAL;
}

gm_status generate_key(BCRYPT_ALG_HANDLE algorithm, gm_bytes key, KeyHandle &generated_key) {
    DWORD object_length = 0;
    DWORD result_length = 0;
    NTSTATUS status = BCryptGetProperty(
        algorithm,
        BCRYPT_OBJECT_LENGTH,
        reinterpret_cast<PUCHAR>(&object_length),
        sizeof(object_length),
        &result_length,
        0
    );
    if (!nt_success(status)) {
        return GM_INTERNAL;
    }
    std::vector<uint8_t> key_object(object_length);
    BCRYPT_KEY_HANDLE key_handle = nullptr;
    status = BCryptGenerateSymmetricKey(
        algorithm,
        &key_handle,
        key_object.data(),
        object_length,
        mutable_data(key),
        byte_count(key),
        0
    );
    if (!nt_success(status)) {
        return GM_INTERNAL;
    }
    generated_key = KeyHandle(key_handle, std::move(key_object));
    return GM_OK;
}

gm_status validate_common(gm_bytes key, gm_bytes nonce, gm_bytes aad, gm_bytes payload, gm_bytes tag) {
    const gm_bytes values[] = {key, nonce, aad, payload, tag};
    for (const gm_bytes value : values) {
        if (value.size != 0u && value.data == nullptr) {
            return GM_BAD_ARGUMENT;
        }
    }
    if (key.size != GM_CRYPTO_KEY_BYTES || nonce.size != GM_MEDIA_NONCE_BYTES || tag.size != GM_MEDIA_TAG_BYTES ||
        aad.size > GM_MEDIA_HEADER_BYTES || payload.size > GM_MEDIA_MAX_PAYLOAD_BYTES) {
        return GM_BAD_MESSAGE;
    }
    return GM_OK;
}
}

namespace ghostmedia::win {

gm_status aes256_gcm_encrypt(gm_bytes key, gm_bytes nonce, gm_bytes aad, gm_bytes plaintext,
                             std::vector<uint8_t> &ciphertext,
                             std::array<uint8_t, GM_MEDIA_TAG_BYTES> &tag) {
    const gm_status input_status = validate_common(key, nonce, aad, plaintext, gm_bytes{tag.data(), tag.size()});
    if (input_status != GM_OK) {
        return input_status;
    }

    AlgorithmHandle algorithm(nullptr);
    gm_status status = open_aes_gcm_algorithm(algorithm);
    if (status != GM_OK) {
        return status;
    }
    KeyHandle generated_key(nullptr, {});
    status = generate_key(algorithm.get(), key, generated_key);
    if (status != GM_OK) {
        return status;
    }

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth_info;
    BCRYPT_INIT_AUTH_MODE_INFO(auth_info);
    auth_info.pbNonce = mutable_data(nonce);
    auth_info.cbNonce = byte_count(nonce);
    auth_info.pbAuthData = mutable_data(aad);
    auth_info.cbAuthData = byte_count(aad);
    auth_info.pbTag = tag.data();
    auth_info.cbTag = static_cast<ULONG>(tag.size());

    ciphertext.assign(plaintext.size, 0u);
    ULONG bytes_done = 0;
    const NTSTATUS encrypt_status = BCryptEncrypt(
        generated_key.get(),
        mutable_data(plaintext),
        byte_count(plaintext),
        &auth_info,
        nullptr,
        0,
        ciphertext.empty() ? nullptr : ciphertext.data(),
        static_cast<ULONG>(ciphertext.size()),
        &bytes_done,
        0
    );
    if (!nt_success(encrypt_status) || bytes_done != ciphertext.size()) {
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

    AlgorithmHandle algorithm(nullptr);
    gm_status status = open_aes_gcm_algorithm(algorithm);
    if (status != GM_OK) {
        return status;
    }
    KeyHandle generated_key(nullptr, {});
    status = generate_key(algorithm.get(), key, generated_key);
    if (status != GM_OK) {
        return status;
    }

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth_info;
    BCRYPT_INIT_AUTH_MODE_INFO(auth_info);
    auth_info.pbNonce = mutable_data(nonce);
    auth_info.cbNonce = byte_count(nonce);
    auth_info.pbAuthData = mutable_data(aad);
    auth_info.cbAuthData = byte_count(aad);
    auth_info.pbTag = mutable_data(tag);
    auth_info.cbTag = byte_count(tag);

    plaintext.assign(ciphertext.size, 0u);
    ULONG bytes_done = 0;
    const NTSTATUS decrypt_status = BCryptDecrypt(
        generated_key.get(),
        mutable_data(ciphertext),
        byte_count(ciphertext),
        &auth_info,
        nullptr,
        0,
        plaintext.empty() ? nullptr : plaintext.data(),
        static_cast<ULONG>(plaintext.size()),
        &bytes_done,
        0
    );
    if (!nt_success(decrypt_status)) {
        return GM_BAD_MESSAGE;
    }
    return bytes_done == plaintext.size() ? GM_OK : GM_INTERNAL;
}

}