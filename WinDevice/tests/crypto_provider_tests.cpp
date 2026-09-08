#include <ghostmedia/gm_core.h>
#include <ghostmedia/win/aes_gcm_provider.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

namespace {
int failures = 0;

void check(bool condition, const char *message) {
    if (!condition) {
        std::cerr << "FAIL: " << message << '\n';
        ++failures;
    }
}

void check_status(gm_status actual, gm_status expected, const char *message) {
    if (actual != expected) {
        std::cerr << "FAIL: " << message << " expected " << gm_status_string(expected)
                  << " got " << gm_status_string(actual) << '\n';
        ++failures;
    }
}

uint8_t hex_nibble(char character) {
    if (character >= '0' && character <= '9') {
        return static_cast<uint8_t>(character - '0');
    }
    if (character >= 'a' && character <= 'f') {
        return static_cast<uint8_t>(character - 'a' + 10);
    }
    if (character >= 'A' && character <= 'F') {
        return static_cast<uint8_t>(character - 'A' + 10);
    }
    check(false, "hex fixture contains invalid character");
    return 0u;
}

std::vector<uint8_t> bytes_from_hex(std::string_view hex) {
    check(hex.size() % 2u == 0u, "hex fixture has even length");
    std::vector<uint8_t> bytes(hex.size() / 2u);
    for (size_t index = 0; index < bytes.size(); ++index) {
        bytes[index] = static_cast<uint8_t>((hex_nibble(hex[index * 2u]) << 4u) |
                                            hex_nibble(hex[index * 2u + 1u]));
    }
    return bytes;
}

std::string hex_from_bytes(const uint8_t *data, size_t size) {
    constexpr char digits[] = "0123456789abcdef";
    std::string hex;
    hex.reserve(size * 2u);
    for (size_t index = 0; index < size; ++index) {
        hex.push_back(digits[(data[index] >> 4u) & 0x0fu]);
        hex.push_back(digits[data[index] & 0x0fu]);
    }
    return hex;
}

template <size_t Size>
void copy_bytes(uint8_t (&destination)[Size], const std::vector<uint8_t> &source) {
    check(source.size() == Size, "fixture length matches destination");
    std::memcpy(destination, source.data(), Size);
}

gm_bytes vector_bytes(const std::vector<uint8_t> &bytes) {
    return gm_bytes{bytes.empty() ? nullptr : bytes.data(), bytes.size()};
}

void test_known_empty_aes_gcm_vector() {
    const std::array<uint8_t, GM_CRYPTO_KEY_BYTES> zero_key{};
    const std::vector<uint8_t> empty_plaintext;
    const std::vector<uint8_t> empty_aad;
    const std::array<uint8_t, GM_MEDIA_NONCE_BYTES> zero_nonce{};
    std::vector<uint8_t> ciphertext;
    std::array<uint8_t, GM_MEDIA_TAG_BYTES> tag{};

    check_status(ghostmedia::win::aes256_gcm_encrypt(gm_bytes{zero_key.data(), zero_key.size()},
                                                     gm_bytes{zero_nonce.data(), zero_nonce.size()},
                                                     vector_bytes(empty_aad), vector_bytes(empty_plaintext),
                                                     ciphertext, tag),
                 GM_OK, "Windows AES-GCM adapter encrypts the empty known-answer vector");
    check(ciphertext.empty(), "empty known-answer vector has empty ciphertext");
    check(hex_from_bytes(tag.data(), tag.size()) == "530f8afbc74536b9a963b4f1c4cb738b",
          "Windows AES-GCM adapter empty tag matches NIST vector");
}

void test_media_aead_round_trip_and_tamper() {
    const std::array<uint8_t, GM_CRYPTO_KEY_BYTES> zero_key{};
    const std::vector<uint8_t> session_id = bytes_from_hex("00112233445566778899aabbccddeeff");
    gm_media_header header{};
    header.struct_size = sizeof(header);
    header.abi_version = GM_ABI_VERSION;
    header.kind = GM_MEDIA_KIND_PATH_CHALLENGE;
    copy_bytes(header.session_id, session_id);
    header.stream_id = 1u;
    header.direction = GM_MEDIA_DIRECTION_WIN_TO_APPLE;
    header.key_epoch = 1u;
    header.sequence = 1u;
    header.payload_length = 12u;

    std::array<uint8_t, GM_MEDIA_HEADER_BYTES> aad{};
    std::array<uint8_t, GM_MEDIA_NONCE_BYTES> nonce{};
    size_t written = 0u;
    check_status(gm_media_build_aad(&header, gm_mut_bytes{aad.data(), aad.size()}, &written), GM_OK,
                 "media AAD builds through shared core");
    check_status(gm_media_build_nonce(header.key_epoch, header.sequence, gm_mut_bytes{nonce.data(), nonce.size()}), GM_OK,
                 "media nonce builds through shared core");

    const std::vector<uint8_t> aad_bytes(aad.begin(), aad.end());
    const std::vector<uint8_t> plaintext = bytes_from_hex("000102030405060708090a0b");
    std::vector<uint8_t> ciphertext;
    std::array<uint8_t, GM_MEDIA_TAG_BYTES> tag{};
    check_status(gm_crypto_validate_aead_inputs(gm_bytes{nullptr, GM_CRYPTO_KEY_BYTES}, gm_bytes{nonce.data(), nonce.size()},
                                                gm_bytes{aad.data(), aad.size()}, gm_bytes{plaintext.data(), plaintext.size()},
                                                gm_bytes{tag.data(), tag.size()}),
                 GM_BAD_ARGUMENT, "shared core rejects a missing key pointer before provider use");

    check_status(ghostmedia::win::aes256_gcm_encrypt(gm_bytes{zero_key.data(), zero_key.size()},
                                                     gm_bytes{nonce.data(), nonce.size()}, vector_bytes(aad_bytes),
                                                     vector_bytes(plaintext), ciphertext, tag),
                 GM_OK, "Windows AES-GCM adapter encrypts media-shaped input");
    check(hex_from_bytes(ciphertext.data(), ciphertext.size()) == "66b08ccab7604f63c2a92e01",
          "Windows AES-GCM adapter media ciphertext matches locked vector");
    check(hex_from_bytes(tag.data(), tag.size()) == "d85931d533d9a35a11712f140821b2f4",
          "Windows AES-GCM adapter media tag matches locked vector");
    std::vector<uint8_t> recovered;
    check_status(ghostmedia::win::aes256_gcm_decrypt(gm_bytes{zero_key.data(), zero_key.size()},
                                                     gm_bytes{nonce.data(), nonce.size()}, vector_bytes(aad_bytes),
                                                     vector_bytes(ciphertext), gm_bytes{tag.data(), tag.size()}, recovered),
                 GM_OK, "Windows AES-GCM adapter decrypts authenticated media-shaped input");
    check(recovered == plaintext, "decrypted plaintext matches original payload");

    std::array<uint8_t, GM_MEDIA_TAG_BYTES> altered_tag = tag;
    altered_tag[0] ^= 0x01u;
    check_status(ghostmedia::win::aes256_gcm_decrypt(gm_bytes{zero_key.data(), zero_key.size()},
                                                     gm_bytes{nonce.data(), nonce.size()}, vector_bytes(aad_bytes),
                                                     vector_bytes(ciphertext),
                                                     gm_bytes{altered_tag.data(), altered_tag.size()}, recovered),
                 GM_BAD_MESSAGE, "Windows AES-GCM adapter rejects altered tag");

    std::vector<uint8_t> altered_ciphertext = ciphertext;
    altered_ciphertext[0] ^= 0x01u;
    check_status(ghostmedia::win::aes256_gcm_decrypt(gm_bytes{zero_key.data(), zero_key.size()},
                                                     gm_bytes{nonce.data(), nonce.size()}, vector_bytes(aad_bytes),
                                                     vector_bytes(altered_ciphertext), gm_bytes{tag.data(), tag.size()},
                                                     recovered),
                 GM_BAD_MESSAGE, "Windows AES-GCM adapter rejects altered ciphertext");

    std::vector<uint8_t> altered_aad = aad_bytes;
    altered_aad[0] ^= 0x01u;
    check_status(ghostmedia::win::aes256_gcm_decrypt(gm_bytes{zero_key.data(), zero_key.size()},
                                                     gm_bytes{nonce.data(), nonce.size()}, vector_bytes(altered_aad),
                                                     vector_bytes(ciphertext), gm_bytes{tag.data(), tag.size()}, recovered),
                 GM_BAD_MESSAGE, "Windows AES-GCM adapter rejects altered AAD");
}
}

int main() {
    test_known_empty_aes_gcm_vector();
    test_media_aead_round_trip_and_tamper();

    if (failures != 0) {
        std::cerr << failures << " failure(s)\n";
        return 1;
    }
    return 0;
}