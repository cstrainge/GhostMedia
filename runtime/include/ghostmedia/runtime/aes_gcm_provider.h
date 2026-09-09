#ifndef GHOSTMEDIA_RUNTIME_AES_GCM_PROVIDER_H
#define GHOSTMEDIA_RUNTIME_AES_GCM_PROVIDER_H

#include <ghostmedia/gm_core.h>

#include <array>
#include <cstdint>
#include <vector>

namespace ghostmedia::runtime {

gm_status aes256_gcm_encrypt(gm_bytes key, gm_bytes nonce, gm_bytes aad, gm_bytes plaintext,
                             std::vector<uint8_t> &ciphertext,
                             std::array<uint8_t, GM_MEDIA_TAG_BYTES> &tag);

gm_status aes256_gcm_decrypt(gm_bytes key, gm_bytes nonce, gm_bytes aad, gm_bytes ciphertext, gm_bytes tag,
                             std::vector<uint8_t> &plaintext);

}

#endif