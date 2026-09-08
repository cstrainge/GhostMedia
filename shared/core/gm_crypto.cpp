#include <ghostmedia/gm_core.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace {
constexpr char kExporterLabel[] = "EXPORTER-GhostMedia-v1";
constexpr char kExporterContextPrefix[] = "ghostmedia/1";
constexpr char kPeerIdAlphabet[] = "abcdefghijklmnopqrstuvwxyz234567";

constexpr uint32_t kSha256InitialState[8] = {
    0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
    0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u
};

constexpr uint32_t kSha256RoundConstants[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u,
    0xab1c5ed5u, 0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu,
    0x9bdc06a7u, 0xc19bf174u, 0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu,
    0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau, 0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu,
    0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u, 0xa2bfe8a1u, 0xa81a664bu,
    0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u, 0x19a4c116u,
    0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u,
    0xc67178f2u
};

bool has_readable_data(gm_bytes bytes) {
    return bytes.size == 0u || bytes.data != nullptr;
}

bool has_writable_data(gm_mut_bytes bytes) {
    return bytes.size == 0u || bytes.data != nullptr;
}

bool all_zero(const uint8_t *bytes, size_t size) {
    for (size_t index = 0; index < size; ++index) {
        if (bytes[index] != 0u) {
            return false;
        }
    }
    return true;
}

bool bounded_c_string(const char *value, size_t capacity, size_t *out_length) {
    if (value == nullptr || capacity == 0u) {
        return false;
    }
    for (size_t index = 0; index < capacity; ++index) {
        if (value[index] == '\0') {
            if (out_length != nullptr) {
                *out_length = index;
            }
            return true;
        }
    }
    return false;
}

bool flag_is_bool(uint8_t value) {
    return value == 0u || value == 1u;
}

bool known_permission(uint32_t permission) {
    return permission == GM_TRUST_PERMISSION_CONNECT || permission == GM_TRUST_PERMISSION_VIEW_STATUS ||
           permission == GM_TRUST_PERMISSION_RECEIVE_SYSTEM_AUDIO ||
           permission == GM_TRUST_PERMISSION_PROVIDE_MICROPHONE ||
           permission == GM_TRUST_PERMISSION_PROVIDE_CAMERA;
}

uint32_t rotate_right(uint32_t value, uint32_t shift) {
    return (value >> shift) | (value << (32u - shift));
}

uint32_t read_u32_be(const uint8_t *data) {
    return (static_cast<uint32_t>(data[0]) << 24u) | (static_cast<uint32_t>(data[1]) << 16u) |
           (static_cast<uint32_t>(data[2]) << 8u) | static_cast<uint32_t>(data[3]);
}

void write_u32_be(uint8_t *data, uint32_t value) {
    data[0] = static_cast<uint8_t>((value >> 24u) & 0xffu);
    data[1] = static_cast<uint8_t>((value >> 16u) & 0xffu);
    data[2] = static_cast<uint8_t>((value >> 8u) & 0xffu);
    data[3] = static_cast<uint8_t>(value & 0xffu);
}

void sha256_transform(const uint8_t *block, uint32_t *state) {
    uint32_t schedule[64]{};
    for (size_t index = 0; index < 16u; ++index) {
        schedule[index] = read_u32_be(block + (index * 4u));
    }
    for (size_t index = 16u; index < 64u; ++index) {
        const uint32_t small_sigma0 = rotate_right(schedule[index - 15u], 7u) ^
                                      rotate_right(schedule[index - 15u], 18u) ^
                                      (schedule[index - 15u] >> 3u);
        const uint32_t small_sigma1 = rotate_right(schedule[index - 2u], 17u) ^
                                      rotate_right(schedule[index - 2u], 19u) ^
                                      (schedule[index - 2u] >> 10u);
        schedule[index] = schedule[index - 16u] + small_sigma0 + schedule[index - 7u] + small_sigma1;
    }

    uint32_t working[8]{};
    std::memcpy(working, state, sizeof(working));
    for (size_t index = 0; index < 64u; ++index) {
        const uint32_t sum1 = rotate_right(working[4], 6u) ^ rotate_right(working[4], 11u) ^ rotate_right(working[4], 25u);
        const uint32_t choice = (working[4] & working[5]) ^ (~working[4] & working[6]);
        const uint32_t temp1 = working[7] + sum1 + choice + kSha256RoundConstants[index] + schedule[index];
        const uint32_t sum0 = rotate_right(working[0], 2u) ^ rotate_right(working[0], 13u) ^ rotate_right(working[0], 22u);
        const uint32_t majority = (working[0] & working[1]) ^ (working[0] & working[2]) ^ (working[1] & working[2]);
        const uint32_t temp2 = sum0 + majority;

        working[7] = working[6];
        working[6] = working[5];
        working[5] = working[4];
        working[4] = working[3] + temp1;
        working[3] = working[2];
        working[2] = working[1];
        working[1] = working[0];
        working[0] = temp1 + temp2;
    }

    for (size_t index = 0; index < 8u; ++index) {
        state[index] += working[index];
    }
}

void sha256_fixed(gm_bytes input, uint8_t *out_digest) {
    std::array<uint8_t, 128> padded{};
    std::memcpy(padded.data(), input.data, input.size);
    padded[input.size] = 0x80u;
    const size_t padded_size = ((input.size + 1u + 8u + 63u) / 64u) * 64u;
    const uint64_t bit_size = static_cast<uint64_t>(input.size) * 8u;
    for (size_t index = 0; index < 8u; ++index) {
        padded[padded_size - 1u - index] = static_cast<uint8_t>((bit_size >> (index * 8u)) & 0xffu);
    }

    uint32_t state[8]{};
    std::memcpy(state, kSha256InitialState, sizeof(state));
    for (size_t offset = 0; offset < padded_size; offset += 64u) {
        sha256_transform(padded.data() + offset, state);
    }
    for (size_t index = 0; index < 8u; ++index) {
        write_u32_be(out_digest + (index * 4u), state[index]);
    }
}

void append_bytes(uint8_t *destination, size_t *offset, const uint8_t *source, size_t size) {
    std::memcpy(destination + *offset, source, size);
    *offset += size;
}

void append_u32_be(uint8_t *destination, size_t *offset, uint32_t value) {
    write_u32_be(destination + *offset, value);
    *offset += 4u;
}

gm_status validate_bool_flags(const gm_tls_peer_policy_observation &observation) {
    const uint8_t flags[] = {
        observation.leaf_self_signed,
        observation.public_key_ed25519,
        observation.signature_ed25519,
        observation.basic_constraints_ca,
        observation.key_usage_digital_signature,
        observation.eku_client_auth,
        observation.eku_server_auth,
        observation.unknown_critical_extension,
        observation.within_validity,
        observation.local_clock_trusted,
        observation.system_trust_used,
        observation.public_ca_path_used,
        observation.psk_or_ticket_used,
        observation.early_data_used,
        observation.compression_used,
        observation.renegotiation_used,
        observation.trust_record_connect,
        observation.trust_record_revoked
    };
    for (uint8_t flag : flags) {
        if (!flag_is_bool(flag)) {
            return GM_BAD_ARGUMENT;
        }
    }
    if (!all_zero(observation.reserved, sizeof(observation.reserved))) {
        return GM_BAD_ARGUMENT;
    }
    return GM_OK;
}
}

const char *gm_tls_exporter_label(void) {
    return kExporterLabel;
}

gm_status gm_identity_encode_peer_id(gm_bytes spki_digest, gm_mut_bytes output, size_t *written) {
    if (written == nullptr || !has_readable_data(spki_digest) || !has_writable_data(output)) {
        return GM_BAD_ARGUMENT;
    }
    *written = GM_PEER_ID_BASE32_BYTES + 1u;
    if (spki_digest.size != GM_SPKI_DIGEST_BYTES) {
        return GM_BAD_MESSAGE;
    }
    if (output.size < GM_PEER_ID_BASE32_BYTES + 1u) {
        return GM_BUFFER_TOO_SMALL;
    }
    if (output.data == nullptr) {
        return GM_BAD_ARGUMENT;
    }

    size_t output_index = 0u;
    uint32_t bit_buffer = 0u;
    uint32_t bits_available = 0u;
    for (size_t input_index = 0u; input_index < spki_digest.size; ++input_index) {
        bit_buffer = (bit_buffer << 8u) | spki_digest.data[input_index];
        bits_available += 8u;
        while (bits_available >= 5u) {
            const uint32_t alphabet_index = (bit_buffer >> (bits_available - 5u)) & 0x1fu;
            output.data[output_index++] = static_cast<uint8_t>(kPeerIdAlphabet[alphabet_index]);
            bits_available -= 5u;
        }
    }
    if (bits_available != 0u) {
        const uint32_t alphabet_index = (bit_buffer << (5u - bits_available)) & 0x1fu;
        output.data[output_index++] = static_cast<uint8_t>(kPeerIdAlphabet[alphabet_index]);
    }
    output.data[output_index] = 0u;
    return output_index == GM_PEER_ID_BASE32_BYTES ? GM_OK : GM_INTERNAL;
}

gm_status gm_trust_record_authorizes(const gm_trust_record *record, uint32_t permission, uint8_t *out_authorized) {
    if (record == nullptr || out_authorized == nullptr || record->struct_size < sizeof(gm_trust_record) ||
        record->abi_version != GM_ABI_VERSION || !known_permission(permission) || record->revoked > 1u ||
        !all_zero(record->reserved, sizeof(record->reserved))) {
        return GM_BAD_ARGUMENT;
    }
    *out_authorized = record->revoked == 0u && (record->permissions & permission) == permission ? 1u : 0u;
    return GM_OK;
}

gm_status gm_tls_peer_policy_validate(const gm_tls_peer_policy_observation *observation) {
    if (observation == nullptr || observation->struct_size < sizeof(gm_tls_peer_policy_observation) ||
        observation->abi_version != GM_ABI_VERSION) {
        return GM_BAD_ARGUMENT;
    }
    const gm_status flag_status = validate_bool_flags(*observation);
    if (flag_status != GM_OK) {
        return flag_status;
    }
    size_t alpn_length = 0u;
    if (!bounded_c_string(observation->alpn, sizeof(observation->alpn), &alpn_length) ||
        alpn_length != GM_TLS_ALPN_BYTES || std::strcmp(observation->alpn, "ghostmedia/1") != 0) {
        return GM_BAD_MESSAGE;
    }
    if (observation->tls_version != GM_TLS_VERSION_1_3 || observation->peer_certificate_count != 1u ||
        observation->leaf_der_size == 0u || observation->leaf_der_size > GM_IDENTITY_LEAF_DER_MAX_BYTES ||
        observation->leaf_self_signed == 0u || observation->public_key_ed25519 == 0u ||
        observation->signature_ed25519 == 0u || observation->basic_constraints_ca != 0u ||
        observation->key_usage_digital_signature == 0u || observation->eku_client_auth == 0u ||
        observation->eku_server_auth == 0u || observation->unknown_critical_extension != 0u ||
        observation->within_validity == 0u || observation->local_clock_trusted == 0u ||
        observation->system_trust_used != 0u || observation->public_ca_path_used != 0u ||
        observation->psk_or_ticket_used != 0u || observation->early_data_used != 0u ||
        observation->compression_used != 0u || observation->renegotiation_used != 0u) {
        return GM_BAD_MESSAGE;
    }
    if (observation->trust_record_connect == 0u || observation->trust_record_revoked != 0u) {
        return GM_UNAUTHORIZED;
    }
    return GM_OK;
}

gm_status gm_crypto_build_exporter_context(const gm_crypto_exporter_context_input *input, gm_mut_bytes output,
                                           size_t *written) {
    if (input == nullptr || written == nullptr || !has_writable_data(output) ||
        input->struct_size < sizeof(gm_crypto_exporter_context_input) || input->abi_version != GM_ABI_VERSION) {
        return GM_BAD_ARGUMENT;
    }
    *written = GM_TLS_EXPORTER_CONTEXT_BYTES;
    if (input->stream_id == 0u || input->key_epoch == 0u ||
        (input->direction != GM_MEDIA_DIRECTION_WIN_TO_APPLE && input->direction != GM_MEDIA_DIRECTION_APPLE_TO_WIN)) {
        return GM_BAD_MESSAGE;
    }
    if (output.size < GM_TLS_EXPORTER_CONTEXT_BYTES) {
        return GM_BUFFER_TOO_SMALL;
    }
    if (output.data == nullptr) {
        return GM_BAD_ARGUMENT;
    }

    std::array<uint8_t, 101> preimage{};
    size_t offset = 0u;
    append_bytes(preimage.data(), &offset, reinterpret_cast<const uint8_t *>(kExporterContextPrefix), GM_TLS_ALPN_BYTES);
    append_bytes(preimage.data(), &offset, input->session_id, GM_SESSION_ID_BYTES);
    append_u32_be(preimage.data(), &offset, input->stream_id);
    preimage[offset++] = static_cast<uint8_t>(input->direction);
    append_u32_be(preimage.data(), &offset, input->key_epoch);
    append_bytes(preimage.data(), &offset, input->sender_spki_digest, GM_SPKI_DIGEST_BYTES);
    append_bytes(preimage.data(), &offset, input->receiver_spki_digest, GM_SPKI_DIGEST_BYTES);

    if (offset != preimage.size()) {
        return GM_INTERNAL;
    }
    sha256_fixed(gm_bytes{preimage.data(), preimage.size()}, output.data);
    return GM_OK;
}

gm_status gm_crypto_split_exporter_output(gm_bytes exporter_output, gm_directional_keys *out_keys) {
    if (out_keys == nullptr || out_keys->struct_size < sizeof(gm_directional_keys) || !has_readable_data(exporter_output)) {
        return GM_BAD_ARGUMENT;
    }
    if (exporter_output.size != GM_TLS_EXPORTER_OUTPUT_BYTES) {
        return GM_BAD_MESSAGE;
    }
    const size_t caller_size = out_keys->struct_size;
    std::memset(out_keys, 0, sizeof(gm_directional_keys));
    out_keys->struct_size = caller_size;
    out_keys->abi_version = GM_ABI_VERSION;
    std::memcpy(out_keys->media_key, exporter_output.data, GM_CRYPTO_KEY_BYTES);
    std::memcpy(out_keys->path_key, exporter_output.data + GM_CRYPTO_KEY_BYTES, GM_CRYPTO_KEY_BYTES);
    return GM_OK;
}

gm_status gm_media_build_aad(const gm_media_header *header, gm_mut_bytes output, size_t *written) {
    return gm_media_encode_header(header, output, written);
}

gm_status gm_crypto_validate_aead_inputs(gm_bytes key, gm_bytes nonce, gm_bytes aad, gm_bytes payload, gm_bytes tag) {
    if (!has_readable_data(key) || !has_readable_data(nonce) || !has_readable_data(aad) ||
        !has_readable_data(payload) || !has_readable_data(tag)) {
        return GM_BAD_ARGUMENT;
    }
    if (key.size != GM_CRYPTO_KEY_BYTES || nonce.size != GM_MEDIA_NONCE_BYTES || aad.size != GM_MEDIA_HEADER_BYTES ||
        tag.size != GM_MEDIA_TAG_BYTES || payload.size > GM_MEDIA_MAX_PAYLOAD_BYTES) {
        return GM_BAD_MESSAGE;
    }
    return GM_OK;
}