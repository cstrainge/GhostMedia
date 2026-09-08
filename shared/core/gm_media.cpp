#include <ghostmedia/gm_core.h>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>

namespace {
constexpr uint64_t kRekeyGraceNs = static_cast<uint64_t>(GM_REKEY_GRACE_MS) * 1000ull * 1000ull;

bool has_readable_data(gm_bytes bytes) {
    return bytes.size == 0 || bytes.data != nullptr;
}

bool has_writable_data(gm_mut_bytes bytes) {
    return bytes.size == 0 || bytes.data != nullptr;
}

uint16_t read_u16_be(const uint8_t *data) {
    return static_cast<uint16_t>((static_cast<uint16_t>(data[0]) << 8u) | static_cast<uint16_t>(data[1]));
}

uint32_t read_u32_be(const uint8_t *data) {
    return (static_cast<uint32_t>(data[0]) << 24u) | (static_cast<uint32_t>(data[1]) << 16u) |
           (static_cast<uint32_t>(data[2]) << 8u) | static_cast<uint32_t>(data[3]);
}

uint64_t read_u64_be(const uint8_t *data) {
    uint64_t value = 0;
    for (size_t index = 0; index < 8u; ++index) {
        value = (value << 8u) | static_cast<uint64_t>(data[index]);
    }
    return value;
}

void write_u16_be(uint8_t *data, uint16_t value) {
    data[0] = static_cast<uint8_t>((value >> 8u) & 0xffu);
    data[1] = static_cast<uint8_t>(value & 0xffu);
}

void write_u32_be(uint8_t *data, uint32_t value) {
    data[0] = static_cast<uint8_t>((value >> 24u) & 0xffu);
    data[1] = static_cast<uint8_t>((value >> 16u) & 0xffu);
    data[2] = static_cast<uint8_t>((value >> 8u) & 0xffu);
    data[3] = static_cast<uint8_t>(value & 0xffu);
}

void write_u64_be(uint8_t *data, uint64_t value) {
    for (size_t index = 0; index < 8u; ++index) {
        data[7u - index] = static_cast<uint8_t>((value >> (index * 8u)) & 0xffu);
    }
}

bool validate_media_header_fields(const gm_media_header &header) {
    if (header.struct_size < sizeof(gm_media_header) || header.abi_version != GM_ABI_VERSION ||
        header.stream_id == 0u || header.key_epoch == 0u || header.payload_length > GM_MEDIA_MAX_PAYLOAD_BYTES) {
        return false;
    }

    switch (header.kind) {
    case GM_MEDIA_KIND_AUDIO:
        return header.direction == GM_MEDIA_DIRECTION_WIN_TO_APPLE && header.payload_length > 0u;
    case GM_MEDIA_KIND_PATH_CHALLENGE:
        return header.direction == GM_MEDIA_DIRECTION_WIN_TO_APPLE && header.media_timestamp == 0u &&
               header.payload_length == 12u;
    case GM_MEDIA_KIND_PATH_RESPONSE:
        return header.direction == GM_MEDIA_DIRECTION_APPLE_TO_WIN && header.media_timestamp == 0u &&
               header.payload_length == 12u;
    case GM_MEDIA_KIND_FEEDBACK:
        return header.direction == GM_MEDIA_DIRECTION_APPLE_TO_WIN && header.media_timestamp == 0u &&
               header.payload_length == GM_FEEDBACK_PAYLOAD_BYTES;
    default:
        return false;
    }
}

bool get_bit(const uint64_t *bitmap, uint64_t bit) {
    return (bitmap[bit / 64u] & (1ull << (bit % 64u))) != 0u;
}

void set_bit(uint64_t *bitmap, uint64_t bit) {
    bitmap[bit / 64u] |= 1ull << (bit % 64u);
}

void clear_bitmap(uint64_t *bitmap) {
    for (size_t index = 0; index < 16u; ++index) {
        bitmap[index] = 0;
    }
}

void shift_bitmap_left(uint64_t *bitmap, uint64_t shift) {
    if (shift >= GM_REPLAY_WINDOW_BITS) {
        clear_bitmap(bitmap);
        return;
    }

    const size_t word_shift = static_cast<size_t>(shift / 64u);
    const uint32_t bit_shift = static_cast<uint32_t>(shift % 64u);

    for (size_t reverse_index = 16u; reverse_index > 0u; --reverse_index) {
        const size_t index = reverse_index - 1u;
        uint64_t value = 0;
        if (index >= word_shift) {
            value = bitmap[index - word_shift] << bit_shift;
            if (bit_shift != 0u && index > word_shift) {
                value |= bitmap[index - word_shift - 1u] >> (64u - bit_shift);
            }
        }
        bitmap[index] = value;
    }
}
}

gm_status gm_media_encode_header(const gm_media_header *header, gm_mut_bytes output, size_t *written) {
    if (header == nullptr || written == nullptr || !has_writable_data(output)) {
        return GM_BAD_ARGUMENT;
    }
    *written = GM_MEDIA_HEADER_BYTES;
    if (!validate_media_header_fields(*header)) {
        return GM_BAD_MESSAGE;
    }
    if (output.size < GM_MEDIA_HEADER_BYTES) {
        return GM_BUFFER_TOO_SMALL;
    }
    if (output.data == nullptr) {
        return GM_BAD_ARGUMENT;
    }

    std::memset(output.data, 0, GM_MEDIA_HEADER_BYTES);
    output.data[0] = static_cast<uint8_t>('G');
    output.data[1] = static_cast<uint8_t>('M');
    output.data[2] = static_cast<uint8_t>('A');
    output.data[3] = static_cast<uint8_t>('1');
    output.data[4] = 1u;
    output.data[5] = static_cast<uint8_t>(header->kind);
    write_u16_be(output.data + 6u, 0u);
    std::memcpy(output.data + 8u, header->session_id, GM_SESSION_ID_BYTES);
    write_u32_be(output.data + 24u, header->stream_id);
    output.data[28] = static_cast<uint8_t>(header->direction);
    write_u32_be(output.data + 32u, header->key_epoch);
    write_u64_be(output.data + 36u, header->sequence);
    write_u64_be(output.data + 44u, header->media_timestamp);
    write_u32_be(output.data + 52u, header->payload_length);
    return GM_OK;
}

gm_status gm_media_decode_header(gm_bytes datagram, gm_media_header *out_header) {
    if (out_header == nullptr || out_header->struct_size < sizeof(gm_media_header) || !has_readable_data(datagram)) {
        return GM_BAD_ARGUMENT;
    }

    const size_t caller_size = out_header->struct_size;
    std::memset(out_header, 0, sizeof(gm_media_header));
    out_header->struct_size = caller_size;
    out_header->abi_version = GM_ABI_VERSION;

    if (datagram.size < GM_MEDIA_MIN_DATAGRAM_BYTES || datagram.size > GM_MEDIA_MAX_DATAGRAM_BYTES) {
        return GM_BAD_MESSAGE;
    }
    const uint8_t *data = datagram.data;
    if (data[0] != static_cast<uint8_t>('G') || data[1] != static_cast<uint8_t>('M') ||
        data[2] != static_cast<uint8_t>('A') || data[3] != static_cast<uint8_t>('1') || data[4] != 1u ||
        read_u16_be(data + 6u) != 0u || data[29] != 0u || data[30] != 0u || data[31] != 0u) {
        return GM_BAD_MESSAGE;
    }
    for (size_t index = 56u; index < 64u; ++index) {
        if (data[index] != 0u) {
            return GM_BAD_MESSAGE;
        }
    }

    out_header->kind = data[5];
    std::memcpy(out_header->session_id, data + 8u, GM_SESSION_ID_BYTES);
    out_header->stream_id = read_u32_be(data + 24u);
    out_header->direction = data[28];
    out_header->key_epoch = read_u32_be(data + 32u);
    out_header->sequence = read_u64_be(data + 36u);
    out_header->media_timestamp = read_u64_be(data + 44u);
    out_header->payload_length = read_u32_be(data + 52u);

    const size_t expected_size = GM_MEDIA_HEADER_BYTES + static_cast<size_t>(out_header->payload_length) + GM_MEDIA_TAG_BYTES;
    if (expected_size != datagram.size || !validate_media_header_fields(*out_header)) {
        return GM_BAD_MESSAGE;
    }

    return GM_OK;
}

gm_status gm_media_build_nonce(uint32_t key_epoch, uint64_t sequence, gm_mut_bytes output) {
    if (!has_writable_data(output)) {
        return GM_BAD_ARGUMENT;
    }
    if (key_epoch == 0u) {
        return GM_BAD_MESSAGE;
    }
    if (output.size < GM_MEDIA_NONCE_BYTES) {
        return GM_BUFFER_TOO_SMALL;
    }
    if (output.data == nullptr) {
        return GM_BAD_ARGUMENT;
    }

    write_u32_be(output.data, key_epoch);
    write_u64_be(output.data + 4u, sequence);
    return GM_OK;
}

gm_status gm_replay_window_init(gm_replay_window *window) {
    if (window == nullptr || window->struct_size < sizeof(gm_replay_window)) {
        return GM_BAD_ARGUMENT;
    }
    const size_t caller_size = window->struct_size;
    std::memset(window, 0, sizeof(gm_replay_window));
    window->struct_size = caller_size;
    window->abi_version = GM_ABI_VERSION;
    return GM_OK;
}

gm_status gm_replay_window_accept(gm_replay_window *window, uint64_t sequence, uint32_t *out_result) {
    if (window == nullptr || out_result == nullptr || window->struct_size < sizeof(gm_replay_window) ||
        window->abi_version != GM_ABI_VERSION) {
        return GM_BAD_ARGUMENT;
    }

    if (window->initialized == 0u) {
        clear_bitmap(window->bitmap);
        window->highest_sequence = sequence;
        window->initialized = 1u;
        set_bit(window->bitmap, 0u);
        *out_result = GM_REPLAY_ACCEPTED;
        return GM_OK;
    }

    if (sequence > window->highest_sequence) {
        shift_bitmap_left(window->bitmap, sequence - window->highest_sequence);
        window->highest_sequence = sequence;
        set_bit(window->bitmap, 0u);
        *out_result = GM_REPLAY_ACCEPTED;
        return GM_OK;
    }

    const uint64_t delta = window->highest_sequence - sequence;
    if (delta >= GM_REPLAY_WINDOW_BITS) {
        *out_result = GM_REPLAY_TOO_OLD;
        return GM_OK;
    }
    if (get_bit(window->bitmap, delta)) {
        *out_result = GM_REPLAY_DUPLICATE;
        return GM_OK;
    }

    set_bit(window->bitmap, delta);
    *out_result = GM_REPLAY_ACCEPTED;
    return GM_OK;
}

gm_status gm_epoch_window_init(gm_epoch_window *window, uint32_t initial_epoch) {
    if (window == nullptr || window->struct_size < sizeof(gm_epoch_window)) {
        return GM_BAD_ARGUMENT;
    }
    if (initial_epoch == 0u) {
        return GM_BAD_MESSAGE;
    }
    const size_t caller_size = window->struct_size;
    std::memset(window, 0, sizeof(gm_epoch_window));
    window->struct_size = caller_size;
    window->abi_version = GM_ABI_VERSION;
    window->current_epoch = initial_epoch;
    return GM_OK;
}

gm_status gm_epoch_window_begin_rekey(gm_epoch_window *window, uint32_t new_epoch, uint64_t now_ns) {
    if (window == nullptr || window->struct_size < sizeof(gm_epoch_window) || window->abi_version != GM_ABI_VERSION) {
        return GM_BAD_ARGUMENT;
    }
    if (new_epoch == 0u || window->current_epoch == 0u || new_epoch != window->current_epoch + 1u) {
        return GM_BAD_MESSAGE;
    }
    window->previous_epoch = window->current_epoch;
    window->current_epoch = new_epoch;
    window->has_previous_epoch = 1u;
    window->previous_epoch_expires_ns = now_ns > std::numeric_limits<uint64_t>::max() - kRekeyGraceNs
                                            ? std::numeric_limits<uint64_t>::max()
                                            : now_ns + kRekeyGraceNs;
    return GM_OK;
}

gm_status gm_epoch_window_accept(const gm_epoch_window *window, uint32_t key_epoch, uint64_t now_ns,
                                 uint32_t *out_acceptance) {
    if (window == nullptr || out_acceptance == nullptr || window->struct_size < sizeof(gm_epoch_window) ||
        window->abi_version != GM_ABI_VERSION || window->current_epoch == 0u) {
        return GM_BAD_ARGUMENT;
    }
    if (key_epoch == 0u) {
        return GM_BAD_MESSAGE;
    }
    if (key_epoch == window->current_epoch) {
        *out_acceptance = GM_EPOCH_CURRENT;
        return GM_OK;
    }
    if (window->has_previous_epoch != 0u && key_epoch == window->previous_epoch &&
        now_ns <= window->previous_epoch_expires_ns) {
        *out_acceptance = GM_EPOCH_PREVIOUS_GRACE;
        return GM_OK;
    }
    *out_acceptance = GM_EPOCH_REJECTED;
    return GM_OK;
}