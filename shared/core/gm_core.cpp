#include <ghostmedia/gm_core.h>

#include <cstddef>
#include <cstdint>
#include <cstring>

namespace {
constexpr const char *kSpecRevision = "1.0-draft.1";

bool has_readable_data(gm_bytes bytes) {
    return bytes.size == 0 || bytes.data != nullptr;
}

bool has_writable_data(gm_mut_bytes bytes) {
    return bytes.size == 0 || bytes.data != nullptr;
}

uint32_t read_u32_be(const uint8_t *data) {
    return (static_cast<uint32_t>(data[0]) << 24) |
           (static_cast<uint32_t>(data[1]) << 16) |
           (static_cast<uint32_t>(data[2]) << 8) |
           static_cast<uint32_t>(data[3]);
}

void write_u32_be(uint8_t *data, uint32_t value) {
    data[0] = static_cast<uint8_t>((value >> 24) & 0xffu);
    data[1] = static_cast<uint8_t>((value >> 16) & 0xffu);
    data[2] = static_cast<uint8_t>((value >> 8) & 0xffu);
    data[3] = static_cast<uint8_t>(value & 0xffu);
}

bool is_json_whitespace(uint8_t value) {
    return value == 0x20u || value == 0x09u || value == 0x0au || value == 0x0du;
}

bool is_valid_utf8(gm_bytes bytes) {
    size_t index = 0;
    while (index < bytes.size) {
        const uint8_t first = bytes.data[index];
        if (first <= 0x7fu) {
            ++index;
            continue;
        }

        if (first >= 0xc2u && first <= 0xdfu) {
            if (index + 1 >= bytes.size) {
                return false;
            }
            const uint8_t second = bytes.data[index + 1];
            if ((second & 0xc0u) != 0x80u) {
                return false;
            }
            index += 2;
            continue;
        }

        if (first >= 0xe0u && first <= 0xefu) {
            if (index + 2 >= bytes.size) {
                return false;
            }
            const uint8_t second = bytes.data[index + 1];
            const uint8_t third = bytes.data[index + 2];
            if ((second & 0xc0u) != 0x80u || (third & 0xc0u) != 0x80u) {
                return false;
            }
            if (first == 0xe0u && second < 0xa0u) {
                return false;
            }
            if (first == 0xedu && second >= 0xa0u) {
                return false;
            }
            index += 3;
            continue;
        }

        if (first >= 0xf0u && first <= 0xf4u) {
            if (index + 3 >= bytes.size) {
                return false;
            }
            const uint8_t second = bytes.data[index + 1];
            const uint8_t third = bytes.data[index + 2];
            const uint8_t fourth = bytes.data[index + 3];
            if ((second & 0xc0u) != 0x80u || (third & 0xc0u) != 0x80u ||
                (fourth & 0xc0u) != 0x80u) {
                return false;
            }
            if (first == 0xf0u && second < 0x90u) {
                return false;
            }
            if (first == 0xf4u && second > 0x8fu) {
                return false;
            }
            index += 4;
            continue;
        }

        return false;
    }

    return true;
}

bool looks_like_json_object(gm_bytes bytes) {
    size_t begin = 0;
    size_t end = bytes.size;

    while (begin < end && is_json_whitespace(bytes.data[begin])) {
        ++begin;
    }
    while (end > begin && is_json_whitespace(bytes.data[end - 1])) {
        --end;
    }

    return end >= begin + 2 && bytes.data[begin] == static_cast<uint8_t>('{') &&
           bytes.data[end - 1] == static_cast<uint8_t>('}');
}
}

const char *gm_status_string(gm_status status) {
    switch (status) {
    case GM_OK:
        return "GM_OK";
    case GM_BAD_ARGUMENT:
        return "GM_BAD_ARGUMENT";
    case GM_BAD_MESSAGE:
        return "GM_BAD_MESSAGE";
    case GM_STATE_CONFLICT:
        return "GM_STATE_CONFLICT";
    case GM_LIMIT_EXCEEDED:
        return "GM_LIMIT_EXCEEDED";
    case GM_BUFFER_TOO_SMALL:
        return "GM_BUFFER_TOO_SMALL";
    case GM_UNAUTHORIZED:
        return "GM_UNAUTHORIZED";
    case GM_NEED_MORE_DATA:
        return "GM_NEED_MORE_DATA";
    default:
        return "GM_UNKNOWN_STATUS";
    }
}

gm_status gm_get_version(gm_core_version *out_version) {
    if (out_version == nullptr || out_version->struct_size < sizeof(gm_core_version)) {
        return GM_BAD_ARGUMENT;
    }

    const size_t caller_size = out_version->struct_size;
    std::memset(out_version, 0, sizeof(gm_core_version));
    out_version->struct_size = caller_size;
    out_version->abi_version = GM_ABI_VERSION;
    out_version->protocol_major = GM_PROTOCOL_MAJOR;
    out_version->spec_revision = kSpecRevision;
    return GM_OK;
}

gm_status gm_control_validate_json_text(gm_bytes json_text) {
    if (!has_readable_data(json_text)) {
        return GM_BAD_ARGUMENT;
    }
    if (json_text.size < GM_CONTROL_FRAME_MIN_PAYLOAD_BYTES ||
        json_text.size > GM_CONTROL_FRAME_MAX_PAYLOAD_BYTES) {
        return GM_BAD_MESSAGE;
    }
    if (!is_valid_utf8(json_text) || !looks_like_json_object(json_text)) {
        return GM_BAD_MESSAGE;
    }

    return GM_OK;
}

gm_status gm_control_encode_frame(gm_bytes json_text, gm_mut_bytes output, size_t *written) {
    if (written == nullptr || !has_writable_data(output)) {
        return GM_BAD_ARGUMENT;
    }

    const gm_status validation = gm_control_validate_json_text(json_text);
    if (validation != GM_OK) {
        return validation;
    }

    const size_t required = GM_CONTROL_FRAME_HEADER_BYTES + json_text.size;
    *written = required;
    if (output.size < required) {
        return GM_BUFFER_TOO_SMALL;
    }
    if (output.data == nullptr) {
        return GM_BAD_ARGUMENT;
    }

    write_u32_be(output.data, static_cast<uint32_t>(json_text.size));
    std::memcpy(output.data + GM_CONTROL_FRAME_HEADER_BYTES, json_text.data, json_text.size);
    return GM_OK;
}

gm_status gm_control_peek_frame(gm_bytes input, gm_control_frame_info *out_info) {
    if (out_info == nullptr || out_info->struct_size < sizeof(gm_control_frame_info) ||
        !has_readable_data(input)) {
        return GM_BAD_ARGUMENT;
    }

    const size_t caller_size = out_info->struct_size;
    std::memset(out_info, 0, sizeof(gm_control_frame_info));
    out_info->struct_size = caller_size;

    if (input.size < GM_CONTROL_FRAME_HEADER_BYTES) {
        return GM_NEED_MORE_DATA;
    }

    const uint32_t payload_length = read_u32_be(input.data);
    if (payload_length < GM_CONTROL_FRAME_MIN_PAYLOAD_BYTES ||
        payload_length > GM_CONTROL_FRAME_MAX_PAYLOAD_BYTES) {
        return GM_BAD_MESSAGE;
    }

    const size_t frame_size = GM_CONTROL_FRAME_HEADER_BYTES + static_cast<size_t>(payload_length);
    out_info->payload_length = payload_length;
    out_info->frame_size = frame_size;

    if (input.size < frame_size) {
        return GM_NEED_MORE_DATA;
    }

    out_info->complete = 1;
    return GM_OK;
}
