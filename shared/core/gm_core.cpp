#include <ghostmedia/gm_core.h>

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
    case GM_UNSUPPORTED_VERSION:
        return "GM_UNSUPPORTED_VERSION";
    case GM_INTERNAL:
        return "GM_INTERNAL";
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
    out_info->abi_version = GM_ABI_VERSION;

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
