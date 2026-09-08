#include <ghostmedia/gm_core.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <iostream>

namespace {
int failures = 0;

void check(bool condition, const char *message) {
    if (!condition) {
        std::cerr << "FAIL: " << message << '\n';
        ++failures;
    }
}

gm_bytes bytes_from_cstr(const char *text) {
    return gm_bytes{reinterpret_cast<const uint8_t *>(text), std::strlen(text)};
}
}

int main() {
    gm_core_version version{sizeof(gm_core_version), 0, 0, nullptr};
    check(gm_get_version(&version) == GM_OK, "version call succeeds");
    check(version.abi_version == GM_ABI_VERSION, "ABI version matches header");
    check(version.protocol_major == GM_PROTOCOL_MAJOR, "protocol major matches header");
    check(std::strcmp(version.spec_revision, "1.0-draft.1") == 0, "spec revision is draft 1");

    const gm_bytes json = bytes_from_cstr("{\"v\":1,\"id\":1,\"type\":\"ping\",\"token\":\"a\"}");
    std::array<uint8_t, 128> frame{};
    size_t written = 0;

    check(gm_control_validate_json_text(json) == GM_OK, "valid JSON object shape is accepted");
    check(gm_control_encode_frame(json, gm_mut_bytes{frame.data(), frame.size()}, &written) == GM_OK,
          "control frame encodes");
    check(written == GM_CONTROL_FRAME_HEADER_BYTES + json.size, "encoded length includes header");
    check(frame[0] == 0 && frame[1] == 0 && frame[2] == 0 && frame[3] == json.size,
          "length prefix is big endian");

    gm_control_frame_info info{sizeof(gm_control_frame_info), 0, 0, 0, {0}};
    check(gm_control_peek_frame(gm_bytes{frame.data(), written}, &info) == GM_OK,
          "complete frame peeks");
    check(info.complete == 1, "complete frame is marked complete");
    check(info.payload_length == json.size, "payload length is reported");
    check(info.frame_size == written, "frame size is reported");

    gm_control_frame_info partial_info{sizeof(gm_control_frame_info), 0, 0, 0, {0}};
    check(gm_control_peek_frame(gm_bytes{frame.data(), 3}, &partial_info) == GM_NEED_MORE_DATA,
          "partial header needs more data");
    check(gm_control_peek_frame(gm_bytes{frame.data(), written - 1}, &partial_info) == GM_NEED_MORE_DATA,
          "partial payload needs more data");

    std::array<uint8_t, 4> too_small{};
    size_t required = 0;
    check(gm_control_encode_frame(json, gm_mut_bytes{too_small.data(), too_small.size()}, &required) ==
              GM_BUFFER_TOO_SMALL,
          "small output buffer reports size");
    check(required == written, "reported required size matches encoded size");

    const uint8_t invalid_utf8[] = {'{', '"', 0xc0u, 0xafu, '"', ':', '1', '}'};
    check(gm_control_validate_json_text(gm_bytes{invalid_utf8, sizeof(invalid_utf8)}) == GM_BAD_MESSAGE,
          "overlong UTF-8 is rejected");
    check(gm_control_validate_json_text(bytes_from_cstr("[]")) == GM_BAD_MESSAGE,
          "non-object JSON text is rejected");

    if (failures != 0) {
        std::cerr << failures << " failure(s)\n";
        return 1;
    }

    return 0;
}
