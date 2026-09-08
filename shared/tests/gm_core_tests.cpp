#include <ghostmedia/gm_core.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

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

gm_bytes bytes_from_string(const std::string &text) {
    return gm_bytes{reinterpret_cast<const uint8_t *>(text.data()), text.size()};
}

void check_status(gm_status actual, gm_status expected, const char *message) {
    if (actual != expected) {
        std::cerr << "FAIL: " << message << " expected " << gm_status_string(expected)
                  << " got " << gm_status_string(actual) << '\n';
        ++failures;
    }
}

void test_version_and_framing() {
    gm_core_version version{sizeof(gm_core_version), 0, 0, nullptr};
    check_status(gm_get_version(&version), GM_OK, "version call succeeds");
    check(version.abi_version == GM_ABI_VERSION, "ABI version matches header");
    check(version.protocol_major == GM_PROTOCOL_MAJOR, "protocol major matches header");
    check(std::strcmp(version.spec_revision, "1.0-draft.1") == 0, "spec revision is draft 1");

    const gm_bytes json = bytes_from_cstr("{\"v\":1,\"id\":1,\"type\":\"ping\",\"token\":\"a\"}");
    std::array<uint8_t, 128> frame{};
    size_t written = 0;

    check_status(gm_control_validate_json_text(json), GM_OK, "valid JSON object is accepted");
    check_status(gm_control_encode_frame(json, gm_mut_bytes{frame.data(), frame.size()}, &written), GM_OK,
                 "control frame encodes");
    check(written == GM_CONTROL_FRAME_HEADER_BYTES + json.size, "encoded length includes header");
    check(frame[0] == 0 && frame[1] == 0 && frame[2] == 0 && frame[3] == json.size,
          "length prefix is big endian");

    gm_control_frame_info info{sizeof(gm_control_frame_info), 0, 0, 0, 0, {0}};
    check_status(gm_control_peek_frame(gm_bytes{frame.data(), written}, &info), GM_OK, "complete frame peeks");
    check(info.abi_version == GM_ABI_VERSION, "frame info ABI is filled");
    check(info.complete == 1, "complete frame is marked complete");
    check(info.payload_length == json.size, "payload length is reported");
    check(info.frame_size == written, "frame size is reported");

    gm_control_frame_info partial_info{sizeof(gm_control_frame_info), 0, 0, 0, 0, {0}};
    check_status(gm_control_peek_frame(gm_bytes{frame.data(), 3}, &partial_info), GM_NEED_MORE_DATA,
                 "partial header needs more data");
    check_status(gm_control_peek_frame(gm_bytes{frame.data(), written - 1}, &partial_info), GM_NEED_MORE_DATA,
                 "partial payload needs more data");

    std::array<uint8_t, 4> too_small{};
    size_t required = 0;
    check_status(gm_control_encode_frame(json, gm_mut_bytes{too_small.data(), too_small.size()}, &required),
                 GM_BUFFER_TOO_SMALL, "small output buffer reports size");
    check(required == written, "reported required size matches encoded size");
}

void test_control_json_limits() {
    const uint8_t invalid_utf8[] = {'{', '"', 0xc0u, 0xafu, '"', ':', '1', '}'};
    check_status(gm_control_validate_json_text(gm_bytes{invalid_utf8, sizeof(invalid_utf8)}), GM_BAD_MESSAGE,
                 "overlong UTF-8 is rejected");
    check_status(gm_control_validate_json_text(bytes_from_cstr("[]")), GM_BAD_MESSAGE,
                 "non-object JSON text is rejected");
    check_status(gm_control_validate_json_text(bytes_from_cstr("{\"v\":1,\"v\":1}")), GM_BAD_MESSAGE,
                 "duplicate object members are rejected");
    check_status(gm_control_validate_json_text(bytes_from_cstr("{\"v\":1.0}")), GM_BAD_MESSAGE,
                 "fractional numbers are rejected");
    check_status(gm_control_validate_json_text(bytes_from_cstr("{\"s\":\"\\uD800\"}")), GM_BAD_MESSAGE,
                 "unpaired UTF-16 surrogate escapes are rejected");

    std::string long_string = "{\"s\":\"";
    long_string.append(GM_CONTROL_MAX_STRING_BYTES + 1u, 'a');
    long_string.append("\"}");
    check_status(gm_control_validate_json_text(bytes_from_string(long_string)), GM_LIMIT_EXCEEDED,
                 "oversized strings are rejected");

    std::string nested = "{\"v\":";
    for (uint32_t index = 0; index < GM_CONTROL_MAX_DEPTH; ++index) {
        nested.push_back('[');
    }
    nested.push_back('1');
    for (uint32_t index = 0; index < GM_CONTROL_MAX_DEPTH; ++index) {
        nested.push_back(']');
    }
    nested.push_back('}');
    check_status(gm_control_validate_json_text(bytes_from_string(nested)), GM_LIMIT_EXCEEDED,
                 "excessive nesting is rejected");
}

void test_control_message_parsing() {
    gm_control_message_info message{sizeof(gm_control_message_info)};
    check_status(gm_control_parse_message(
                     bytes_from_cstr("{\"v\":1,\"id\":1,\"type\":\"session.hello\",\"role\":\"win-client\","
                                     "\"client_name\":\"Living Room Mac\",\"versions\":[2,1],\"udp_port\":49152}"),
                     &message),
                 GM_OK, "session.hello parses");
    check(message.kind == GM_CONTROL_REQUEST_SESSION_HELLO, "hello kind is reported");
    check(message.id == 1u, "hello id is reported");
    check(message.mutating == 1u, "hello is mutating");
    check(message.udp_port == 49152u, "hello UDP port is reported");
    check(message.versions_count == 2u && message.versions[0] == 2u && message.versions[1] == 1u,
          "hello versions are reported");
    check(std::strcmp(message.role, "win-client") == 0, "hello role is copied");
    check(std::strcmp(message.client_name, "Living Room Mac") == 0, "hello name is copied");

    check_status(gm_control_parse_message(
                     bytes_from_cstr("{\"v\":1,\"id\":1,\"type\":\"session.hello\",\"role\":\"mac-client\","
                                     "\"client_name\":\"x\",\"versions\":[1],\"udp_port\":1}"),
                     &message),
                 GM_BAD_MESSAGE, "old Mac client role is rejected");

    check_status(gm_control_parse_message(
                     bytes_from_cstr("{\"v\":1,\"id\":1,\"type\":\"session.hello\",\"role\":\"win-client\","
                                     "\"client_name\":\"x\",\"versions\":[1,2],\"udp_port\":1}"),
                     &message),
                 GM_BAD_MESSAGE, "ascending versions are rejected");
    check_status(gm_control_parse_message(bytes_from_cstr("{\"v\":2,\"id\":1,\"type\":\"ping\",\"token\":\"a\"}"),
                                          &message),
                 GM_UNSUPPORTED_VERSION, "unsupported control version is reported");
    check_status(gm_control_parse_message(bytes_from_cstr("{\"v\":1,\"id\":1,\"type\":\"ping\",\"token\":\"a\",\"x\":1}"),
                                          &message),
                 GM_BAD_MESSAGE, "closed request schema rejects unknown fields");

    check_status(gm_control_parse_message(bytes_from_cstr("{\"v\":1,\"id\":2,\"type\":\"transport.bind\","
                                                         "\"session_id\":\"00112233445566778899aabbccddeeff\",\"udp_port\":49152}"),
                                          &message),
                 GM_OK, "transport.bind parses");
    check(message.kind == GM_CONTROL_REQUEST_TRANSPORT_BIND, "transport bind kind is reported");
    check(std::strcmp(message.session_id, "00112233445566778899aabbccddeeff") == 0,
          "session id is copied");

    check_status(gm_control_parse_message(bytes_from_cstr("{\"v\":1,\"id\":3,\"type\":\"stream.open\","
                                                         "\"kind\":\"audio\",\"direction\":\"win_to_apple\","
                                                         "\"profile\":{\"codec\":\"pcm_s16le\",\"sample_rate_hz\":48000,"
                                                         "\"channels\":2,\"channel_layout\":\"stereo\",\"frames_per_packet\":240},"
                                                         "\"playout_target_ms\":30}"),
                                          &message),
                 GM_OK, "stream.open PCM parses");
    check(message.kind == GM_CONTROL_REQUEST_STREAM_OPEN, "stream open kind is reported");
    check(message.profile.codec == GM_AUDIO_CODEC_PCM_S16LE, "PCM codec is reported");
    check(message.profile.payload_bytes == GM_AUDIO_PCM_S16LE_PAYLOAD_BYTES, "PCM payload bytes are derived");

    check_status(gm_control_parse_message(bytes_from_cstr("{\"v\":1,\"id\":3,\"type\":\"stream.open\","
                                                         "\"kind\":\"audio\",\"direction\":\"win_to_mac\","
                                                         "\"profile\":{\"codec\":\"pcm_s16le\",\"sample_rate_hz\":48000,"
                                                         "\"channels\":2,\"channel_layout\":\"stereo\",\"frames_per_packet\":240},"
                                                         "\"playout_target_ms\":30}"),
                                          &message),
                 GM_BAD_MESSAGE, "old win_to_mac direction is rejected");

    check_status(gm_control_parse_message(bytes_from_cstr("{\"v\":1,\"id\":3,\"type\":\"stream.open\","
                                                         "\"kind\":\"audio\",\"direction\":\"win_to_apple\","
                                                         "\"profile\":{\"codec\":\"pcm_s16le\",\"sample_rate_hz\":48000,"
                                                         "\"channels\":2,\"channel_layout\":\"stereo\",\"frames_per_packet\":480},"
                                                         "\"playout_target_ms\":30}"),
                                          &message),
                 GM_BAD_MESSAGE, "wrong PCM packet duration is rejected");

    check_status(gm_control_parse_message(bytes_from_cstr("{\"v\":1,\"id\":4,\"type\":\"stream.start\","
                                                         "\"stream_id\":1,\"first_media_timestamp\":\"240\"}"),
                                          &message),
                 GM_OK, "stream.start parses with sender timestamp");
    check(message.kind == GM_CONTROL_REQUEST_STREAM_START && std::strcmp(message.first_media_timestamp, "240") == 0,
          "stream.start timestamp is copied");

    check_status(gm_control_parse_message(bytes_from_cstr("{\"v\":1,\"id\":4,\"type\":\"stream.start\","
                                                         "\"stream_id\":1}"),
                                          &message),
                 GM_BAD_MESSAGE, "stream.start without sender timestamp is rejected");

    check_status(gm_control_parse_message(bytes_from_cstr("{\"v\":1,\"id\":4,\"type\":\"stream.rekey\","
                                                         "\"stream_id\":1,\"key_epoch\":2}"),
                                          &message),
                 GM_OK, "stream.rekey parses");
    check(message.kind == GM_CONTROL_REQUEST_STREAM_REKEY && message.stream_id == 1u && message.key_epoch == 2u,
          "stream rekey fields are reported");

    check_status(gm_control_parse_message(bytes_from_cstr("{\"v\":1,\"id\":5,\"type\":\"session.close\","
                                                         "\"reason\":\"USER_REQUEST\"}"),
                                          &message),
                 GM_OK, "session.close parses");
    check(message.has_reason == 1u && std::strcmp(message.reason, "USER_REQUEST") == 0,
          "session close reason is copied");

    check_status(gm_control_parse_message(bytes_from_cstr("{\"v\":1,\"id\":7,\"type\":\"error\","
                                                         "\"error\":{\"code\":\"RESOURCE_BUSY\",\"message\":\"busy\","
                                                         "\"retryable\":true}}"),
                                          &message),
                 GM_OK, "error response schema parses");
    check(message.kind == GM_CONTROL_RESPONSE_ERROR, "error response kind is reported");

    check_status(gm_control_parse_message(bytes_from_cstr("{\"v\":1,\"id\":6,\"type\":\"result\","
                                                         "\"result\":{\"version\":1,\"role\":\"apple-output-server\","
                                                         "\"server_id\":\"01234567-89ab-cdef-0123-456789abcdef\","
                                                         "\"session_id\":\"00112233445566778899aabbccddeeff\","
                                                         "\"boot_id\":\"11111111-2222-3333-4444-555555555555\","
                                                         "\"udp_port\":49152,"
                                                         "\"capabilities\":{\"audio_send\":false,\"audio_receive\":true,"
                                                         "\"microphone\":false,\"camera\":false,\"audio_profiles\":["
                                                         "{\"codec\":\"pcm_s16le\",\"sample_rate_hz\":48000,\"channels\":2,"
                                                         "\"channel_layout\":\"stereo\",\"frames_per_packet\":240}]},"
                                                         "\"limits\":{\"max_audio_subscribers\":1,\"playout_target_ms_min\":15,"
                                                         "\"playout_target_ms_max\":120}}}"),
                                          &message),
                 GM_OK, "Apple output server hello result parses");
    check(message.kind == GM_CONTROL_RESPONSE_RESULT && message.udp_port == 49152u,
          "hello result UDP port is reported");
    check(std::strcmp(message.role, "apple-output-server") == 0 &&
              std::strcmp(message.server_id, "01234567-89ab-cdef-0123-456789abcdef") == 0 &&
              std::strcmp(message.session_id, "00112233445566778899aabbccddeeff") == 0 &&
              std::strcmp(message.boot_id, "11111111-2222-3333-4444-555555555555") == 0,
          "hello result identifiers are copied");

    check_status(gm_control_parse_message(bytes_from_cstr("{\"v\":1,\"id\":6,\"type\":\"result\","
                                                         "\"result\":{\"udp_port\":51838,\"path_state\":\"bound\"}}"),
                                          &message),
                 GM_OK, "transport.bind result schema parses");
    check(message.udp_port == 51838u && std::strcmp(message.path_state, "bound") == 0,
          "transport.bind result fields are copied");

    check_status(gm_control_parse_message(bytes_from_cstr("{\"v\":1,\"id\":6,\"type\":\"result\","
                                                         "\"result\":{\"udp_port\":51838,\"path_state\":\"probing\"}}"),
                                          &message),
                 GM_BAD_MESSAGE, "transport.bind result rejects probing path state");

    check_status(gm_control_parse_message(bytes_from_cstr("{\"v\":1,\"id\":7,\"type\":\"result\","
                                                         "\"result\":{\"stream_id\":1,\"key_epoch\":1,"
                                                         "\"profile\":{\"codec\":\"pcm_s16le\",\"sample_rate_hz\":48000,"
                                                         "\"channels\":2,\"channel_layout\":\"stereo\",\"frames_per_packet\":240},"
                                                         "\"packet_interval_us\":5000,\"path_state\":\"probing\"}}"),
                                          &message),
                 GM_OK, "stream.open result schema parses");
    check(message.kind == GM_CONTROL_RESPONSE_RESULT && message.stream_id == 1u && message.key_epoch == 1u,
          "stream.open result fields are reported");

    check_status(gm_control_parse_message(bytes_from_cstr("{\"v\":1,\"id\":8,\"type\":\"result\","
                                                         "\"result\":{\"state\":\"started\"}}"),
                                          &message),
                 GM_OK, "stream.start result schema parses");
    check(std::strcmp(message.state, "started") == 0, "stream.start result state is copied");

    check_status(gm_control_parse_message(bytes_from_cstr("{\"v\":1,\"id\":9,\"type\":\"result\","
                                                         "\"result\":{\"output_state\":\"available\","
                                                         "\"session_stream_state\":\"started\",\"transport_state\":\"bound\","
                                                         "\"feedback_age_ms\":500}}"),
                                          &message),
                 GM_OK, "status.get result schema parses");
    check(std::strcmp(message.output_state, "available") == 0 &&
              std::strcmp(message.session_stream_state, "started") == 0 &&
              std::strcmp(message.transport_state, "bound") == 0,
          "status result state fields are copied");

    check_status(gm_control_parse_message(bytes_from_cstr("{\"v\":1,\"id\":9,\"type\":\"result\","
                                                         "\"result\":{\"endpoint_state\":\"available\","
                                                         "\"session_stream_state\":\"started\",\"transport_state\":\"bound\","
                                                         "\"feedback_age_ms\":500}}"),
                                          &message),
                 GM_BAD_MESSAGE, "old status endpoint_state result field is rejected");

    check_status(gm_control_parse_message(bytes_from_cstr("{\"v\":1,\"id\":7,\"type\":\"result\","
                                                         "\"result\":{\"stream_id\":1,\"key_epoch\":1,"
                                                         "\"profile\":{\"codec\":\"pcm_s16le\",\"sample_rate_hz\":48000,"
                                                         "\"channels\":2,\"channel_layout\":\"stereo\",\"frames_per_packet\":240},"
                                                         "\"packet_interval_us\":5000,\"source_media_timestamp\":\"0\","
                                                         "\"path_state\":\"probing\"}}"),
                                          &message),
                 GM_BAD_MESSAGE, "old stream.open source timestamp result is rejected");

    check_status(gm_control_parse_message(bytes_from_cstr("{\"v\":1,\"type\":\"event.output.state\","
                                                         "\"state\":\"available\",\"reason\":\"ROUTE_READY\"}"),
                                          &message),
                 GM_OK, "output state event parses");
    check(message.kind == GM_CONTROL_EVENT_OUTPUT_STATE && message.has_reason == 1u &&
              std::strcmp(message.state, "available") == 0,
          "output state event fields are reported");

    check_status(gm_control_parse_message(bytes_from_cstr("{\"v\":1,\"type\":\"event.path.validated\","
                                                         "\"stream_id\":3,\"key_epoch\":1}"),
                                          &message),
                 GM_BAD_MESSAGE, "old path validation control event is rejected");

    check_status(gm_control_parse_message(
                     bytes_from_cstr("{\"v\":1,\"type\":\"event.session.expiring\","
                                     "\"reason\":\"SERVER_RESTART\",\"deadline_monotonic_ns\":\"123456789\"}"),
                     &message),
                 GM_OK, "session expiring event parses");
    check(message.kind == GM_CONTROL_EVENT_SESSION_EXPIRING &&
              std::strcmp(message.monotonic_ns, "123456789") == 0,
          "session expiring deadline is reported");
}

void test_media_header_and_replay() {
    gm_media_header header{};
    header.struct_size = sizeof(gm_media_header);
    header.abi_version = GM_ABI_VERSION;
    header.kind = GM_MEDIA_KIND_PATH_CHALLENGE;
    for (uint8_t index = 0; index < GM_SESSION_ID_BYTES; ++index) {
        header.session_id[index] = index;
    }
    header.stream_id = 7u;
    header.direction = GM_MEDIA_DIRECTION_WIN_TO_APPLE;
    header.key_epoch = 1u;
    header.sequence = 0x0102030405060708ull;
    header.media_timestamp = 0u;
    header.payload_length = 12u;

    std::array<uint8_t, GM_MEDIA_HEADER_BYTES> encoded{};
    size_t written = 0;
    check_status(gm_media_encode_header(&header, gm_mut_bytes{encoded.data(), encoded.size()}, &written), GM_OK,
                 "media header encodes");
    check(written == GM_MEDIA_HEADER_BYTES, "media header write size is reported");
    check(encoded[0] == 'G' && encoded[1] == 'M' && encoded[2] == 'A' && encoded[3] == '1',
          "media magic is encoded");
    check(encoded[4] == 1u && encoded[5] == GM_MEDIA_KIND_PATH_CHALLENGE, "media version and kind encode");
    check(encoded[36] == 0x01u && encoded[43] == 0x08u, "sequence is big endian");

    std::vector<uint8_t> datagram(GM_MEDIA_HEADER_BYTES + header.payload_length + GM_MEDIA_TAG_BYTES);
    std::memcpy(datagram.data(), encoded.data(), encoded.size());
    gm_media_header decoded{sizeof(gm_media_header)};
    check_status(gm_media_decode_header(gm_bytes{datagram.data(), datagram.size()}, &decoded), GM_OK,
                 "media header decodes from datagram");
    check(decoded.kind == header.kind && decoded.stream_id == header.stream_id && decoded.sequence == header.sequence,
          "decoded media fields match");

    datagram[29] = 1u;
    check_status(gm_media_decode_header(gm_bytes{datagram.data(), datagram.size()}, &decoded), GM_BAD_MESSAGE,
                 "reserved media bytes are rejected");

    std::array<uint8_t, GM_MEDIA_NONCE_BYTES> nonce{};
    check_status(gm_media_build_nonce(2u, 0x0102030405060708ull, gm_mut_bytes{nonce.data(), nonce.size()}), GM_OK,
                 "media nonce builds");
    check(nonce[0] == 0u && nonce[1] == 0u && nonce[2] == 0u && nonce[3] == 2u && nonce[4] == 1u &&
              nonce[11] == 8u,
          "media nonce is epoch plus sequence");

    gm_replay_window window{sizeof(gm_replay_window)};
    uint32_t replay_result = 0;
    check_status(gm_replay_window_init(&window), GM_OK, "replay window initializes");
    check_status(gm_replay_window_accept(&window, 2000u, &replay_result), GM_OK, "first replay sequence checks");
    check(replay_result == GM_REPLAY_ACCEPTED, "first replay sequence is accepted");
    check_status(gm_replay_window_accept(&window, 2000u, &replay_result), GM_OK, "duplicate replay sequence checks");
    check(replay_result == GM_REPLAY_DUPLICATE, "duplicate replay sequence is reported");
    check_status(gm_replay_window_accept(&window, 977u, &replay_result), GM_OK, "lookbehind edge checks");
    check(replay_result == GM_REPLAY_ACCEPTED, "sequence 1023 behind is accepted once");
    check_status(gm_replay_window_accept(&window, 976u, &replay_result), GM_OK, "old replay sequence checks");
    check(replay_result == GM_REPLAY_TOO_OLD, "sequence 1024 behind is too old");
}
}

int main() {
    test_version_and_framing();
    test_control_json_limits();
    test_control_message_parsing();
    test_media_header_and_replay();

    if (failures != 0) {
        std::cerr << failures << " failure(s)\n";
        return 1;
    }

    return 0;
}
