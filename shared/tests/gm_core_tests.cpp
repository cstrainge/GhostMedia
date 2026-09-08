#include <ghostmedia/gm_core.h>

#include <array>
#include <chrono>
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

gm_bytes bytes_from_cstr(const char *text) {
    return gm_bytes{reinterpret_cast<const uint8_t *>(text), std::strlen(text)};
}

gm_bytes bytes_from_string(const std::string &text) {
    return gm_bytes{reinterpret_cast<const uint8_t *>(text.data()), text.size()};
}

void set_c_string(char *destination, size_t destination_size, std::string_view source) {
    std::memset(destination, 0, destination_size);
    const size_t copy_size = source.size() < destination_size - 1u ? source.size() : destination_size - 1u;
    std::memcpy(destination, source.data(), copy_size);
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

    gm_control_session_config test_session_config() {
        gm_control_session_config config{};
        config.struct_size = sizeof(config);
        config.abi_version = GM_ABI_VERSION;
        config.role = GM_CONTROL_SESSION_ROLE_APPLE_OUTPUT_SERVER;
        config.apple_udp_port = 51838u;
        config.stream_id = 1u;
        config.key_epoch = 1u;
        config.max_audio_subscribers = 1u;
        config.playout_target_ms_min = 15u;
        config.playout_target_ms_max = 120u;
        config.output_available = 1u;
        set_c_string(config.server_id, sizeof(config.server_id), "01234567-89ab-cdef-0123-456789abcdef");
        set_c_string(config.boot_id, sizeof(config.boot_id), "11111111-2222-3333-4444-555555555555");
        set_c_string(config.session_id, sizeof(config.session_id), "00112233445566778899aabbccddeeff");
        return config;
    }

    gm_status ingest(gm_control_session &session, const char *json, uint64_t now_ns, gm_control_action &action) {
        action.struct_size = sizeof(action);
        return gm_control_session_ingest(&session, bytes_from_cstr(json), now_ns, &action);
    }

    void test_control_session_state_machine() {
        gm_control_session_config config = test_session_config();
        gm_control_session session{sizeof(gm_control_session)};
        gm_control_action action{sizeof(gm_control_action)};

        check_status(gm_control_session_init(&config, &session), GM_OK, "control session initializes");
        check(session.state == GM_CONTROL_SESSION_STATE_TLS_READY, "session starts after TLS readiness");

        check_status(ingest(session,
                    "{\"v\":1,\"id\":1,\"type\":\"session.hello\",\"role\":\"win-client\","
                    "\"client_name\":\"state test\",\"versions\":[1],\"udp_port\":49152}",
                    1000u, action),
                 GM_OK, "hello advances state machine");
        check(session.state == GM_CONTROL_SESSION_STATE_HELLO, "hello state is recorded");
        check(action.kind == GM_CONTROL_ACTION_SEND_SESSION_HELLO_RESULT && action.response_id == 1u,
            "hello emits a typed result action");
        check(std::strcmp(action.server_id, config.server_id) == 0 && std::strcmp(action.session_id, config.session_id) == 0,
            "hello action carries configured identifiers");

        check_status(ingest(session,
                    "{\"v\":1,\"id\":2,\"type\":\"transport.bind\","
                    "\"session_id\":\"00112233445566778899aabbccddeeff\",\"udp_port\":49152}",
                    2000u, action),
                 GM_OK, "bind after hello is accepted");
        check(session.state == GM_CONTROL_SESSION_STATE_BOUND, "bind advances to bound");
        check(action.kind == GM_CONTROL_ACTION_SEND_TRANSPORT_BIND_RESULT && std::strcmp(action.path_state, "bound") == 0,
            "bind emits bound path state");

        check_status(ingest(session,
                    "{\"v\":1,\"id\":3,\"type\":\"stream.open\",\"kind\":\"audio\","
                    "\"direction\":\"win_to_apple\",\"profile\":{\"codec\":\"pcm_s16le\","
                    "\"sample_rate_hz\":48000,\"channels\":2,\"channel_layout\":\"stereo\","
                    "\"frames_per_packet\":240},\"playout_target_ms\":30}",
                    3000u, action),
                 GM_OK, "stream.open after bind is accepted");
        check(session.state == GM_CONTROL_SESSION_STATE_STREAM_OPEN && session.stream_id == 1u,
            "stream.open reserves stream");
        check(action.kind == GM_CONTROL_ACTION_SEND_STREAM_OPEN_RESULT && std::strcmp(action.path_state, "probing") == 0,
            "stream.open emits probing state");

        check_status(ingest(session,
                    "{\"v\":1,\"id\":4,\"type\":\"stream.open\",\"kind\":\"audio\","
                    "\"direction\":\"win_to_apple\",\"profile\":{\"codec\":\"pcm_s16le\","
                    "\"sample_rate_hz\":48000,\"channels\":2,\"channel_layout\":\"stereo\","
                    "\"frames_per_packet\":240},\"playout_target_ms\":30}",
                    4000u, action),
                 GM_OK, "duplicate equivalent stream.open is idempotent");
        check(session.state == GM_CONTROL_SESSION_STATE_STREAM_OPEN && action.stream_id == 1u,
            "duplicate stream.open returns same stream");

        check_status(ingest(session,
                    "{\"v\":1,\"id\":5,\"type\":\"stream.open\",\"kind\":\"audio\","
                    "\"direction\":\"win_to_apple\",\"profile\":{\"codec\":\"pcm_s16le\","
                    "\"sample_rate_hz\":48000,\"channels\":2,\"channel_layout\":\"stereo\","
                    "\"frames_per_packet\":240},\"playout_target_ms\":60}",
                    5000u, action),
                 GM_STATE_CONFLICT, "non-equivalent duplicate stream.open conflicts");
        check(session.state == GM_CONTROL_SESSION_STATE_STREAM_OPEN && action.kind == GM_CONTROL_ACTION_SEND_ERROR_RESULT,
            "stream.open conflict does not close the session");

        check_status(ingest(session,
                    "{\"v\":1,\"id\":6,\"type\":\"stream.start\",\"stream_id\":1,"
                    "\"first_media_timestamp\":\"240\"}",
                    6000u, action),
                 GM_STATE_CONFLICT, "stream.start before path validation conflicts");
        check(session.state == GM_CONTROL_SESSION_STATE_STREAM_OPEN, "unvalidated start leaves stream open");

        action.struct_size = sizeof(action);
        check_status(gm_control_session_mark_path_validated(&session, 1u, 1u, &action), GM_OK,
                 "path validation callback is accepted");
        check(session.path_validated == 1u && action.kind == GM_CONTROL_ACTION_PATH_VALIDATED,
            "path validation emits action");

        check_status(ingest(session,
                    "{\"v\":1,\"id\":7,\"type\":\"stream.start\",\"stream_id\":1,"
                    "\"first_media_timestamp\":\"240\"}",
                    7000u, action),
                 GM_OK, "stream.start after path validation succeeds");
        check(session.state == GM_CONTROL_SESSION_STATE_STREAMING && std::strcmp(action.state, "started") == 0,
            "stream.start advances to streaming");

        check_status(ingest(session,
                    "{\"v\":1,\"id\":8,\"type\":\"stream.start\",\"stream_id\":1,"
                    "\"first_media_timestamp\":\"240\"}",
                    8000u, action),
                 GM_OK, "duplicate stream.start with same timestamp is idempotent");

        check_status(ingest(session,
                    "{\"v\":1,\"id\":9,\"type\":\"stream.start\",\"stream_id\":1,"
                    "\"first_media_timestamp\":\"480\"}",
                    9000u, action),
                 GM_STATE_CONFLICT, "started stream rejects different duplicate timestamp");

        check_status(ingest(session,
                    "{\"v\":1,\"id\":10,\"type\":\"stream.rekey\",\"stream_id\":1,"
                    "\"key_epoch\":2}",
                    10000u, action),
                 GM_OK, "stream.rekey accepts exact next epoch");
        check(session.key_epoch == 2u && session.path_validated == 0u && action.kind == GM_CONTROL_ACTION_SEND_STREAM_REKEY_RESULT,
            "rekey updates epoch and resets path validation");

        check_status(ingest(session,
                    "{\"v\":1,\"id\":11,\"type\":\"stream.rekey\",\"stream_id\":1,"
                    "\"key_epoch\":2}",
                    11000u, action),
                 GM_OK, "duplicate stream.rekey returns committed epoch");

        action.struct_size = sizeof(action);
        check_status(gm_control_session_mark_path_validated(&session, 1u, 2u, &action), GM_OK,
                 "path validation accepts rekey epoch");

        check_status(ingest(session, "{\"v\":1,\"id\":12,\"type\":\"status.get\"}", 12000u, action),
                 GM_OK, "status.get is accepted after hello");
        check(action.kind == GM_CONTROL_ACTION_SEND_STATUS_RESULT && std::strcmp(action.output_state, "available") == 0 &&
              std::strcmp(action.session_stream_state, "started") == 0,
            "status action carries typed session state");

        check_status(ingest(session, "{\"v\":1,\"id\":13,\"type\":\"ping\",\"token\":\"abc\"}", 12345u, action),
                 GM_OK, "ping is accepted after hello");
        check(action.kind == GM_CONTROL_ACTION_SEND_PING_RESULT && std::strcmp(action.token, "abc") == 0 &&
              std::strcmp(action.monotonic_ns, "12345") == 0,
            "ping action echoes token and monotonic time");

        check_status(ingest(session, "{\"v\":1,\"id\":14,\"type\":\"stream.stop\",\"stream_id\":1}", 14000u, action),
                 GM_OK, "stream.stop is accepted while streaming");
        check(session.state == GM_CONTROL_SESSION_STATE_STREAM_OPEN && std::strcmp(action.state, "stopped") == 0,
            "stream.stop leaves stream open and silent");

        check_status(ingest(session,
                    "{\"v\":1,\"id\":15,\"type\":\"stream.start\",\"stream_id\":1,"
                    "\"first_media_timestamp\":\"480\"}",
                    15000u, action),
                 GM_OK, "stream.start after stop restarts stream");

        check_status(ingest(session, "{\"v\":1,\"id\":16,\"type\":\"stream.close\",\"stream_id\":1}", 16000u, action),
                 GM_OK, "stream.close is accepted");
        check(session.state == GM_CONTROL_SESSION_STATE_BOUND && action.stream_id == 1u && std::strcmp(action.state, "closed") == 0,
            "stream.close releases ownership");

        check_status(ingest(session, "{\"v\":1,\"id\":17,\"type\":\"stream.close\",\"stream_id\":1}", 17000u, action),
                 GM_OK, "duplicate stream.close is idempotent while session is alive");

            check_status(ingest(session,
                        "{\"v\":1,\"id\":18,\"type\":\"stream.open\",\"kind\":\"audio\","
                        "\"direction\":\"win_to_apple\",\"profile\":{\"codec\":\"pcm_s16le\","
                        "\"sample_rate_hz\":48000,\"channels\":2,\"channel_layout\":\"stereo\","
                        "\"frames_per_packet\":240},\"playout_target_ms\":30}",
                        18000u, action),
                     GM_OK, "stream.open after close allocates a new stream");
            check(session.state == GM_CONTROL_SESSION_STATE_STREAM_OPEN && action.stream_id == 2u,
                "reopened stream receives the next stream ID");

            check_status(ingest(session, "{\"v\":1,\"id\":19,\"type\":\"session.close\",\"reason\":\"USER_REQUEST\"}", 19000u, action),
                 GM_OK, "session.close closes the session");
            check(session.state == GM_CONTROL_SESSION_STATE_CLOSED && session.stream_id == 0u && action.terminal == 1u,
                "session.close emits terminal action and clears stream state");

        gm_control_metrics metrics{sizeof(gm_control_metrics)};
        check_status(gm_control_session_get_metrics(&session, &metrics), GM_OK, "control metrics are exposed");
        check(metrics.valid_requests == 16u && metrics.rejected_requests == 3u && metrics.state_conflicts == 3u,
            "metrics count valid requests and state conflicts");
        check(metrics.streams_started == 2u && metrics.streams_stopped == 1u && metrics.streams_closed == 2u &&
              metrics.rekeys_committed == 1u,
            "metrics count stream lifecycle changes");

        gm_control_session duplicate_session{sizeof(gm_control_session)};
        check_status(gm_control_session_init(&config, &duplicate_session), GM_OK, "duplicate ID session initializes");
        check_status(ingest(duplicate_session,
                    "{\"v\":1,\"id\":1,\"type\":\"session.hello\",\"role\":\"win-client\","
                    "\"client_name\":\"state test\",\"versions\":[1],\"udp_port\":49152}",
                    1000u, action),
                 GM_OK, "duplicate ID fixture hello succeeds");
        check_status(ingest(duplicate_session, "{\"v\":1,\"id\":1,\"type\":\"ping\",\"token\":\"again\"}", 2000u, action),
                 GM_BAD_MESSAGE, "duplicate request ID is rejected");
        check(duplicate_session.state == GM_CONTROL_SESSION_STATE_CLOSED && action.kind == GM_CONTROL_ACTION_SEND_ERROR_CLOSE,
            "duplicate request ID closes the session");
    }

    void test_deterministic_property_smoke() {
        const std::string valid_ping = "{\"v\":1,\"id\":3,\"type\":\"ping\",\"token\":\"phase1\"}";
        for (size_t byte_index = 0; byte_index < valid_ping.size(); ++byte_index) {
            std::string mutated = valid_ping;
            mutated[byte_index] = static_cast<char>(0xff);
            gm_control_message_info message{sizeof(gm_control_message_info)};
            const gm_status status = gm_control_parse_message(bytes_from_string(mutated), &message);
            check(status != GM_INTERNAL, "mutated control messages never report internal failure");
        }

        const char *early_requests[] = {
            "{\"v\":1,\"id\":1,\"type\":\"ping\",\"token\":\"too-early\"}",
            "{\"v\":1,\"id\":1,\"type\":\"status.get\"}",
            "{\"v\":1,\"id\":1,\"type\":\"transport.bind\","
            "\"session_id\":\"00112233445566778899aabbccddeeff\",\"udp_port\":49152}"
        };
        for (const char *request_json : early_requests) {
            gm_control_session_config config = test_session_config();
            gm_control_session session{sizeof(gm_control_session)};
            gm_control_action action{sizeof(gm_control_action)};
            check_status(gm_control_session_init(&config, &session), GM_OK, "property smoke session initializes");
            check_status(gm_control_session_ingest(&session, bytes_from_cstr(request_json), 1u, &action),
                         GM_STATE_CONFLICT, "non-hello request before hello conflicts deterministically");
            check(session.state == GM_CONTROL_SESSION_STATE_TLS_READY && action.kind == GM_CONTROL_ACTION_SEND_ERROR_RESULT,
                  "early request does not advance the state machine");
        }
    }

    void test_audio_timing_plan() {
        gm_audio_profile profile{};
        profile.struct_size = sizeof(profile);
        profile.abi_version = GM_ABI_VERSION;
        profile.codec = GM_AUDIO_CODEC_PCM_S16LE;
        profile.sample_rate_hz = GM_AUDIO_SAMPLE_RATE_HZ;
        profile.channels = 2u;
        profile.frames_per_packet = 240u;
        profile.channel_layout = GM_CHANNEL_LAYOUT_STEREO;
        profile.packet_interval_us = 5000u;
        profile.payload_bytes = GM_AUDIO_PCM_S16LE_PAYLOAD_BYTES;

        gm_audio_timing_plan timing{sizeof(gm_audio_timing_plan)};
        check_status(gm_audio_calculate_timing_plan(&profile, 30u, &timing), GM_OK,
                 "PCM timing plan calculates");
        check(timing.packet_interval_us == 5000u && timing.playout_target_frames == 1440u,
            "timing plan reports packet interval and playout target frames");
        check(timing.jitter_capacity_packets == 60u && timing.jitter_capacity_bytes == 57600u,
            "timing plan reports bounded jitter capacity");
        check(timing.lookbehind_frames == 5760u && timing.lookahead_frames == 12000u,
            "timing plan reports accepted media timestamp window");
        check(timing.bridge_capacity_frames == 4800u && timing.bridge_freshness_frames == 2400u &&
              timing.send_capacity_frames == 1920u && timing.send_freshness_frames == 960u,
            "timing plan reports bridge and send freshness policy");

        check_status(gm_audio_calculate_timing_plan(&profile, 14u, &timing), GM_BAD_MESSAGE,
                 "timing plan rejects too-low playout target");
        check_status(gm_audio_calculate_timing_plan(&profile, 121u, &timing), GM_BAD_MESSAGE,
                 "timing plan rejects too-high playout target");
    }
}

void test_packet_path_budget_smoke() {
    gm_media_header header{};
    header.struct_size = sizeof(gm_media_header);
    header.abi_version = GM_ABI_VERSION;
    header.kind = GM_MEDIA_KIND_PATH_CHALLENGE;
    for (uint8_t byte_index = 0; byte_index < GM_SESSION_ID_BYTES; ++byte_index) {
        header.session_id[byte_index] = byte_index;
    }
    header.stream_id = 1u;
    header.direction = GM_MEDIA_DIRECTION_WIN_TO_APPLE;
    header.key_epoch = 1u;
    header.sequence = 1u;
    header.payload_length = 12u;

    std::array<uint8_t, GM_MEDIA_HEADER_BYTES> encoded{};
    std::array<uint8_t, GM_MEDIA_HEADER_BYTES + 12u + GM_MEDIA_TAG_BYTES> datagram{};
    std::array<uint8_t, GM_MEDIA_NONCE_BYTES> nonce{};
    gm_media_header decoded{sizeof(gm_media_header)};
    gm_replay_window replay_window{sizeof(gm_replay_window)};
    uint32_t replay_result = 0;
    size_t written = 0;

    check_status(gm_replay_window_init(&replay_window), GM_OK, "packet budget replay window initializes");

    const auto started_at = std::chrono::steady_clock::now();
    for (uint32_t iteration = 0; iteration < 10000u; ++iteration) {
        header.sequence = iteration + 1u;
        check_status(gm_media_encode_header(&header, gm_mut_bytes{encoded.data(), encoded.size()}, &written), GM_OK,
                     "packet budget media header encodes");
        std::memcpy(datagram.data(), encoded.data(), encoded.size());
        check_status(gm_media_decode_header(gm_bytes{datagram.data(), datagram.size()}, &decoded), GM_OK,
                     "packet budget media header decodes");
        check_status(gm_media_build_nonce(header.key_epoch, header.sequence, gm_mut_bytes{nonce.data(), nonce.size()}), GM_OK,
                     "packet budget nonce builds");
        check_status(gm_replay_window_accept(&replay_window, header.sequence, &replay_result), GM_OK,
                     "packet budget replay window accepts");
        check(replay_result == GM_REPLAY_ACCEPTED, "packet budget replay accepts fresh sequence");
    }
    const auto elapsed = std::chrono::steady_clock::now() - started_at;
    const auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count();
    check(elapsed_ms < 5000, "packet helper fixed-buffer loop stays within the Phase 1 smoke budget");
}

int main() {
    test_version_and_framing();
    test_control_json_limits();
    test_control_message_parsing();
    test_media_header_and_replay();
    test_control_session_state_machine();
    test_audio_timing_plan();
    test_deterministic_property_smoke();
    test_packet_path_budget_smoke();

    if (failures != 0) {
        std::cerr << failures << " failure(s)\n";
        return 1;
    }

    return 0;
}
