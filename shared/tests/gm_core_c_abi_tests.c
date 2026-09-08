#include <ghostmedia/gm_core.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int failures = 0;

static void check(int condition, const char *label) {
    if (!condition) {
        printf("FAIL: %s\n", label);
        ++failures;
    }
}

static void check_status(gm_status actual, gm_status expected, const char *label) {
    if (actual != expected) {
        printf("FAIL: %s expected %s got %s\n", label, gm_status_string(expected), gm_status_string(actual));
        ++failures;
    }
}

static gm_bytes bytes_from_cstr(const char *text) {
    gm_bytes bytes;
    bytes.data = (const uint8_t *)text;
    bytes.size = strlen(text);
    return bytes;
}

static void set_c_string(char *destination, size_t destination_size, const char *source) {
    memset(destination, 0, destination_size);
    const size_t source_size = strlen(source);
    const size_t copy_size = source_size < destination_size - 1u ? source_size : destination_size - 1u;
    memcpy(destination, source, copy_size);
}

int main(void) {
    gm_core_version version;
    memset(&version, 0, sizeof(version));
    version.struct_size = sizeof(version);
    check_status(gm_get_version(&version), GM_OK, "gm_get_version works from C");
    check(version.abi_version == GM_ABI_VERSION && version.protocol_major == GM_PROTOCOL_MAJOR,
          "version fields match public constants");

    gm_control_message_info message;
    memset(&message, 0, sizeof(message));
    message.struct_size = sizeof(message);
    check_status(gm_control_parse_message(
                     bytes_from_cstr("{\"v\":1,\"id\":1,\"type\":\"session.hello\",\"role\":\"win-client\","
                                     "\"client_name\":\"C ABI smoke\",\"versions\":[1],\"udp_port\":49152}"),
                     &message),
                 GM_OK, "control parser works from C");
    check(message.kind == GM_CONTROL_REQUEST_SESSION_HELLO && strcmp(message.role, "win-client") == 0,
          "parsed C ABI control fields are available");

    gm_audio_profile profile;
    memset(&profile, 0, sizeof(profile));
    profile.struct_size = sizeof(profile);
    profile.abi_version = GM_ABI_VERSION;
    profile.codec = GM_AUDIO_CODEC_PCM_S16LE;
    profile.sample_rate_hz = 48000u;
    profile.channels = 2u;
    profile.frames_per_packet = 240u;
    profile.channel_layout = GM_CHANNEL_LAYOUT_STEREO;
    profile.packet_interval_us = 5000u;
    profile.payload_bytes = GM_AUDIO_PCM_S16LE_PAYLOAD_BYTES;
    check_status(gm_audio_profile_validate(&profile), GM_OK, "audio profile validator works from C");

    gm_media_header header;
    uint8_t encoded[GM_MEDIA_HEADER_BYTES];
    gm_mut_bytes output;
    size_t written = 0u;
    memset(&header, 0, sizeof(header));
    memset(encoded, 0, sizeof(encoded));
    header.struct_size = sizeof(header);
    header.abi_version = GM_ABI_VERSION;
    header.kind = GM_MEDIA_KIND_PATH_RESPONSE;
    header.stream_id = 1u;
    header.direction = GM_MEDIA_DIRECTION_APPLE_TO_WIN;
    header.key_epoch = 1u;
    header.sequence = 1u;
    header.payload_length = 12u;
    output.data = encoded;
    output.size = sizeof(encoded);
    check_status(gm_media_encode_header(&header, output, &written), GM_OK, "media header encoder works from C");
    check(written == GM_MEDIA_HEADER_BYTES && encoded[28] == GM_MEDIA_DIRECTION_APPLE_TO_WIN,
          "encoded C ABI media header is available");

        gm_control_session_config config;
        gm_control_session session;
        gm_control_action action;
        gm_control_metrics metrics;
        memset(&config, 0, sizeof(config));
        memset(&session, 0, sizeof(session));
        memset(&action, 0, sizeof(action));
        memset(&metrics, 0, sizeof(metrics));
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
        session.struct_size = sizeof(session);
        action.struct_size = sizeof(action);
        metrics.struct_size = sizeof(metrics);
        check_status(gm_control_session_init(&config, &session), GM_OK, "control session initializes from C");
        check_status(gm_control_session_ingest(
                   &session,
                   bytes_from_cstr("{\"v\":1,\"id\":1,\"type\":\"session.hello\",\"role\":\"win-client\","
                             "\"client_name\":\"C ABI smoke\",\"versions\":[1],\"udp_port\":49152}"),
                   1u,
                   &action),
                 GM_OK, "control session ingests hello from C");
        check(action.kind == GM_CONTROL_ACTION_SEND_SESSION_HELLO_RESULT &&
              session.state == GM_CONTROL_SESSION_STATE_HELLO,
            "control session emits typed action from C");
        check_status(gm_control_session_get_metrics(&session, &metrics), GM_OK, "control metrics read from C");
        check(metrics.valid_requests == 1u && metrics.actions_emitted == 1u,
            "control metrics expose deterministic counters from C");

        gm_audio_timing_plan timing;
        memset(&timing, 0, sizeof(timing));
        timing.struct_size = sizeof(timing);
        check_status(gm_audio_calculate_timing_plan(&profile, 30u, &timing), GM_OK,
                 "audio timing plan calculates from C");
        check(timing.jitter_capacity_packets == 60u && timing.send_freshness_frames == 960u,
            "audio timing plan fields are available from C");

    if (failures != 0) {
        printf("%d failure(s)\n", failures);
        return 1;
    }
    return 0;
}