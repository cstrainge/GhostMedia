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

    if (failures != 0) {
        printf("%d failure(s)\n", failures);
        return 1;
    }
    return 0;
}