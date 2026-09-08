#ifndef GHOSTMEDIA_GM_CORE_H
#define GHOSTMEDIA_GM_CORE_H

#include <stddef.h>
#include <stdint.h>

#if defined(_WIN32) && defined(GM_CORE_SHARED)
#if defined(GM_CORE_BUILD)
#define GM_API __declspec(dllexport)
#else
#define GM_API __declspec(dllimport)
#endif
#else
#define GM_API
#endif

#define GM_ABI_VERSION 1u
#define GM_PROTOCOL_MAJOR 1u
#define GM_CONTROL_FRAME_HEADER_BYTES 4u
#define GM_CONTROL_FRAME_MIN_PAYLOAD_BYTES 2u
#define GM_CONTROL_FRAME_MAX_PAYLOAD_BYTES 65536u
#define GM_CONTROL_MESSAGE_MAX_BYTES 8192u
#define GM_CONTROL_HELLO_MAX_BYTES 12288u
#define GM_CONTROL_MAX_DEPTH 16u
#define GM_CONTROL_MAX_OBJECT_MEMBERS 32u
#define GM_CONTROL_MAX_MESSAGE_MEMBERS 64u
#define GM_CONTROL_MAX_ARRAY_ELEMENTS 8u
#define GM_CONTROL_MAX_STRING_BYTES 4096u
#define GM_CONTROL_TYPE_MAX_BYTES 64u
#define GM_CONTROL_CLIENT_NAME_MAX_BYTES 128u
#define GM_CONTROL_TOKEN_MAX_BYTES 64u
#define GM_CONTROL_REASON_MAX_BYTES 64u
#define GM_CONTROL_SESSION_ID_HEX_BYTES 32u
#define GM_CONTROL_ROLE_MAX_BYTES 32u
#define GM_CONTROL_DECIMAL_U64_MAX_BYTES 20u
#define GM_CONTROL_UUID_BYTES 36u

#define GM_SESSION_ID_BYTES 16u
#define GM_MEDIA_HEADER_BYTES 64u
#define GM_MEDIA_TAG_BYTES 16u
#define GM_MEDIA_MIN_DATAGRAM_BYTES 80u
#define GM_MEDIA_MAX_DATAGRAM_BYTES 1500u
#define GM_MEDIA_MAX_PAYLOAD_BYTES 1420u
#define GM_MEDIA_NONCE_BYTES 12u
#define GM_REPLAY_WINDOW_BITS 1024u
#define GM_AUDIO_PCM_S16LE_PAYLOAD_BYTES 960u
#define GM_AUDIO_OPUS_MAX_PAYLOAD_BYTES 1128u
#define GM_FEEDBACK_PAYLOAD_BYTES 32u
#define GM_AUDIO_SAMPLE_RATE_HZ 48000u
#define GM_RECEIVER_JITTER_CAPACITY_MS 300u
#define GM_RECEIVER_JITTER_CAPACITY_BYTES 65536u
#define GM_MEDIA_LOOKBEHIND_MS 120u
#define GM_MEDIA_LOOKAHEAD_MS 250u
#define GM_BRIDGE_CAPACITY_MS 100u
#define GM_BRIDGE_FRESHNESS_MS 50u
#define GM_SEND_CAPACITY_MS 40u
#define GM_SEND_FRESHNESS_MS 20u

#ifdef __cplusplus
extern "C" {
#endif

typedef enum gm_status {
    GM_OK = 0,
    GM_BAD_ARGUMENT = 1,
    GM_BAD_MESSAGE = 2,
    GM_STATE_CONFLICT = 3,
    GM_LIMIT_EXCEEDED = 4,
    GM_BUFFER_TOO_SMALL = 5,
    GM_UNAUTHORIZED = 6,
    GM_NEED_MORE_DATA = 7,
    GM_UNSUPPORTED_VERSION = 8,
    GM_INTERNAL = 9
} gm_status;

typedef enum gm_control_message_kind {
    GM_CONTROL_MESSAGE_UNKNOWN = 0,
    GM_CONTROL_REQUEST_SESSION_HELLO = 1,
    GM_CONTROL_REQUEST_TRANSPORT_BIND = 2,
    GM_CONTROL_REQUEST_STREAM_OPEN = 3,
    GM_CONTROL_REQUEST_STREAM_START = 4,
    GM_CONTROL_REQUEST_STREAM_STOP = 5,
    GM_CONTROL_REQUEST_STREAM_CLOSE = 6,
    GM_CONTROL_REQUEST_STREAM_REKEY = 7,
    GM_CONTROL_REQUEST_STATUS_GET = 8,
    GM_CONTROL_REQUEST_PING = 9,
    GM_CONTROL_REQUEST_SESSION_CLOSE = 10,
    GM_CONTROL_RESPONSE_RESULT = 100,
    GM_CONTROL_RESPONSE_ERROR = 101,
    GM_CONTROL_EVENT_STREAM_STARTED = 200,
    GM_CONTROL_EVENT_STREAM_STOPPED = 201,
    GM_CONTROL_EVENT_OUTPUT_STATE = 202,
    GM_CONTROL_EVENT_SESSION_EXPIRING = 203
} gm_control_message_kind;

typedef enum gm_audio_codec {
    GM_AUDIO_CODEC_UNKNOWN = 0,
    GM_AUDIO_CODEC_PCM_S16LE = 1,
    GM_AUDIO_CODEC_OPUS = 2
} gm_audio_codec;

typedef enum gm_channel_layout {
    GM_CHANNEL_LAYOUT_UNKNOWN = 0,
    GM_CHANNEL_LAYOUT_STEREO = 1
} gm_channel_layout;

typedef enum gm_media_kind {
    GM_MEDIA_KIND_UNKNOWN = 0,
    GM_MEDIA_KIND_AUDIO = 1,
    GM_MEDIA_KIND_PATH_CHALLENGE = 2,
    GM_MEDIA_KIND_PATH_RESPONSE = 3,
    GM_MEDIA_KIND_FEEDBACK = 4
} gm_media_kind;

typedef enum gm_media_direction {
    GM_MEDIA_DIRECTION_UNKNOWN = 0,
    GM_MEDIA_DIRECTION_WIN_TO_APPLE = 1,
    GM_MEDIA_DIRECTION_APPLE_TO_WIN = 2
} gm_media_direction;

typedef enum gm_replay_result {
    GM_REPLAY_ACCEPTED = 1,
    GM_REPLAY_DUPLICATE = 2,
    GM_REPLAY_TOO_OLD = 3
} gm_replay_result;

typedef enum gm_control_session_role {
    GM_CONTROL_SESSION_ROLE_APPLE_OUTPUT_SERVER = 1
} gm_control_session_role;

typedef enum gm_control_session_state {
    GM_CONTROL_SESSION_STATE_CLOSED = 0,
    GM_CONTROL_SESSION_STATE_TLS_READY = 1,
    GM_CONTROL_SESSION_STATE_HELLO = 2,
    GM_CONTROL_SESSION_STATE_BOUND = 3,
    GM_CONTROL_SESSION_STATE_STREAM_OPEN = 4,
    GM_CONTROL_SESSION_STATE_STREAMING = 5
} gm_control_session_state;

typedef enum gm_control_action_kind {
    GM_CONTROL_ACTION_NONE = 0,
    GM_CONTROL_ACTION_SEND_SESSION_HELLO_RESULT = 1,
    GM_CONTROL_ACTION_SEND_TRANSPORT_BIND_RESULT = 2,
    GM_CONTROL_ACTION_SEND_STREAM_OPEN_RESULT = 3,
    GM_CONTROL_ACTION_SEND_STREAM_START_RESULT = 4,
    GM_CONTROL_ACTION_SEND_STREAM_STOP_RESULT = 5,
    GM_CONTROL_ACTION_SEND_STREAM_CLOSE_RESULT = 6,
    GM_CONTROL_ACTION_SEND_STREAM_REKEY_RESULT = 7,
    GM_CONTROL_ACTION_SEND_STATUS_RESULT = 8,
    GM_CONTROL_ACTION_SEND_PING_RESULT = 9,
    GM_CONTROL_ACTION_SEND_SESSION_CLOSE_RESULT = 10,
    GM_CONTROL_ACTION_PATH_VALIDATED = 20,
    GM_CONTROL_ACTION_SEND_ERROR_RESULT = 100,
    GM_CONTROL_ACTION_SEND_ERROR_CLOSE = 101
} gm_control_action_kind;

typedef struct gm_bytes {
    const uint8_t *data;
    size_t size;
} gm_bytes;

typedef struct gm_mut_bytes {
    uint8_t *data;
    size_t size;
} gm_mut_bytes;

typedef struct gm_core_version {
    size_t struct_size;
    uint32_t abi_version;
    uint32_t protocol_major;
    const char *spec_revision;
} gm_core_version;

typedef struct gm_control_frame_info {
    size_t struct_size;
    uint32_t abi_version;
    uint32_t payload_length;
    size_t frame_size;
    uint8_t complete;
    uint8_t reserved[3];
} gm_control_frame_info;

typedef struct gm_audio_profile {
    size_t struct_size;
    uint32_t abi_version;
    uint32_t codec;
    uint32_t sample_rate_hz;
    uint16_t channels;
    uint16_t frames_per_packet;
    uint32_t channel_layout;
    uint32_t packet_interval_us;
    uint32_t payload_bytes;
} gm_audio_profile;

typedef struct gm_control_message_info {
    size_t struct_size;
    uint32_t abi_version;
    uint32_t kind;
    uint32_t id;
    uint32_t mutating;
    uint32_t udp_port;
    uint32_t stream_id;
    uint32_t key_epoch;
    uint32_t playout_target_ms;
    uint8_t has_reason;
    uint8_t versions_count;
    uint8_t versions[8];
    uint8_t reserved[2];
    gm_audio_profile profile;
    char type[GM_CONTROL_TYPE_MAX_BYTES + 1u];
    char role[GM_CONTROL_ROLE_MAX_BYTES + 1u];
    char client_name[GM_CONTROL_CLIENT_NAME_MAX_BYTES + 1u];
    char server_id[GM_CONTROL_UUID_BYTES + 1u];
    char boot_id[GM_CONTROL_UUID_BYTES + 1u];
    char session_id[GM_CONTROL_SESSION_ID_HEX_BYTES + 1u];
    char token[GM_CONTROL_TOKEN_MAX_BYTES + 1u];
    char reason[GM_CONTROL_REASON_MAX_BYTES + 1u];
    char state[GM_CONTROL_REASON_MAX_BYTES + 1u];
    char path_state[GM_CONTROL_REASON_MAX_BYTES + 1u];
    char output_state[GM_CONTROL_REASON_MAX_BYTES + 1u];
    char session_stream_state[GM_CONTROL_REASON_MAX_BYTES + 1u];
    char transport_state[GM_CONTROL_REASON_MAX_BYTES + 1u];
    char first_media_timestamp[GM_CONTROL_DECIMAL_U64_MAX_BYTES + 1u];
    char monotonic_ns[GM_CONTROL_DECIMAL_U64_MAX_BYTES + 1u];
} gm_control_message_info;

typedef struct gm_media_header {
    size_t struct_size;
    uint32_t abi_version;
    uint32_t kind;
    uint8_t session_id[GM_SESSION_ID_BYTES];
    uint32_t stream_id;
    uint32_t direction;
    uint32_t key_epoch;
    uint64_t sequence;
    uint64_t media_timestamp;
    uint32_t payload_length;
} gm_media_header;

typedef struct gm_replay_window {
    size_t struct_size;
    uint32_t abi_version;
    uint8_t initialized;
    uint8_t reserved[3];
    uint64_t highest_sequence;
    uint64_t bitmap[16];
} gm_replay_window;

typedef struct gm_control_session_config {
    size_t struct_size;
    uint32_t abi_version;
    uint32_t role;
    uint32_t apple_udp_port;
    uint32_t stream_id;
    uint32_t key_epoch;
    uint32_t max_audio_subscribers;
    uint32_t playout_target_ms_min;
    uint32_t playout_target_ms_max;
    uint8_t output_available;
    uint8_t reserved[3];
    char server_id[GM_CONTROL_UUID_BYTES + 1u];
    char boot_id[GM_CONTROL_UUID_BYTES + 1u];
    char session_id[GM_CONTROL_SESSION_ID_HEX_BYTES + 1u];
} gm_control_session_config;

typedef struct gm_control_session {
    size_t struct_size;
    uint32_t abi_version;
    uint32_t role;
    uint32_t state;
    uint32_t last_request_id;
    uint32_t windows_udp_port;
    uint32_t apple_udp_port;
    uint32_t stream_id;
    uint32_t next_stream_id;
    uint32_t key_epoch;
    uint32_t initial_key_epoch;
    uint32_t last_rekey_epoch;
    uint32_t last_closed_stream_id;
    uint32_t playout_target_ms;
    uint64_t last_update_ns;
    uint64_t valid_requests;
    uint64_t rejected_requests;
    uint64_t actions_emitted;
    uint64_t state_conflicts;
    uint64_t protocol_errors;
    uint64_t streams_started;
    uint64_t streams_stopped;
    uint64_t streams_closed;
    uint64_t rekeys_committed;
    uint8_t path_validated;
    uint8_t output_available;
    uint8_t reserved[6];
    gm_audio_profile profile;
    char server_id[GM_CONTROL_UUID_BYTES + 1u];
    char boot_id[GM_CONTROL_UUID_BYTES + 1u];
    char session_id[GM_CONTROL_SESSION_ID_HEX_BYTES + 1u];
    char first_media_timestamp[GM_CONTROL_DECIMAL_U64_MAX_BYTES + 1u];
} gm_control_session;

typedef struct gm_control_action {
    size_t struct_size;
    uint32_t abi_version;
    uint32_t kind;
    uint32_t response_id;
    uint32_t status;
    uint32_t session_state;
    uint32_t udp_port;
    uint32_t stream_id;
    uint32_t key_epoch;
    uint32_t playout_target_ms;
    uint32_t packet_interval_us;
    uint8_t terminal;
    uint8_t reserved[3];
    gm_audio_profile profile;
    char server_id[GM_CONTROL_UUID_BYTES + 1u];
    char boot_id[GM_CONTROL_UUID_BYTES + 1u];
    char session_id[GM_CONTROL_SESSION_ID_HEX_BYTES + 1u];
    char token[GM_CONTROL_TOKEN_MAX_BYTES + 1u];
    char state[GM_CONTROL_REASON_MAX_BYTES + 1u];
    char path_state[GM_CONTROL_REASON_MAX_BYTES + 1u];
    char output_state[GM_CONTROL_REASON_MAX_BYTES + 1u];
    char session_stream_state[GM_CONTROL_REASON_MAX_BYTES + 1u];
    char transport_state[GM_CONTROL_REASON_MAX_BYTES + 1u];
    char first_media_timestamp[GM_CONTROL_DECIMAL_U64_MAX_BYTES + 1u];
    char monotonic_ns[GM_CONTROL_DECIMAL_U64_MAX_BYTES + 1u];
} gm_control_action;

typedef struct gm_control_metrics {
    size_t struct_size;
    uint32_t abi_version;
    uint64_t valid_requests;
    uint64_t rejected_requests;
    uint64_t actions_emitted;
    uint64_t state_conflicts;
    uint64_t protocol_errors;
    uint64_t streams_started;
    uint64_t streams_stopped;
    uint64_t streams_closed;
    uint64_t rekeys_committed;
} gm_control_metrics;

typedef struct gm_audio_timing_plan {
    size_t struct_size;
    uint32_t abi_version;
    uint32_t packet_interval_us;
    uint32_t frames_per_packet;
    uint32_t playout_target_ms;
    uint32_t playout_target_frames;
    uint32_t jitter_capacity_packets;
    uint32_t jitter_capacity_bytes;
    uint32_t lookbehind_frames;
    uint32_t lookahead_frames;
    uint32_t bridge_capacity_frames;
    uint32_t bridge_freshness_frames;
    uint32_t send_capacity_frames;
    uint32_t send_freshness_frames;
} gm_audio_timing_plan;

GM_API const char *gm_status_string(gm_status status);
GM_API gm_status gm_get_version(gm_core_version *out_version);
GM_API gm_status gm_control_validate_json_text(gm_bytes json_text);
GM_API gm_status gm_control_parse_message(gm_bytes json_text, gm_control_message_info *out_info);
GM_API gm_status gm_control_encode_frame(gm_bytes json_text, gm_mut_bytes output, size_t *written);
GM_API gm_status gm_control_peek_frame(gm_bytes input, gm_control_frame_info *out_info);
GM_API gm_status gm_audio_profile_validate(const gm_audio_profile *profile);
GM_API gm_status gm_media_encode_header(const gm_media_header *header, gm_mut_bytes output, size_t *written);
GM_API gm_status gm_media_decode_header(gm_bytes datagram, gm_media_header *out_header);
GM_API gm_status gm_media_build_nonce(uint32_t key_epoch, uint64_t sequence, gm_mut_bytes output);
GM_API gm_status gm_replay_window_init(gm_replay_window *window);
GM_API gm_status gm_replay_window_accept(gm_replay_window *window, uint64_t sequence, uint32_t *out_result);
GM_API gm_status gm_control_session_init(const gm_control_session_config *config, gm_control_session *session);
GM_API gm_status gm_control_session_ingest(gm_control_session *session, gm_bytes json_text, uint64_t now_ns, gm_control_action *out_action);
GM_API gm_status gm_control_session_mark_path_validated(gm_control_session *session, uint32_t stream_id, uint32_t key_epoch, gm_control_action *out_action);
GM_API gm_status gm_control_session_get_metrics(const gm_control_session *session, gm_control_metrics *out_metrics);
GM_API gm_status gm_audio_calculate_timing_plan(const gm_audio_profile *profile, uint32_t playout_target_ms, gm_audio_timing_plan *out_plan);

#ifdef __cplusplus
}
#endif

#endif
