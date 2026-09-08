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
    GM_NEED_MORE_DATA = 7
} gm_status;

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
    uint32_t payload_length;
    size_t frame_size;
    uint8_t complete;
    uint8_t reserved[7];
} gm_control_frame_info;

GM_API const char *gm_status_string(gm_status status);
GM_API gm_status gm_get_version(gm_core_version *out_version);
GM_API gm_status gm_control_validate_json_text(gm_bytes json_text);
GM_API gm_status gm_control_encode_frame(gm_bytes json_text, gm_mut_bytes output, size_t *written);
GM_API gm_status gm_control_peek_frame(gm_bytes input, gm_control_frame_info *out_info);

#ifdef __cplusplus
}
#endif

#endif
