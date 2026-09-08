#include <ghostmedia/gm_core.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>

namespace {
bool bounded_c_string(const char *value, size_t capacity, size_t *out_length) {
    if (value == nullptr || capacity == 0u) {
        return false;
    }
    for (size_t index = 0; index < capacity; ++index) {
        if (value[index] == '\0') {
            if (out_length != nullptr) {
                *out_length = index;
            }
            return true;
        }
    }
    return false;
}

bool is_lower_uuid_text(const char *value) {
    size_t length = 0;
    if (!bounded_c_string(value, GM_CONTROL_UUID_BYTES + 1u, &length) || length != GM_CONTROL_UUID_BYTES) {
        return false;
    }
    for (size_t index = 0; index < GM_CONTROL_UUID_BYTES; ++index) {
        const char character = value[index];
        if (index == 8u || index == 13u || index == 18u || index == 23u) {
            if (character != '-') {
                return false;
            }
            continue;
        }
        if (!((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f'))) {
            return false;
        }
    }
    return true;
}

bool is_lower_session_id_text(const char *value) {
    size_t length = 0;
    if (!bounded_c_string(value, GM_CONTROL_SESSION_ID_HEX_BYTES + 1u, &length) ||
        length != GM_CONTROL_SESSION_ID_HEX_BYTES) {
        return false;
    }
    for (size_t index = 0; index < GM_CONTROL_SESSION_ID_HEX_BYTES; ++index) {
        const char character = value[index];
        if (!((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f'))) {
            return false;
        }
    }
    return true;
}

void copy_c_string(char *destination, size_t destination_size, const char *source) {
    std::memset(destination, 0, destination_size);
    if (destination_size == 0u || source == nullptr) {
        return;
    }
    size_t source_length = 0;
    if (!bounded_c_string(source, destination_size, &source_length)) {
        source_length = destination_size - 1u;
    }
    const size_t copy_size = std::min(source_length, destination_size - 1u);
    std::memcpy(destination, source, copy_size);
}

void copy_literal(char *destination, size_t destination_size, const char *source) {
    std::memset(destination, 0, destination_size);
    if (destination_size == 0u || source == nullptr) {
        return;
    }
    const size_t copy_size = std::min(std::strlen(source), destination_size - 1u);
    std::memcpy(destination, source, copy_size);
}

bool same_c_string(const char *left, const char *right) {
    return std::strcmp(left, right) == 0;
}

bool same_profile(const gm_audio_profile &left, const gm_audio_profile &right) {
    return left.codec == right.codec && left.sample_rate_hz == right.sample_rate_hz &&
           left.channels == right.channels && left.frames_per_packet == right.frames_per_packet &&
           left.channel_layout == right.channel_layout &&
           left.packet_interval_us == right.packet_interval_us && left.payload_bytes == right.payload_bytes;
}

void fill_action(gm_control_action *action, const gm_control_session &session, uint32_t kind, uint32_t response_id,
                 gm_status status, uint8_t terminal) {
    const size_t caller_size = action->struct_size;
    std::memset(action, 0, sizeof(gm_control_action));
    action->struct_size = caller_size;
    action->abi_version = GM_ABI_VERSION;
    action->kind = kind;
    action->response_id = response_id;
    action->status = status;
    action->session_state = session.state;
    action->udp_port = session.apple_udp_port;
    action->stream_id = session.stream_id;
    action->key_epoch = session.key_epoch;
    action->playout_target_ms = session.playout_target_ms;
    action->packet_interval_us = session.profile.packet_interval_us;
    action->terminal = terminal;
    action->profile = session.profile;
    copy_c_string(action->server_id, sizeof(action->server_id), session.server_id);
    copy_c_string(action->boot_id, sizeof(action->boot_id), session.boot_id);
    copy_c_string(action->session_id, sizeof(action->session_id), session.session_id);
    copy_c_string(action->first_media_timestamp, sizeof(action->first_media_timestamp), session.first_media_timestamp);
}

void fill_error_action(gm_control_session *session, gm_control_action *action, uint32_t response_id,
                       gm_status status, bool close_session) {
    if (status == GM_STATE_CONFLICT) {
        ++session->state_conflicts;
    } else {
        ++session->protocol_errors;
    }
    ++session->rejected_requests;
    if (close_session) {
        session->state = GM_CONTROL_SESSION_STATE_CLOSED;
    }
    fill_action(
        action,
        *session,
        close_session ? GM_CONTROL_ACTION_SEND_ERROR_CLOSE : GM_CONTROL_ACTION_SEND_ERROR_RESULT,
        response_id,
        status,
        close_session ? 1u : 0u
    );
    ++session->actions_emitted;
}

bool valid_session_for_ingest(const gm_control_session *session, const gm_control_action *action) {
    return session != nullptr && action != nullptr && session->struct_size >= sizeof(gm_control_session) &&
           action->struct_size >= sizeof(gm_control_action) && session->abi_version == GM_ABI_VERSION;
}

gm_status ensure_request(gm_control_session *session, const gm_control_message_info &message,
                         gm_control_action *action) {
    if (message.kind < GM_CONTROL_REQUEST_SESSION_HELLO || message.kind > GM_CONTROL_REQUEST_SESSION_CLOSE) {
        fill_error_action(session, action, message.id, GM_BAD_MESSAGE, true);
        return GM_BAD_MESSAGE;
    }
    if (message.id <= session->last_request_id) {
        fill_error_action(session, action, message.id, GM_BAD_MESSAGE, true);
        return GM_BAD_MESSAGE;
    }
    session->last_request_id = message.id;
    return GM_OK;
}

gm_status reject_conflict(gm_control_session *session, gm_control_action *action, uint32_t response_id) {
    fill_error_action(session, action, response_id, GM_STATE_CONFLICT, false);
    return GM_STATE_CONFLICT;
}

void commit_action(gm_control_session *session, gm_control_action *action, uint32_t kind,
                   const gm_control_message_info &message) {
    ++session->valid_requests;
    fill_action(action, *session, kind, message.id, GM_OK, session->state == GM_CONTROL_SESSION_STATE_CLOSED ? 1u : 0u);
    ++session->actions_emitted;
}

bool active_stream_matches(const gm_control_session &session, uint32_t stream_id) {
    return session.stream_id != 0u && session.stream_id == stream_id &&
           (session.state == GM_CONTROL_SESSION_STATE_STREAM_OPEN ||
            session.state == GM_CONTROL_SESSION_STATE_STREAMING);
}

uint32_t stream_id_or_default(uint32_t configured_stream_id) {
    return configured_stream_id == 0u ? 1u : configured_stream_id;
}

uint32_t key_epoch_or_default(uint32_t configured_key_epoch) {
    return configured_key_epoch == 0u ? 1u : configured_key_epoch;
}

uint32_t frames_for_milliseconds(uint32_t milliseconds) {
    return static_cast<uint32_t>((static_cast<uint64_t>(GM_AUDIO_SAMPLE_RATE_HZ) * milliseconds) / 1000u);
}
}

gm_status gm_control_session_init(const gm_control_session_config *config, gm_control_session *session) {
    if (config == nullptr || session == nullptr || config->struct_size < sizeof(gm_control_session_config) ||
        session->struct_size < sizeof(gm_control_session) || config->abi_version != GM_ABI_VERSION) {
        return GM_BAD_ARGUMENT;
    }
    if (config->role != GM_CONTROL_SESSION_ROLE_APPLE_OUTPUT_SERVER || config->apple_udp_port == 0u ||
        config->apple_udp_port > 65535u || config->max_audio_subscribers == 0u ||
        config->playout_target_ms_min > config->playout_target_ms_max || config->playout_target_ms_min < 15u ||
        config->playout_target_ms_max > 120u || config->output_available > 1u ||
        !is_lower_uuid_text(config->server_id) || !is_lower_uuid_text(config->boot_id) ||
        !is_lower_session_id_text(config->session_id)) {
        return GM_BAD_ARGUMENT;
    }

    const size_t caller_size = session->struct_size;
    std::memset(session, 0, sizeof(gm_control_session));
    session->struct_size = caller_size;
    session->abi_version = GM_ABI_VERSION;
    session->role = config->role;
    session->state = GM_CONTROL_SESSION_STATE_TLS_READY;
    session->apple_udp_port = config->apple_udp_port;
    session->next_stream_id = stream_id_or_default(config->stream_id);
    session->initial_key_epoch = key_epoch_or_default(config->key_epoch);
    session->output_available = config->output_available;
    session->profile.struct_size = sizeof(gm_audio_profile);
    session->profile.abi_version = GM_ABI_VERSION;
    copy_c_string(session->server_id, sizeof(session->server_id), config->server_id);
    copy_c_string(session->boot_id, sizeof(session->boot_id), config->boot_id);
    copy_c_string(session->session_id, sizeof(session->session_id), config->session_id);
    return GM_OK;
}

gm_status gm_control_session_ingest(gm_control_session *session, gm_bytes json_text, uint64_t now_ns,
                                    gm_control_action *out_action) {
    if (!valid_session_for_ingest(session, out_action)) {
        return GM_BAD_ARGUMENT;
    }
    fill_action(out_action, *session, GM_CONTROL_ACTION_NONE, 0u, GM_OK, 0u);
    if (session->state == GM_CONTROL_SESSION_STATE_CLOSED) {
        fill_error_action(session, out_action, 0u, GM_STATE_CONFLICT, false);
        return GM_STATE_CONFLICT;
    }

    gm_control_message_info message{};
    message.struct_size = sizeof(message);
    const gm_status parse_status = gm_control_parse_message(json_text, &message);
    if (parse_status != GM_OK) {
        fill_error_action(session, out_action, 0u, parse_status, true);
        return parse_status;
    }

    gm_status request_status = ensure_request(session, message, out_action);
    if (request_status != GM_OK) {
        return request_status;
    }

    session->last_update_ns = now_ns;

    if (message.kind != GM_CONTROL_REQUEST_SESSION_HELLO && session->state == GM_CONTROL_SESSION_STATE_TLS_READY) {
        return reject_conflict(session, out_action, message.id);
    }

    switch (message.kind) {
    case GM_CONTROL_REQUEST_SESSION_HELLO:
        if (session->state != GM_CONTROL_SESSION_STATE_TLS_READY) {
            return reject_conflict(session, out_action, message.id);
        }
        session->windows_udp_port = message.udp_port;
        session->state = GM_CONTROL_SESSION_STATE_HELLO;
        commit_action(session, out_action, GM_CONTROL_ACTION_SEND_SESSION_HELLO_RESULT, message);
        copy_literal(out_action->state, sizeof(out_action->state), "hello");
        return GM_OK;

    case GM_CONTROL_REQUEST_TRANSPORT_BIND:
        if (session->state < GM_CONTROL_SESSION_STATE_HELLO ||
            std::strncmp(message.session_id, session->session_id, sizeof(session->session_id)) != 0 ||
            message.udp_port != session->windows_udp_port) {
            return reject_conflict(session, out_action, message.id);
        }
        if (session->state == GM_CONTROL_SESSION_STATE_HELLO) {
            session->state = GM_CONTROL_SESSION_STATE_BOUND;
        }
        commit_action(session, out_action, GM_CONTROL_ACTION_SEND_TRANSPORT_BIND_RESULT, message);
        copy_literal(out_action->path_state, sizeof(out_action->path_state), "bound");
        return GM_OK;

    case GM_CONTROL_REQUEST_STREAM_OPEN:
        if (session->state == GM_CONTROL_SESSION_STATE_BOUND) {
            session->stream_id = session->next_stream_id;
            session->key_epoch = session->initial_key_epoch;
            session->profile = message.profile;
            session->playout_target_ms = message.playout_target_ms;
            session->path_validated = 0u;
            session->state = GM_CONTROL_SESSION_STATE_STREAM_OPEN;
            commit_action(session, out_action, GM_CONTROL_ACTION_SEND_STREAM_OPEN_RESULT, message);
            copy_literal(out_action->path_state, sizeof(out_action->path_state), "probing");
            return GM_OK;
        }
        if ((session->state == GM_CONTROL_SESSION_STATE_STREAM_OPEN ||
             session->state == GM_CONTROL_SESSION_STATE_STREAMING) &&
            same_profile(session->profile, message.profile) && session->playout_target_ms == message.playout_target_ms) {
            commit_action(session, out_action, GM_CONTROL_ACTION_SEND_STREAM_OPEN_RESULT, message);
            copy_literal(out_action->path_state, sizeof(out_action->path_state), "probing");
            return GM_OK;
        }
        return reject_conflict(session, out_action, message.id);

    case GM_CONTROL_REQUEST_STREAM_START:
        if (!active_stream_matches(*session, message.stream_id) || session->path_validated == 0u) {
            return reject_conflict(session, out_action, message.id);
        }
        if (session->state == GM_CONTROL_SESSION_STATE_STREAMING &&
            !same_c_string(session->first_media_timestamp, message.first_media_timestamp)) {
            return reject_conflict(session, out_action, message.id);
        }
        copy_c_string(session->first_media_timestamp, sizeof(session->first_media_timestamp), message.first_media_timestamp);
        if (session->state != GM_CONTROL_SESSION_STATE_STREAMING) {
            ++session->streams_started;
        }
        session->state = GM_CONTROL_SESSION_STATE_STREAMING;
        commit_action(session, out_action, GM_CONTROL_ACTION_SEND_STREAM_START_RESULT, message);
        copy_literal(out_action->state, sizeof(out_action->state), "started");
        copy_c_string(out_action->first_media_timestamp, sizeof(out_action->first_media_timestamp), message.first_media_timestamp);
        return GM_OK;

    case GM_CONTROL_REQUEST_STREAM_STOP:
        if (!active_stream_matches(*session, message.stream_id)) {
            return reject_conflict(session, out_action, message.id);
        }
        if (session->state == GM_CONTROL_SESSION_STATE_STREAMING) {
            ++session->streams_stopped;
        }
        session->state = GM_CONTROL_SESSION_STATE_STREAM_OPEN;
        commit_action(session, out_action, GM_CONTROL_ACTION_SEND_STREAM_STOP_RESULT, message);
        copy_literal(out_action->state, sizeof(out_action->state), "stopped");
        return GM_OK;

    case GM_CONTROL_REQUEST_STREAM_CLOSE:
        if (active_stream_matches(*session, message.stream_id)) {
            session->last_closed_stream_id = message.stream_id;
            if (session->next_stream_id <= message.stream_id && message.stream_id != std::numeric_limits<uint32_t>::max()) {
                session->next_stream_id = message.stream_id + 1u;
            }
            session->stream_id = 0u;
            session->key_epoch = 0u;
            session->last_rekey_epoch = 0u;
            session->playout_target_ms = 0u;
            session->path_validated = 0u;
            std::memset(&session->profile, 0, sizeof(session->profile));
            session->profile.struct_size = sizeof(gm_audio_profile);
            session->profile.abi_version = GM_ABI_VERSION;
            std::memset(session->first_media_timestamp, 0, sizeof(session->first_media_timestamp));
            session->state = GM_CONTROL_SESSION_STATE_BOUND;
            ++session->streams_closed;
            commit_action(session, out_action, GM_CONTROL_ACTION_SEND_STREAM_CLOSE_RESULT, message);
            out_action->stream_id = message.stream_id;
            copy_literal(out_action->state, sizeof(out_action->state), "closed");
            return GM_OK;
        }
        if (session->state == GM_CONTROL_SESSION_STATE_BOUND && message.stream_id == session->last_closed_stream_id) {
            commit_action(session, out_action, GM_CONTROL_ACTION_SEND_STREAM_CLOSE_RESULT, message);
            out_action->stream_id = message.stream_id;
            copy_literal(out_action->state, sizeof(out_action->state), "closed");
            return GM_OK;
        }
        return reject_conflict(session, out_action, message.id);

    case GM_CONTROL_REQUEST_STREAM_REKEY:
        if (!active_stream_matches(*session, message.stream_id)) {
            return reject_conflict(session, out_action, message.id);
        }
        if (message.key_epoch == session->key_epoch + 1u) {
            session->key_epoch = message.key_epoch;
            session->last_rekey_epoch = message.key_epoch;
            session->path_validated = 0u;
            ++session->rekeys_committed;
            commit_action(session, out_action, GM_CONTROL_ACTION_SEND_STREAM_REKEY_RESULT, message);
            copy_literal(out_action->state, sizeof(out_action->state), "rekeying");
            return GM_OK;
        }
        if (message.key_epoch == session->key_epoch && message.key_epoch == session->last_rekey_epoch) {
            commit_action(session, out_action, GM_CONTROL_ACTION_SEND_STREAM_REKEY_RESULT, message);
            copy_literal(out_action->state, sizeof(out_action->state), "rekeying");
            return GM_OK;
        }
        return reject_conflict(session, out_action, message.id);

    case GM_CONTROL_REQUEST_STATUS_GET:
        if (session->state < GM_CONTROL_SESSION_STATE_HELLO) {
            return reject_conflict(session, out_action, message.id);
        }
        commit_action(session, out_action, GM_CONTROL_ACTION_SEND_STATUS_RESULT, message);
        copy_literal(out_action->output_state, sizeof(out_action->output_state), session->output_available != 0u ? "available" : "unavailable");
        copy_literal(out_action->transport_state, sizeof(out_action->transport_state), session->state >= GM_CONTROL_SESSION_STATE_BOUND ? "bound" : "unbound");
        copy_literal(
            out_action->session_stream_state,
            sizeof(out_action->session_stream_state),
            session->state == GM_CONTROL_SESSION_STATE_STREAMING ? "started" :
            session->state == GM_CONTROL_SESSION_STATE_STREAM_OPEN ? "open" : "none"
        );
        return GM_OK;

    case GM_CONTROL_REQUEST_PING:
        if (session->state < GM_CONTROL_SESSION_STATE_HELLO) {
            return reject_conflict(session, out_action, message.id);
        }
        commit_action(session, out_action, GM_CONTROL_ACTION_SEND_PING_RESULT, message);
        copy_c_string(out_action->token, sizeof(out_action->token), message.token);
        if (now_ns == 0u) {
            copy_literal(out_action->monotonic_ns, sizeof(out_action->monotonic_ns), "0");
        } else {
            char digits[GM_CONTROL_DECIMAL_U64_MAX_BYTES + 1u]{};
            uint64_t remaining = now_ns;
            size_t write_index = sizeof(digits) - 1u;
            do {
                digits[--write_index] = static_cast<char>('0' + (remaining % 10u));
                remaining /= 10u;
            } while (remaining != 0u && write_index > 0u);
            copy_literal(out_action->monotonic_ns, sizeof(out_action->monotonic_ns), digits + write_index);
        }
        return GM_OK;

    case GM_CONTROL_REQUEST_SESSION_CLOSE:
        if (active_stream_matches(*session, session->stream_id)) {
            session->last_closed_stream_id = session->stream_id;
            session->stream_id = 0u;
            session->key_epoch = 0u;
            session->last_rekey_epoch = 0u;
            session->playout_target_ms = 0u;
            session->path_validated = 0u;
            std::memset(&session->profile, 0, sizeof(session->profile));
            session->profile.struct_size = sizeof(gm_audio_profile);
            session->profile.abi_version = GM_ABI_VERSION;
            std::memset(session->first_media_timestamp, 0, sizeof(session->first_media_timestamp));
            ++session->streams_closed;
        }
        session->state = GM_CONTROL_SESSION_STATE_CLOSED;
        commit_action(session, out_action, GM_CONTROL_ACTION_SEND_SESSION_CLOSE_RESULT, message);
        copy_literal(out_action->state, sizeof(out_action->state), "closed");
        return GM_OK;

    default:
        fill_error_action(session, out_action, message.id, GM_BAD_MESSAGE, true);
        return GM_BAD_MESSAGE;
    }
}

gm_status gm_control_session_mark_path_validated(gm_control_session *session, uint32_t stream_id, uint32_t key_epoch,
                                                 gm_control_action *out_action) {
    if (!valid_session_for_ingest(session, out_action)) {
        return GM_BAD_ARGUMENT;
    }
    fill_action(out_action, *session, GM_CONTROL_ACTION_NONE, 0u, GM_OK, 0u);
    if (!active_stream_matches(*session, stream_id) || session->key_epoch != key_epoch) {
        fill_error_action(session, out_action, 0u, GM_STATE_CONFLICT, false);
        return GM_STATE_CONFLICT;
    }
    session->path_validated = 1u;
    fill_action(out_action, *session, GM_CONTROL_ACTION_PATH_VALIDATED, 0u, GM_OK, 0u);
    copy_literal(out_action->path_state, sizeof(out_action->path_state), "validated");
    ++session->actions_emitted;
    return GM_OK;
}

gm_status gm_control_session_get_metrics(const gm_control_session *session, gm_control_metrics *out_metrics) {
    if (session == nullptr || out_metrics == nullptr || session->struct_size < sizeof(gm_control_session) ||
        out_metrics->struct_size < sizeof(gm_control_metrics) || session->abi_version != GM_ABI_VERSION) {
        return GM_BAD_ARGUMENT;
    }
    const size_t caller_size = out_metrics->struct_size;
    std::memset(out_metrics, 0, sizeof(gm_control_metrics));
    out_metrics->struct_size = caller_size;
    out_metrics->abi_version = GM_ABI_VERSION;
    out_metrics->valid_requests = session->valid_requests;
    out_metrics->rejected_requests = session->rejected_requests;
    out_metrics->actions_emitted = session->actions_emitted;
    out_metrics->state_conflicts = session->state_conflicts;
    out_metrics->protocol_errors = session->protocol_errors;
    out_metrics->streams_started = session->streams_started;
    out_metrics->streams_stopped = session->streams_stopped;
    out_metrics->streams_closed = session->streams_closed;
    out_metrics->rekeys_committed = session->rekeys_committed;
    return GM_OK;
}

gm_status gm_audio_calculate_timing_plan(const gm_audio_profile *profile, uint32_t playout_target_ms,
                                         gm_audio_timing_plan *out_plan) {
    if (profile == nullptr || out_plan == nullptr || out_plan->struct_size < sizeof(gm_audio_timing_plan)) {
        return GM_BAD_ARGUMENT;
    }
    const gm_status profile_status = gm_audio_profile_validate(profile);
    if (profile_status != GM_OK) {
        return profile_status;
    }
    if (playout_target_ms < 15u || playout_target_ms > 120u) {
        return GM_BAD_MESSAGE;
    }

    const uint32_t packet_interval_us = profile->codec == GM_AUDIO_CODEC_OPUS ? 10000u : 5000u;
    const uint32_t packet_payload_bytes = profile->codec == GM_AUDIO_CODEC_OPUS ? GM_AUDIO_OPUS_MAX_PAYLOAD_BYTES
                                                                                : GM_AUDIO_PCM_S16LE_PAYLOAD_BYTES;
    const uint32_t jitter_packets_by_time = (GM_RECEIVER_JITTER_CAPACITY_MS * 1000u + packet_interval_us - 1u) /
                                            packet_interval_us;
    const uint32_t jitter_packets_by_bytes = GM_RECEIVER_JITTER_CAPACITY_BYTES / packet_payload_bytes;
    const uint32_t jitter_packets = std::min(jitter_packets_by_time, jitter_packets_by_bytes);

    const size_t caller_size = out_plan->struct_size;
    std::memset(out_plan, 0, sizeof(gm_audio_timing_plan));
    out_plan->struct_size = caller_size;
    out_plan->abi_version = GM_ABI_VERSION;
    out_plan->packet_interval_us = packet_interval_us;
    out_plan->frames_per_packet = profile->frames_per_packet;
    out_plan->playout_target_ms = playout_target_ms;
    out_plan->playout_target_frames = frames_for_milliseconds(playout_target_ms);
    out_plan->jitter_capacity_packets = jitter_packets;
    out_plan->jitter_capacity_bytes = jitter_packets * packet_payload_bytes;
    out_plan->lookbehind_frames = frames_for_milliseconds(GM_MEDIA_LOOKBEHIND_MS);
    out_plan->lookahead_frames = frames_for_milliseconds(GM_MEDIA_LOOKAHEAD_MS);
    out_plan->bridge_capacity_frames = frames_for_milliseconds(GM_BRIDGE_CAPACITY_MS);
    out_plan->bridge_freshness_frames = frames_for_milliseconds(GM_BRIDGE_FRESHNESS_MS);
    out_plan->send_capacity_frames = frames_for_milliseconds(GM_SEND_CAPACITY_MS);
    out_plan->send_freshness_frames = frames_for_milliseconds(GM_SEND_FRESHNESS_MS);
    return GM_OK;
}