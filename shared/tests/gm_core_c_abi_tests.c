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
    for (size_t index = 0u; index < GM_SESSION_ID_BYTES; ++index) {
        header.session_id[index] = (uint8_t)(index * 0x11u);
    }
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

        check(strcmp(gm_tls_exporter_label(), "EXPORTER-GhostMedia-v1") == 0,
            "TLS exporter label is available from C");

        uint8_t windows_spki[GM_SPKI_DIGEST_BYTES];
        uint8_t apple_spki[GM_SPKI_DIGEST_BYTES];
        for (size_t index = 0u; index < GM_SPKI_DIGEST_BYTES; ++index) {
          windows_spki[index] = (uint8_t)index;
          apple_spki[index] = (uint8_t)(0xf0u - index);
        }
        uint8_t peer_id[GM_PEER_ID_BASE32_BYTES + 1u];
        gm_bytes windows_spki_bytes;
        windows_spki_bytes.data = windows_spki;
        windows_spki_bytes.size = sizeof(windows_spki);
        output.data = peer_id;
        output.size = sizeof(peer_id);
        check_status(gm_identity_encode_peer_id(windows_spki_bytes, output, &written), GM_OK,
                 "peer ID encoder works from C");
        check(strcmp((const char *)peer_id, "aaaqeayeaudaocajbifqydiob4ibceqtcqkrmfyydenbwha5dypq") == 0,
            "peer ID vector is available from C");

        gm_trust_record trust;
        memset(&trust, 0, sizeof(trust));
        trust.struct_size = sizeof(trust);
        trust.abi_version = GM_ABI_VERSION;
        memcpy(trust.peer_spki_digest, windows_spki, sizeof(windows_spki));
        trust.permissions = GM_TRUST_PERMISSION_CONNECT;
        uint8_t authorized = 0u;
        check_status(gm_trust_record_authorizes(&trust, GM_TRUST_PERMISSION_CONNECT, &authorized), GM_OK,
                 "trust record authorization works from C");
        check(authorized == 1u, "trust record grants connect from C");

        gm_tls_peer_policy_observation observation;
        memset(&observation, 0, sizeof(observation));
        observation.struct_size = sizeof(observation);
        observation.abi_version = GM_ABI_VERSION;
        observation.tls_version = GM_TLS_VERSION_1_3;
        observation.peer_certificate_count = 1u;
        observation.leaf_der_size = 512u;
        set_c_string(observation.alpn, sizeof(observation.alpn), "ghostmedia/1");
        observation.leaf_self_signed = 1u;
        observation.public_key_ed25519 = 1u;
        observation.signature_ed25519 = 1u;
        observation.key_usage_digital_signature = 1u;
        observation.eku_client_auth = 1u;
        observation.eku_server_auth = 1u;
        observation.within_validity = 1u;
        observation.local_clock_trusted = 1u;
        observation.trust_record_connect = 1u;
        check_status(gm_tls_peer_policy_validate(&observation), GM_OK,
                 "TLS peer policy validates from C");

        gm_crypto_exporter_context_input context_input;
        uint8_t exporter_context[GM_TLS_EXPORTER_CONTEXT_BYTES];
        memset(&context_input, 0, sizeof(context_input));
        memset(exporter_context, 0, sizeof(exporter_context));
        context_input.struct_size = sizeof(context_input);
        context_input.abi_version = GM_ABI_VERSION;
        context_input.stream_id = 1u;
        context_input.direction = GM_MEDIA_DIRECTION_WIN_TO_APPLE;
        context_input.key_epoch = 1u;
        memcpy(context_input.session_id, header.session_id, sizeof(context_input.session_id));
        memcpy(context_input.sender_spki_digest, windows_spki, sizeof(windows_spki));
        memcpy(context_input.receiver_spki_digest, apple_spki, sizeof(apple_spki));
        output.data = exporter_context;
        output.size = sizeof(exporter_context);
        check_status(gm_crypto_build_exporter_context(&context_input, output, &written), GM_OK,
                 "TLS exporter context builds from C");
        check(exporter_context[0] == 0xea && exporter_context[31] == 0x02,
            "TLS exporter context vector is available from C");

        uint8_t exporter_output[GM_TLS_EXPORTER_OUTPUT_BYTES];
        for (size_t index = 0u; index < sizeof(exporter_output); ++index) {
          exporter_output[index] = (uint8_t)(0xa0u + index);
        }
        gm_directional_keys keys;
        gm_bytes exporter_bytes;
        memset(&keys, 0, sizeof(keys));
        keys.struct_size = sizeof(keys);
        exporter_bytes.data = exporter_output;
        exporter_bytes.size = sizeof(exporter_output);
        check_status(gm_crypto_split_exporter_output(exporter_bytes, &keys), GM_OK,
                 "TLS exporter output split works from C");
        check(keys.media_key[0] == 0xa0u && keys.path_key[0] == 0xc0u,
            "directional key split is available from C");

        check_status(gm_media_build_aad(&header, output, &written), GM_BUFFER_TOO_SMALL,
                 "AAD builder rejects wrong output buffer from C");
        output.data = encoded;
        output.size = sizeof(encoded);
        check_status(gm_media_build_aad(&header, output, &written), GM_OK,
                 "AAD builder works from C");
        gm_bytes key_bytes;
        gm_bytes nonce_bytes;
        gm_bytes aad_bytes;
        gm_bytes payload_bytes;
        gm_bytes tag_bytes;
        uint8_t key[GM_CRYPTO_KEY_BYTES] = {0};
        uint8_t nonce[GM_MEDIA_NONCE_BYTES] = {0};
        uint8_t tag[GM_MEDIA_TAG_BYTES] = {0};
        key_bytes.data = key;
        key_bytes.size = sizeof(key);
        nonce_bytes.data = nonce;
        nonce_bytes.size = sizeof(nonce);
        aad_bytes.data = encoded;
        aad_bytes.size = sizeof(encoded);
        payload_bytes.data = NULL;
        payload_bytes.size = 0u;
        tag_bytes.data = tag;
        tag_bytes.size = sizeof(tag);
        check_status(gm_crypto_validate_aead_inputs(key_bytes, nonce_bytes, aad_bytes, payload_bytes, tag_bytes), GM_OK,
                 "AEAD input boundary validates from C");

        gm_epoch_window epoch_window;
        uint32_t epoch_acceptance = GM_EPOCH_REJECTED;
        memset(&epoch_window, 0, sizeof(epoch_window));
        epoch_window.struct_size = sizeof(epoch_window);
        check_status(gm_epoch_window_init(&epoch_window, 1u), GM_OK,
                 "epoch window initializes from C");
        check_status(gm_epoch_window_begin_rekey(&epoch_window, 2u, 1000u), GM_OK,
                 "epoch window begins rekey from C");
        check_status(gm_epoch_window_accept(&epoch_window, 1u, 1000u + ((uint64_t)GM_REKEY_GRACE_MS * 1000u * 1000u),
                                            &epoch_acceptance),
                 GM_OK, "epoch window accepts previous epoch at grace boundary from C");
        check(epoch_acceptance == GM_EPOCH_PREVIOUS_GRACE,
            "epoch window reports previous-epoch grace from C");
        check_status(gm_epoch_window_accept(&epoch_window, 1u, 1000u + ((uint64_t)GM_REKEY_GRACE_MS * 1000u * 1000u) + 1u,
                                            &epoch_acceptance),
                 GM_OK, "epoch window rejects expired previous epoch from C");
        check(epoch_acceptance == GM_EPOCH_REJECTED,
            "epoch window reports expired previous epoch from C");

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