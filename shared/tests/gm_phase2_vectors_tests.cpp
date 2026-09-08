#include <ghostmedia/gm_core.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <fstream>
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

void check_status(gm_status actual, gm_status expected, const char *message) {
    if (actual != expected) {
        std::cerr << "FAIL: " << message << " expected " << gm_status_string(expected)
                  << " got " << gm_status_string(actual) << '\n';
        ++failures;
    }
}

uint8_t hex_nibble(char character) {
    if (character >= '0' && character <= '9') {
        return static_cast<uint8_t>(character - '0');
    }
    if (character >= 'a' && character <= 'f') {
        return static_cast<uint8_t>(character - 'a' + 10);
    }
    if (character >= 'A' && character <= 'F') {
        return static_cast<uint8_t>(character - 'A' + 10);
    }
    check(false, "hex fixture contains invalid character");
    return 0u;
}

std::vector<uint8_t> bytes_from_hex(std::string_view hex) {
    check(hex.size() % 2u == 0u, "hex fixture has even length");
    std::vector<uint8_t> bytes(hex.size() / 2u);
    for (size_t index = 0; index < bytes.size(); ++index) {
        bytes[index] = static_cast<uint8_t>((hex_nibble(hex[index * 2u]) << 4u) |
                                            hex_nibble(hex[index * 2u + 1u]));
    }
    return bytes;
}

std::string hex_from_bytes(const uint8_t *data, size_t size) {
    constexpr char digits[] = "0123456789abcdef";
    std::string hex;
    hex.reserve(size * 2u);
    for (size_t index = 0; index < size; ++index) {
        hex.push_back(digits[(data[index] >> 4u) & 0x0fu]);
        hex.push_back(digits[data[index] & 0x0fu]);
    }
    return hex;
}

gm_bytes bytes_view(const std::vector<uint8_t> &bytes) {
    return gm_bytes{bytes.data(), bytes.size()};
}

gm_bytes bytes_from_cstr(const char *text) {
    return gm_bytes{reinterpret_cast<const uint8_t *>(text), std::strlen(text)};
}

template <size_t Size>
void copy_bytes(uint8_t (&destination)[Size], const std::vector<uint8_t> &source) {
    check(source.size() == Size, "fixture length matches destination");
    std::memcpy(destination, source.data(), Size);
}

void set_alpn(gm_tls_peer_policy_observation &observation, std::string_view alpn) {
    std::memset(observation.alpn, 0, sizeof(observation.alpn));
    const size_t copy_size = alpn.size() < sizeof(observation.alpn) - 1u ? alpn.size() : sizeof(observation.alpn) - 1u;
    std::memcpy(observation.alpn, alpn.data(), copy_size);
}

void set_c_string(char *destination, size_t destination_size, std::string_view source) {
    std::memset(destination, 0, destination_size);
    const size_t copy_size = source.size() < destination_size - 1u ? source.size() : destination_size - 1u;
    std::memcpy(destination, source.data(), copy_size);
}

gm_status ingest(gm_control_session &session, const char *json, uint64_t now_ns, gm_control_action &action) {
    action.struct_size = sizeof(action);
    return gm_control_session_ingest(&session, bytes_from_cstr(json), now_ns, &action);
}

gm_crypto_exporter_context_input exporter_context_input(uint32_t direction) {
    const std::vector<uint8_t> session_id = bytes_from_hex("00112233445566778899aabbccddeeff");
    const std::vector<uint8_t> windows_spki = bytes_from_hex(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    );
    const std::vector<uint8_t> apple_spki = bytes_from_hex(
        "f0efeeedecebeae9e8e7e6e5e4e3e2e1e0dfdedddcdbdad9d8d7d6d5d4d3d2d1"
    );

    gm_crypto_exporter_context_input input{};
    input.struct_size = sizeof(input);
    input.abi_version = GM_ABI_VERSION;
    input.stream_id = 1u;
    input.direction = direction;
    input.key_epoch = 1u;
    copy_bytes(input.session_id, session_id);
    if (direction == GM_MEDIA_DIRECTION_WIN_TO_APPLE) {
        copy_bytes(input.sender_spki_digest, windows_spki);
        copy_bytes(input.receiver_spki_digest, apple_spki);
    } else {
        copy_bytes(input.sender_spki_digest, apple_spki);
        copy_bytes(input.receiver_spki_digest, windows_spki);
    }
    return input;
}

gm_tls_peer_policy_observation valid_policy_observation() {
    gm_tls_peer_policy_observation observation{};
    observation.struct_size = sizeof(observation);
    observation.abi_version = GM_ABI_VERSION;
    observation.tls_version = GM_TLS_VERSION_1_3;
    observation.peer_certificate_count = 1u;
    observation.leaf_der_size = 512u;
    set_alpn(observation, "ghostmedia/1");
    observation.leaf_self_signed = 1u;
    observation.public_key_ed25519 = 1u;
    observation.signature_ed25519 = 1u;
    observation.basic_constraints_ca = 0u;
    observation.key_usage_digital_signature = 1u;
    observation.eku_client_auth = 1u;
    observation.eku_server_auth = 1u;
    observation.unknown_critical_extension = 0u;
    observation.within_validity = 1u;
    observation.local_clock_trusted = 1u;
    observation.system_trust_used = 0u;
    observation.public_ca_path_used = 0u;
    observation.psk_or_ticket_used = 0u;
    observation.early_data_used = 0u;
    observation.compression_used = 0u;
    observation.renegotiation_used = 0u;
    observation.trust_record_connect = 1u;
    observation.trust_record_revoked = 0u;
    return observation;
}

void test_identity_and_trust_vectors() {
    const std::vector<uint8_t> windows_spki = bytes_from_hex(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    );
    const std::vector<uint8_t> apple_spki = bytes_from_hex(
        "f0efeeedecebeae9e8e7e6e5e4e3e2e1e0dfdedddcdbdad9d8d7d6d5d4d3d2d1"
    );
    std::array<uint8_t, GM_PEER_ID_BASE32_BYTES + 1u> peer_id{};
    size_t written = 0u;

    check_status(gm_identity_encode_peer_id(bytes_view(windows_spki), gm_mut_bytes{peer_id.data(), peer_id.size()}, &written),
                 GM_OK, "Windows SPKI digest encodes as peer ID");
    check(written == GM_PEER_ID_BASE32_BYTES + 1u,
          "peer ID encoder reports capacity including terminator");
    check(std::strcmp(reinterpret_cast<const char *>(peer_id.data()),
                      "aaaqeayeaudaocajbifqydiob4ibceqtcqkrmfyydenbwha5dypq") == 0,
          "Windows peer ID matches locked vector");

    check_status(gm_identity_encode_peer_id(bytes_view(apple_spki), gm_mut_bytes{peer_id.data(), peer_id.size()}, &written),
                 GM_OK, "Apple SPKI digest encodes as peer ID");
    check(std::strcmp(reinterpret_cast<const char *>(peer_id.data()),
                      "6dx653pm5pvot2hh43s6jy7c4hqn7xw53tn5vwoy27lnlvgt2liq") == 0,
          "Apple peer ID matches locked vector");

    gm_trust_record trust{};
    trust.struct_size = sizeof(trust);
    trust.abi_version = GM_ABI_VERSION;
    copy_bytes(trust.peer_spki_digest, windows_spki);
    trust.permissions = GM_TRUST_PERMISSION_CONNECT | GM_TRUST_PERMISSION_VIEW_STATUS;
    uint8_t authorized = 0u;
    check_status(gm_trust_record_authorizes(&trust, GM_TRUST_PERMISSION_CONNECT, &authorized), GM_OK,
                 "connect trust check succeeds");
    check(authorized == 1u, "connect permission is authorized");
    check_status(gm_trust_record_authorizes(&trust, GM_TRUST_PERMISSION_RECEIVE_SYSTEM_AUDIO, &authorized), GM_OK,
                 "missing stream permission check succeeds");
    check(authorized == 0u, "missing stream permission is denied");
    trust.revoked = 1u;
    check_status(gm_trust_record_authorizes(&trust, GM_TRUST_PERMISSION_CONNECT, &authorized), GM_OK,
                 "revoked trust check succeeds");
    check(authorized == 0u, "revoked trust denies connect");
}

void test_tls_policy_vectors() {
    gm_tls_peer_policy_observation observation = valid_policy_observation();
    check_status(gm_tls_peer_policy_validate(&observation), GM_OK,
                 "valid TLS policy observation is accepted");

    observation = valid_policy_observation();
    set_alpn(observation, "http/1.1");
    check_status(gm_tls_peer_policy_validate(&observation), GM_BAD_MESSAGE,
                 "ALPN mismatch is rejected");

    observation = valid_policy_observation();
    observation.peer_certificate_count = 2u;
    check_status(gm_tls_peer_policy_validate(&observation), GM_BAD_MESSAGE,
                 "additional peer certificates are rejected");

    observation = valid_policy_observation();
    observation.system_trust_used = 1u;
    check_status(gm_tls_peer_policy_validate(&observation), GM_BAD_MESSAGE,
                 "system trust fallback is rejected");

    observation = valid_policy_observation();
    observation.trust_record_connect = 0u;
    check_status(gm_tls_peer_policy_validate(&observation), GM_UNAUTHORIZED,
                 "missing connect trust is unauthorized");

    observation = valid_policy_observation();
    observation.trust_record_revoked = 1u;
    check_status(gm_tls_peer_policy_validate(&observation), GM_UNAUTHORIZED,
                 "revoked trust is unauthorized");
}

void test_exporter_context_and_key_vectors() {
    std::array<uint8_t, GM_TLS_EXPORTER_CONTEXT_BYTES> context{};
    size_t written = 0u;
    gm_crypto_exporter_context_input input = exporter_context_input(GM_MEDIA_DIRECTION_WIN_TO_APPLE);
    check_status(gm_crypto_build_exporter_context(&input, gm_mut_bytes{context.data(), context.size()}, &written), GM_OK,
                 "Windows-to-Apple exporter context builds");
    check(written == GM_TLS_EXPORTER_CONTEXT_BYTES, "exporter context reports exact size");
    check(hex_from_bytes(context.data(), context.size()) ==
              "eae82ef20c131d0f5b03bb069b25d92b1d594ed041c02a8f474367c682087a02",
          "Windows-to-Apple exporter context matches locked vector");

    input = exporter_context_input(GM_MEDIA_DIRECTION_APPLE_TO_WIN);
    check_status(gm_crypto_build_exporter_context(&input, gm_mut_bytes{context.data(), context.size()}, &written), GM_OK,
                 "Apple-to-Windows exporter context builds");
    check(hex_from_bytes(context.data(), context.size()) ==
              "3b03b2e0f4278c33de868e66f688c0047b1ec901fe72725cad2a39b638d090a7",
          "Apple-to-Windows exporter context matches locked vector");

    input.direction = 9u;
    check_status(gm_crypto_build_exporter_context(&input, gm_mut_bytes{context.data(), context.size()}, &written),
                 GM_BAD_MESSAGE, "invalid exporter direction is rejected");

    const std::vector<uint8_t> exporter_output = bytes_from_hex(
        "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
        "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
    );
    gm_directional_keys keys{};
    keys.struct_size = sizeof(keys);
    check_status(gm_crypto_split_exporter_output(bytes_view(exporter_output), &keys), GM_OK,
                 "64-byte TLS exporter output splits into media/path keys");
    check(keys.media_key[0] == 0xa0u && keys.media_key[31] == 0xbfu && keys.path_key[0] == 0xc0u &&
              keys.path_key[31] == 0xdfu,
          "directional keys match locked split");

    std::vector<uint8_t> short_exporter = bytes_from_hex("a0a1");
    keys.struct_size = sizeof(keys);
    check_status(gm_crypto_split_exporter_output(bytes_view(short_exporter), &keys), GM_BAD_MESSAGE,
                 "short TLS exporter output is rejected");
}

void test_aad_and_aead_boundary_vectors() {
    const std::vector<uint8_t> session_id = bytes_from_hex("00112233445566778899aabbccddeeff");
    gm_media_header header{};
    header.struct_size = sizeof(header);
    header.abi_version = GM_ABI_VERSION;
    header.kind = GM_MEDIA_KIND_AUDIO;
    copy_bytes(header.session_id, session_id);
    header.stream_id = 1u;
    header.direction = GM_MEDIA_DIRECTION_WIN_TO_APPLE;
    header.key_epoch = 1u;
    header.sequence = 0x0102030405060708ull;
    header.media_timestamp = 240u;
    header.payload_length = GM_AUDIO_PCM_S16LE_PAYLOAD_BYTES;

    std::array<uint8_t, GM_MEDIA_HEADER_BYTES> aad{};
    size_t written = 0u;
    check_status(gm_media_build_aad(&header, gm_mut_bytes{aad.data(), aad.size()}, &written), GM_OK,
                 "media AAD builds from canonical header");
    check(written == GM_MEDIA_HEADER_BYTES, "media AAD reports header size");
    check(hex_from_bytes(aad.data(), aad.size()) ==
              "474d41310101000000112233445566778899aabbccddeeff0000000101000000"
              "00000001010203040506070800000000000000f0000003c00000000000000000",
          "media AAD matches locked header vector");

    std::array<uint8_t, GM_CRYPTO_KEY_BYTES> key{};
    std::array<uint8_t, GM_MEDIA_NONCE_BYTES> nonce{};
    std::array<uint8_t, 12> payload{};
    std::array<uint8_t, GM_MEDIA_TAG_BYTES> tag{};
    check_status(gm_crypto_validate_aead_inputs(gm_bytes{key.data(), key.size()}, gm_bytes{nonce.data(), nonce.size()},
                                                gm_bytes{aad.data(), aad.size()}, gm_bytes{payload.data(), payload.size()},
                                                gm_bytes{tag.data(), tag.size()}),
                 GM_OK, "valid AEAD boundary sizes are accepted");
    check_status(gm_crypto_validate_aead_inputs(gm_bytes{nullptr, key.size()}, gm_bytes{nonce.data(), nonce.size()},
                                                gm_bytes{aad.data(), aad.size()}, gm_bytes{payload.data(), payload.size()},
                                                gm_bytes{tag.data(), tag.size()}),
                 GM_BAD_ARGUMENT, "missing nonempty key buffer is rejected");
    check_status(gm_crypto_validate_aead_inputs(gm_bytes{key.data(), key.size()}, gm_bytes{nonce.data(), nonce.size()},
                                                gm_bytes{aad.data(), aad.size()}, gm_bytes{payload.data(), payload.size()},
                                                gm_bytes{tag.data(), tag.size() - 1u}),
                 GM_BAD_MESSAGE, "wrong tag length is rejected");
    std::vector<uint8_t> oversized_payload(GM_MEDIA_MAX_PAYLOAD_BYTES + 1u);
    check_status(gm_crypto_validate_aead_inputs(gm_bytes{key.data(), key.size()}, gm_bytes{nonce.data(), nonce.size()},
                                                gm_bytes{aad.data(), aad.size()}, bytes_view(oversized_payload),
                                                gm_bytes{tag.data(), tag.size()}),
                 GM_BAD_MESSAGE, "oversized AEAD payload is rejected");
}

        void test_replay_and_rekey_vectors() {
            gm_replay_window replay_window{};
            replay_window.struct_size = sizeof(replay_window);
            uint32_t replay_result = 0u;
            check_status(gm_replay_window_init(&replay_window), GM_OK,
                   "replay vector window initializes");
            check_status(gm_replay_window_accept(&replay_window, 2000u, &replay_result), GM_OK,
                   "replay vector first sequence checks");
            check(replay_result == GM_REPLAY_ACCEPTED, "replay vector first sequence is accepted");
            check_status(gm_replay_window_accept(&replay_window, 2000u, &replay_result), GM_OK,
                   "replay vector duplicate checks");
            check(replay_result == GM_REPLAY_DUPLICATE, "replay vector duplicate is reported");
            check_status(gm_replay_window_accept(&replay_window, 977u, &replay_result), GM_OK,
                   "replay vector lower window edge checks");
            check(replay_result == GM_REPLAY_ACCEPTED, "replay vector sequence 1023 behind is accepted once");
            check_status(gm_replay_window_accept(&replay_window, 976u, &replay_result), GM_OK,
                   "replay vector too-old edge checks");
            check(replay_result == GM_REPLAY_TOO_OLD, "replay vector sequence 1024 behind is too old");

                 gm_epoch_window epoch_window{};
                 epoch_window.struct_size = sizeof(epoch_window);
                 uint32_t epoch_acceptance = GM_EPOCH_REJECTED;
                 check_status(gm_epoch_window_init(&epoch_window, 1u), GM_OK,
                     "epoch vector window initializes");
                 check_status(gm_epoch_window_accept(&epoch_window, 1u, 1000u, &epoch_acceptance), GM_OK,
                     "epoch vector accepts initial epoch check");
                 check(epoch_acceptance == GM_EPOCH_CURRENT, "epoch vector accepts current epoch");
                 check_status(gm_epoch_window_begin_rekey(&epoch_window, 2u, 1'000'000'000u), GM_OK,
                     "epoch vector begins exact next epoch rekey");
                 check_status(gm_epoch_window_accept(&epoch_window, 2u, 1'000'000'001u, &epoch_acceptance), GM_OK,
                     "epoch vector accepts new epoch check");
                 check(epoch_acceptance == GM_EPOCH_CURRENT, "epoch vector accepts new current epoch");
                 check_status(gm_epoch_window_accept(&epoch_window, 1u, 6'000'000'000u, &epoch_acceptance), GM_OK,
                     "epoch vector accepts previous epoch at grace boundary check");
                 check(epoch_acceptance == GM_EPOCH_PREVIOUS_GRACE, "epoch vector accepts previous epoch at grace boundary");
                 check_status(gm_epoch_window_accept(&epoch_window, 1u, 6'000'000'001u, &epoch_acceptance), GM_OK,
                     "epoch vector rejects previous epoch after grace check");
                 check(epoch_acceptance == GM_EPOCH_REJECTED, "epoch vector rejects previous epoch after grace");
                 check_status(gm_epoch_window_begin_rekey(&epoch_window, 4u, 7'000'000'000u), GM_BAD_MESSAGE,
                     "epoch vector rejects skipped epoch rekey");

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

            gm_control_session session{};
            session.struct_size = sizeof(session);
            gm_control_action action{};
            action.struct_size = sizeof(action);
            check_status(gm_control_session_init(&config, &session), GM_OK,
                   "rekey vector session initializes after TLS readiness");
            check_status(ingest(session,
                       "{\"v\":1,\"id\":1,\"type\":\"session.hello\",\"role\":\"win-client\","
                       "\"client_name\":\"phase2 vectors\",\"versions\":[1],\"udp_port\":49152}",
                       1000u, action),
                   GM_OK, "rekey vector accepts hello");
            check_status(ingest(session,
                       "{\"v\":1,\"id\":2,\"type\":\"transport.bind\","
                       "\"session_id\":\"00112233445566778899aabbccddeeff\",\"udp_port\":49152}",
                       2000u, action),
                   GM_OK, "rekey vector accepts bind");
            check_status(ingest(session,
                       "{\"v\":1,\"id\":3,\"type\":\"stream.open\",\"kind\":\"audio\","
                       "\"direction\":\"win_to_apple\",\"profile\":{\"codec\":\"pcm_s16le\","
                       "\"sample_rate_hz\":48000,\"channels\":2,\"channel_layout\":\"stereo\","
                       "\"frames_per_packet\":240},\"playout_target_ms\":30}",
                       3000u, action),
                   GM_OK, "rekey vector accepts stream open");
            check_status(gm_control_session_mark_path_validated(&session, 1u, 1u, &action), GM_OK,
                   "rekey vector validates epoch 1 path");
            check_status(ingest(session,
                       "{\"v\":1,\"id\":4,\"type\":\"stream.start\",\"stream_id\":1,"
                       "\"first_media_timestamp\":\"240\"}",
                       4000u, action),
                   GM_OK, "rekey vector starts stream");
            check_status(ingest(session,
                       "{\"v\":1,\"id\":5,\"type\":\"stream.rekey\",\"stream_id\":1,\"key_epoch\":2}",
                       5000u, action),
                   GM_OK, "rekey vector commits next epoch");
            check(session.key_epoch == 2u && session.path_validated == 0u && session.rekeys_committed == 1u,
               "rekey vector resets path validation for the new epoch");
            check_status(gm_control_session_mark_path_validated(&session, 1u, 1u, &action), GM_STATE_CONFLICT,
                   "rekey vector rejects stale epoch path validation");
            check_status(gm_control_session_mark_path_validated(&session, 1u, 2u, &action), GM_OK,
                   "rekey vector accepts current epoch path validation");
        }

void test_vector_file_is_locked() {
#ifndef GM_PHASE2_VECTOR_FILE
    check(false, "GM_PHASE2_VECTOR_FILE compile definition is present");
#else
    std::ifstream vector_file(GM_PHASE2_VECTOR_FILE);
    check(vector_file.good(), "Phase 2 vector file opens");
    const std::string contents((std::istreambuf_iterator<char>(vector_file)), std::istreambuf_iterator<char>());
    check(contents.find("EXPORTER-GhostMedia-v1") != std::string::npos, "vector file contains exporter label");
    check(contents.find("aaaqeayeaudaocajbifqydiob4ibceqtcqkrmfyydenbwha5dypq") != std::string::npos,
          "vector file contains Windows peer ID");
    check(contents.find("eae82ef20c131d0f5b03bb069b25d92b1d594ed041c02a8f474367c682087a02") != std::string::npos,
          "vector file contains Windows-to-Apple exporter context");
    check(contents.find("3b03b2e0f4278c33de868e66f688c0047b1ec901fe72725cad2a39b638d090a7") != std::string::npos,
          "vector file contains Apple-to-Windows exporter context");
    check(contents.find("474d41310101000000112233445566778899aabbccddeeff0000000101000000") != std::string::npos,
          "vector file contains media AAD prefix");
        check(contents.find("\"highest_sequence\": \"2000\"") != std::string::npos,
            "vector file contains replay edge fixture");
        check(contents.find("\"new_key_epoch\": 2") != std::string::npos,
            "vector file contains rekey fixture");
        check(contents.find("\"previous_epoch_grace_acceptance\": \"GM_EPOCH_PREVIOUS_GRACE\"") != std::string::npos,
            "vector file contains epoch grace fixture");
#endif
}
}

int main() {
    check(std::strcmp(gm_tls_exporter_label(), "EXPORTER-GhostMedia-v1") == 0,
          "exporter label matches v1 spec");
    test_identity_and_trust_vectors();
    test_tls_policy_vectors();
    test_exporter_context_and_key_vectors();
    test_aad_and_aead_boundary_vectors();
    test_replay_and_rekey_vectors();
    test_vector_file_is_locked();

    if (failures != 0) {
        std::cerr << failures << " failure(s)\n";
        return 1;
    }
    return 0;
}