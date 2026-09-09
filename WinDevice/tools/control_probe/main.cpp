#include <ghostmedia/gm_core.h>
#include <ghostmedia/gm_runtime.h>

#include <array>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace {
constexpr uint16_t kDefaultUdpPort = 49152u;
constexpr uint16_t kDefaultPlayoutTargetMs = 30u;
constexpr uint32_t kDefaultReceiveTimeoutMs = 5000u;
constexpr uint32_t kPhase3PacketCount = 8u;

constexpr std::array<uint8_t, 32> kPhase3WindowsPrivateKey{
    0x01, 0x72, 0x65, 0x9f, 0x44, 0x3a, 0x8c, 0xd1,
    0x20, 0x6e, 0x55, 0x11, 0x93, 0x27, 0xba, 0x6f,
    0x32, 0xe8, 0x09, 0x4c, 0xa1, 0x7d, 0xf0, 0x58,
    0x6b, 0xc3, 0x16, 0x84, 0x2d, 0x97, 0x3e, 0xfa,
};
constexpr std::array<uint8_t, 32> kPhase3ApplePrivateKey{
    0xa2, 0x8b, 0x45, 0x19, 0xde, 0x70, 0x36, 0xc4,
    0x5f, 0x0d, 0x91, 0x2a, 0x68, 0xb7, 0xe3, 0x54,
    0x9c, 0x21, 0xf6, 0x80, 0x3b, 0xad, 0x47, 0xd2,
    0x75, 0x0e, 0x6a, 0x98, 0xc5, 0x14, 0xbf, 0x62,
};

struct Options {
    bool dry_run = false;
    bool show_help = false;
    bool allow_plaintext = false;
    bool phase3_test = false;
    std::string host;
    uint16_t port = 0u;
    uint16_t udp_port = kDefaultUdpPort;
    uint16_t playout_target_ms = kDefaultPlayoutTargetMs;
    std::string client_name = "GhostMedia Windows Probe";
    std::string expected_server_id;
};

struct ReceivedMessage {
    std::string json;
    gm_control_message_info info;
};

class SocketHandle {
public:
    explicit SocketHandle(gm_runtime_tcp_socket *socket_handle = nullptr)
        : socket_handle_(socket_handle) {}

    SocketHandle(const SocketHandle &) = delete;
    SocketHandle &operator=(const SocketHandle &) = delete;

    SocketHandle(SocketHandle &&other) noexcept : socket_handle_(other.socket_handle_) {
        other.socket_handle_ = nullptr;
    }

    SocketHandle &operator=(SocketHandle &&other) noexcept {
        if (this != &other) {
            close();
            socket_handle_ = other.socket_handle_;
            other.socket_handle_ = nullptr;
        }
        return *this;
    }

    ~SocketHandle() {
        close();
    }

    gm_runtime_tcp_socket *get() const {
        return socket_handle_;
    }

    bool valid() const {
        return socket_handle_ != nullptr;
    }

private:
    void close() {
        if (socket_handle_ != nullptr) {
            gm_runtime_tcp_socket_destroy(socket_handle_);
            socket_handle_ = nullptr;
        }
    }

    gm_runtime_tcp_socket *socket_handle_;
};

class IdentityHandle {
public:
    explicit IdentityHandle(gm_runtime_identity *identity = nullptr) : identity_(identity) {}
    IdentityHandle(const IdentityHandle &) = delete;
    IdentityHandle &operator=(const IdentityHandle &) = delete;
    IdentityHandle(IdentityHandle &&other) noexcept : identity_(other.identity_) { other.identity_ = nullptr; }
    ~IdentityHandle() { if (identity_ != nullptr) { gm_runtime_identity_destroy(identity_); } }
    gm_runtime_identity *get() const { return identity_; }
private:
    gm_runtime_identity *identity_;
};

class TlsHandle {
public:
    explicit TlsHandle(gm_runtime_tls_session *session = nullptr) : session_(session) {}
    TlsHandle(const TlsHandle &) = delete;
    TlsHandle &operator=(const TlsHandle &) = delete;
    TlsHandle(TlsHandle &&other) noexcept : session_(other.session_) { other.session_ = nullptr; }
    ~TlsHandle() { if (session_ != nullptr) { gm_runtime_tls_session_destroy(session_); } }
    gm_runtime_tls_session *get() const { return session_; }
private:
    gm_runtime_tls_session *session_;
};

class UdpHandle {
public:
    explicit UdpHandle(gm_runtime_udp_socket *socket = nullptr) : socket_(socket) {}
    UdpHandle(const UdpHandle &) = delete;
    UdpHandle &operator=(const UdpHandle &) = delete;
    UdpHandle(UdpHandle &&other) noexcept : socket_(other.socket_) { other.socket_ = nullptr; }
    ~UdpHandle() { if (socket_ != nullptr) { gm_runtime_udp_socket_destroy(socket_); } }
    gm_runtime_udp_socket *get() const { return socket_; }
private:
    gm_runtime_udp_socket *socket_;
};

struct ControlConnection {
    gm_runtime_tcp_socket *socket = nullptr;
    gm_runtime_tls_session *tls = nullptr;
};

[[noreturn]] void fail_with_usage(const std::string &message);

void print_usage(std::ostream &output) {
    output << "GhostMediaWinControlProbe\n"
           << "  --dry-run\n"
           << "      Validate the scripted Windows-side hello/bind/open flow locally.\n"
           << "  --connect <host> <port> --allow-plaintext [options]\n"
           << "      Run the same framed-control flow against a Mac CLI harness.\n\n"
           << "  --connect <host> <port> --phase3-test [options]\n"
           << "      Run the pinned-TLS and protected-UDP Phase 3 test fixture.\n\n"
           << "Options:\n"
           << "  --udp-port <1..65535>             Windows prebound UDP port fixture.\n"
           << "  --playout-target-ms <15..120>     stream.open playout target.\n"
           << "  --client-name <text>              session.hello client name.\n\n"
           << "  --expect-server-id <uuid>         reject mismatched Apple server_id.\n\n"
           << "--allow-plaintext is only for the first control-framing interop test.\n"
           << "--phase3-test uses pinned mutual TLS and protected UDP test fixtures.\n";
}

bool parse_u16(std::string_view text, uint16_t minimum, uint16_t maximum, uint16_t *out_value) {
    if (text.empty() || out_value == nullptr) {
        return false;
    }

    uint32_t parsed_value = 0u;
    for (const char character : text) {
        if (character < '0' || character > '9') {
            return false;
        }
        parsed_value = parsed_value * 10u + static_cast<uint32_t>(character - '0');
        if (parsed_value > maximum) {
            return false;
        }
    }

    if (parsed_value < minimum) {
        return false;
    }
    *out_value = static_cast<uint16_t>(parsed_value);
    return true;
}

Options parse_options(int argument_count, char **arguments) {
    Options options{};
    for (int argument_index = 1; argument_index < argument_count; ++argument_index) {
        const std::string_view argument = arguments[argument_index];
        if (argument == "--help" || argument == "-h") {
            options.show_help = true;
        } else if (argument == "--dry-run") {
            options.dry_run = true;
        } else if (argument == "--allow-plaintext") {
            options.allow_plaintext = true;
        } else if (argument == "--phase3-test") {
            options.phase3_test = true;
        } else if (argument == "--connect") {
            if (argument_index + 2 >= argument_count) {
                fail_with_usage("--connect requires <host> <port>");
            }
            options.host = arguments[++argument_index];
            if (!parse_u16(arguments[++argument_index], 1u, 65535u, &options.port)) {
                fail_with_usage("invalid --connect port");
            }
        } else if (argument == "--udp-port") {
            if (argument_index + 1 >= argument_count ||
                !parse_u16(arguments[++argument_index], 1u, 65535u, &options.udp_port)) {
                fail_with_usage("invalid --udp-port value");
            }
        } else if (argument == "--playout-target-ms") {
            if (argument_index + 1 >= argument_count ||
                !parse_u16(arguments[++argument_index], 15u, 120u, &options.playout_target_ms)) {
                fail_with_usage("invalid --playout-target-ms value");
            }
        } else if (argument == "--client-name") {
            if (argument_index + 1 >= argument_count) {
                fail_with_usage("--client-name requires text");
            }
            options.client_name = arguments[++argument_index];
        } else if (argument == "--expect-server-id") {
            if (argument_index + 1 >= argument_count) {
                fail_with_usage("--expect-server-id requires a UUID");
            }
            options.expected_server_id = arguments[++argument_index];
        } else {
            fail_with_usage("unknown argument: " + std::string(argument));
        }
    }

    if (!options.show_help && !options.dry_run && options.host.empty()) {
        fail_with_usage("choose --dry-run or --connect <host> <port>");
    }
    if (options.dry_run && !options.host.empty()) {
        fail_with_usage("choose only one of --dry-run or --connect");
    }
    if (!options.host.empty() && !options.allow_plaintext && !options.phase3_test) {
        fail_with_usage("--connect requires --allow-plaintext for this pre-TLS probe");
    }
    if (options.allow_plaintext && options.phase3_test) {
        fail_with_usage("choose only one of --allow-plaintext or --phase3-test");
    }
    if (options.client_name.empty() || options.client_name.size() > GM_CONTROL_CLIENT_NAME_MAX_BYTES) {
        fail_with_usage("--client-name must be 1..128 bytes");
    }

    return options;
}

[[noreturn]] void fail_with_usage(const std::string &message) {
    std::cerr << "error: " << message << "\n\n";
    print_usage(std::cerr);
    throw std::invalid_argument(message);
}

gm_bytes bytes_from_string(const std::string &text) {
    return gm_bytes{reinterpret_cast<const uint8_t *>(text.data()), text.size()};
}

std::string escape_json_string(std::string_view text) {
    std::ostringstream escaped;
    escaped << std::hex << std::setfill('0');
    for (const unsigned char character : text) {
        switch (character) {
        case '"':
            escaped << "\\\"";
            break;
        case '\\':
            escaped << "\\\\";
            break;
        case '\b':
            escaped << "\\b";
            break;
        case '\f':
            escaped << "\\f";
            break;
        case '\n':
            escaped << "\\n";
            break;
        case '\r':
            escaped << "\\r";
            break;
        case '\t':
            escaped << "\\t";
            break;
        default:
            if (character < 0x20u) {
                escaped << "\\u" << std::setw(4) << static_cast<unsigned int>(character);
            } else {
                escaped << static_cast<char>(character);
            }
            break;
        }
    }
    return escaped.str();
}

std::string session_hello_json(const Options &options) {
    return "{\"v\":1,\"id\":1,\"type\":\"session.hello\",\"role\":\"win-client\","
           "\"client_name\":\"" +
           escape_json_string(options.client_name) + "\",\"versions\":[1],\"udp_port\":" +
           std::to_string(options.udp_port) + "}";
}

std::string transport_bind_json(std::string_view session_id, uint16_t udp_port) {
    return "{\"v\":1,\"id\":2,\"type\":\"transport.bind\",\"session_id\":\"" + std::string(session_id) +
           "\",\"udp_port\":" + std::to_string(udp_port) + "}";
}

std::string stream_open_json(uint16_t playout_target_ms) {
    return "{\"v\":1,\"id\":3,\"type\":\"stream.open\",\"kind\":\"audio\",\"direction\":\"win_to_apple\","
           "\"profile\":{\"codec\":\"pcm_s16le\",\"sample_rate_hz\":48000,\"channels\":2,"
           "\"channel_layout\":\"stereo\",\"frames_per_packet\":240},\"playout_target_ms\":" +
           std::to_string(playout_target_ms) + "}";
}

std::string stream_start_json(uint32_t stream_id, uint64_t first_media_timestamp) {
    return "{\"v\":1,\"id\":4,\"type\":\"stream.start\",\"stream_id\":" + std::to_string(stream_id) + ",\"first_media_timestamp\":\"" +
           std::to_string(first_media_timestamp) + "\"}";
}

std::string simulated_hello_result_json() {
    return "{\"v\":1,\"id\":1,\"type\":\"result\",\"result\":{\"version\":1,\"role\":\"apple-output-server\","
           "\"server_id\":\"01234567-89ab-cdef-0123-456789abcdef\","
           "\"session_id\":\"00112233445566778899aabbccddeeff\","
           "\"boot_id\":\"11111111-2222-3333-4444-555555555555\",\"udp_port\":51838,"
           "\"capabilities\":{\"audio_send\":false,\"audio_receive\":true,\"microphone\":false,\"camera\":false,"
           "\"audio_profiles\":[{\"codec\":\"pcm_s16le\",\"sample_rate_hz\":48000,\"channels\":2,"
           "\"channel_layout\":\"stereo\",\"frames_per_packet\":240}]},"
           "\"limits\":{\"max_audio_subscribers\":1,\"playout_target_ms_min\":15,\"playout_target_ms_max\":120}}}";
}

std::string simulated_bind_result_json() {
    return "{\"v\":1,\"id\":2,\"type\":\"result\",\"result\":{\"udp_port\":51838,\"path_state\":\"bound\"}}";
}

std::string simulated_open_result_json() {
    return "{\"v\":1,\"id\":3,\"type\":\"result\",\"result\":{\"stream_id\":1,\"key_epoch\":1,"
           "\"profile\":{\"codec\":\"pcm_s16le\",\"sample_rate_hz\":48000,\"channels\":2,"
           "\"channel_layout\":\"stereo\",\"frames_per_packet\":240},\"packet_interval_us\":5000,"
           "\"path_state\":\"probing\"}}";
}

gm_control_message_info parse_control_message(const std::string &json, const std::string &label) {
    gm_control_message_info message{};
    message.struct_size = sizeof(message);
    const gm_status status = gm_control_parse_message(bytes_from_string(json), &message);
    if (status != GM_OK) {
        throw std::runtime_error(label + " rejected by gm_core: " + gm_status_string(status));
    }
    return message;
}

void require_result(const gm_control_message_info &message, uint32_t expected_id, const std::string &label) {
    if (message.kind != GM_CONTROL_RESPONSE_RESULT || message.id != expected_id) {
        throw std::runtime_error(label + " was not the expected result response");
    }
}

std::vector<uint8_t> encode_control_frame(const std::string &json, const std::string &label) {
    parse_control_message(json, label);
    std::vector<uint8_t> frame(GM_CONTROL_FRAME_HEADER_BYTES + json.size());
    size_t written = 0u;
    const gm_status status = gm_control_encode_frame(bytes_from_string(json), gm_mut_bytes{frame.data(), frame.size()}, &written);
    if (status != GM_OK) {
        throw std::runtime_error(label + " frame rejected by gm_core: " + gm_status_string(status));
    }
    frame.resize(written);
    return frame;
}

std::array<uint8_t, GM_SESSION_ID_BYTES> decode_session_id(std::string_view hex_session_id) {
    if (hex_session_id.size() != GM_CONTROL_SESSION_ID_HEX_BYTES) {
        throw std::runtime_error("session_id is not 32 lowercase hexadecimal bytes");
    }

    auto hex_value = [](char character) -> uint8_t {
        if (character >= '0' && character <= '9') {
            return static_cast<uint8_t>(character - '0');
        }
        if (character >= 'a' && character <= 'f') {
            return static_cast<uint8_t>(character - 'a' + 10);
        }
        throw std::runtime_error("session_id contains a non-hex character");
    };

    std::array<uint8_t, GM_SESSION_ID_BYTES> session_id{};
    for (size_t byte_index = 0; byte_index < session_id.size(); ++byte_index) {
        session_id[byte_index] = static_cast<uint8_t>((hex_value(hex_session_id[byte_index * 2u]) << 4u) |
                                                      hex_value(hex_session_id[byte_index * 2u + 1u]));
    }
    return session_id;
}

void validate_path_headers(const gm_control_message_info &open_result, std::string_view session_id_text) {
    const std::array<uint8_t, GM_SESSION_ID_BYTES> session_id = decode_session_id(session_id_text);
    std::array<uint8_t, GM_MEDIA_HEADER_BYTES> encoded{};
    size_t written = 0u;

    gm_media_header challenge{};
    challenge.struct_size = sizeof(challenge);
    challenge.abi_version = GM_ABI_VERSION;
    challenge.kind = GM_MEDIA_KIND_PATH_CHALLENGE;
    std::memcpy(challenge.session_id, session_id.data(), session_id.size());
    challenge.stream_id = open_result.stream_id;
    challenge.direction = GM_MEDIA_DIRECTION_WIN_TO_APPLE;
    challenge.key_epoch = open_result.key_epoch;
    challenge.sequence = 1u;
    challenge.media_timestamp = 0u;
    challenge.payload_length = 12u;

    gm_status status = gm_media_encode_header(&challenge, gm_mut_bytes{encoded.data(), encoded.size()}, &written);
    if (status != GM_OK || written != GM_MEDIA_HEADER_BYTES) {
        throw std::runtime_error("PATH_CHALLENGE header failed: " + std::string(gm_status_string(status)));
    }

    gm_media_header response = challenge;
    response.kind = GM_MEDIA_KIND_PATH_RESPONSE;
    response.direction = GM_MEDIA_DIRECTION_APPLE_TO_WIN;
    response.sequence = 2u;
    status = gm_media_encode_header(&response, gm_mut_bytes{encoded.data(), encoded.size()}, &written);
    if (status != GM_OK || written != GM_MEDIA_HEADER_BYTES) {
        throw std::runtime_error("PATH_RESPONSE header failed: " + std::string(gm_status_string(status)));
    }
}

std::string runtime_error(const std::string &operation, gm_status status) {
    return operation + " failed: " + gm_status_string(status) + ": " + gm_runtime_last_error();
}

SocketHandle connect_tcp(const std::string &host, uint16_t port) {
    gm_runtime_tcp_socket *connection = nullptr;
    const gm_status status = gm_runtime_tcp_connect(
        host.c_str(),
        port,
        kDefaultReceiveTimeoutMs,
        &connection);
    if (status != GM_OK || connection == nullptr) {
        throw std::runtime_error(runtime_error("connect", status));
    }
    return SocketHandle(connection);
}

void send_all(const ControlConnection &connection, const uint8_t *data, size_t size) {
    const gm_status status = connection.tls != nullptr
        ? gm_runtime_tls_send_all(connection.tls, gm_bytes{data, size})
        : gm_runtime_tcp_send_all(connection.socket, gm_bytes{data, size});
    if (status != GM_OK) {
        throw std::runtime_error(runtime_error("send", status));
    }
}

void recv_all(const ControlConnection &connection, uint8_t *data, size_t size) {
    const gm_status status = connection.tls != nullptr
        ? gm_runtime_tls_receive_exact(connection.tls, gm_mut_bytes{data, size})
        : gm_runtime_tcp_receive_exact(connection.socket, gm_mut_bytes{data, size});
    if (status != GM_OK) {
        throw std::runtime_error(runtime_error("receive", status));
    }
}

void send_control_json(const ControlConnection &connection, const std::string &json, const std::string &label) {
    const std::vector<uint8_t> frame = encode_control_frame(json, label);
    send_all(connection, frame.data(), frame.size());
    std::cout << "sent " << label << " (" << json.size() << " JSON bytes)\n";
}

ReceivedMessage receive_control_message(const ControlConnection &connection) {
    std::array<uint8_t, GM_CONTROL_FRAME_HEADER_BYTES> header{};
    recv_all(connection, header.data(), header.size());

    gm_control_frame_info frame_info{};
    frame_info.struct_size = sizeof(frame_info);
    gm_status status = gm_control_peek_frame(gm_bytes{header.data(), header.size()}, &frame_info);
    if (status != GM_NEED_MORE_DATA && status != GM_OK) {
        throw std::runtime_error("received invalid frame header: " + std::string(gm_status_string(status)));
    }

    std::vector<uint8_t> frame(frame_info.frame_size);
    std::memcpy(frame.data(), header.data(), header.size());
    recv_all(connection, frame.data() + header.size(), frame.size() - header.size());

    frame_info = gm_control_frame_info{};
    frame_info.struct_size = sizeof(frame_info);
    status = gm_control_peek_frame(gm_bytes{frame.data(), frame.size()}, &frame_info);
    if (status != GM_OK || frame_info.complete != 1u) {
        throw std::runtime_error("received incomplete frame: " + std::string(gm_status_string(status)));
    }

    ReceivedMessage received{};
    received.json.assign(reinterpret_cast<const char *>(frame.data() + GM_CONTROL_FRAME_HEADER_BYTES), frame_info.payload_length);
    received.info = parse_control_message(received.json, "received control frame");
    return received;
}

gm_control_message_info receive_result_for_id(
    const ControlConnection &connection,
    uint32_t expected_id,
    const std::string &label) {
    for (uint32_t frame_count = 0u; frame_count < 8u; ++frame_count) {
        ReceivedMessage received = receive_control_message(connection);
        if (received.info.kind == GM_CONTROL_RESPONSE_RESULT && received.info.id == expected_id) {
            std::cout << "received " << label << "\n";
            return received.info;
        }
        if (received.info.kind == GM_CONTROL_RESPONSE_ERROR && received.info.id == expected_id) {
            throw std::runtime_error(label + " returned a protocol error response");
        }
        if (std::strncmp(received.info.type, "event.", 6u) == 0) {
            std::cout << "received event while waiting for " << label << ": " << received.info.type << "\n";
            continue;
        }
        throw std::runtime_error("unexpected response while waiting for " + label);
    }
    throw std::runtime_error("too many events while waiting for " + label);
}

void run_dry_run(const Options &options) {
    const std::string hello = session_hello_json(options);
    const std::vector<uint8_t> hello_frame = encode_control_frame(hello, "session.hello");
    const gm_control_message_info hello_result = parse_control_message(simulated_hello_result_json(), "simulated session.hello result");
    require_result(hello_result, 1u, "simulated session.hello result");

    const std::string bind = transport_bind_json(hello_result.session_id, options.udp_port);
    const std::vector<uint8_t> bind_frame = encode_control_frame(bind, "transport.bind");
    const gm_control_message_info bind_result = parse_control_message(simulated_bind_result_json(), "simulated transport.bind result");
    require_result(bind_result, 2u, "simulated transport.bind result");

    const std::string open = stream_open_json(options.playout_target_ms);
    const std::vector<uint8_t> open_frame = encode_control_frame(open, "stream.open");
    const gm_control_message_info open_result = parse_control_message(simulated_open_result_json(), "simulated stream.open result");
    require_result(open_result, 3u, "simulated stream.open result");
    validate_path_headers(open_result, hello_result.session_id);

    std::cout << "dry-run ok\n"
              << "  session.hello frame bytes: " << hello_frame.size() << "\n"
              << "  transport.bind frame bytes: " << bind_frame.size() << "\n"
              << "  stream.open frame bytes: " << open_frame.size() << "\n"
              << "  server role: " << hello_result.role << "\n"
              << "  session_id: " << hello_result.session_id << "\n"
              << "  stream_id: " << open_result.stream_id << "\n"
              << "  key_epoch: " << open_result.key_epoch << "\n"
              << "  path headers: WIN_TO_APPLE challenge and APPLE_TO_WIN response validated\n";
}

std::array<uint8_t, GM_SPKI_DIGEST_BYTES> identity_digest(const gm_runtime_identity *identity) {
    std::array<uint8_t, GM_SPKI_DIGEST_BYTES> digest{};
    const gm_status status = gm_runtime_identity_spki_sha256(
        identity, gm_mut_bytes{digest.data(), digest.size()});
    if (status != GM_OK) {
        throw std::runtime_error(runtime_error("identity digest", status));
    }
    return digest;
}

std::string hex_encode(const uint8_t *bytes, size_t size) {
    constexpr char digits[] = "0123456789abcdef";
    std::string result;
    result.reserve(size * 2u);
    for (size_t index = 0u; index < size; ++index) {
        result.push_back(digits[(bytes[index] >> 4u) & 0x0fu]);
        result.push_back(digits[bytes[index] & 0x0fu]);
    }
    return result;
}

IdentityHandle phase3_test_identity(const std::array<uint8_t, 32> &private_key) {
    gm_runtime_identity *identity = nullptr;
    const gm_status status = gm_runtime_identity_renew_raw_ed25519(
        gm_bytes{private_key.data(), private_key.size()}, &identity);
    if (status != GM_OK || identity == nullptr) {
        throw std::runtime_error(runtime_error("Phase 3 test identity", status));
    }
    return IdentityHandle(identity);
}

gm_directional_keys derive_phase3_keys(
    gm_runtime_tls_session *tls,
    const std::array<uint8_t, GM_SESSION_ID_BYTES> &session_id,
    uint32_t stream_id,
    uint32_t direction,
    uint32_t key_epoch,
    const std::array<uint8_t, GM_SPKI_DIGEST_BYTES> &sender_digest,
    const std::array<uint8_t, GM_SPKI_DIGEST_BYTES> &receiver_digest) {
    gm_crypto_exporter_context_input input{};
    input.struct_size = sizeof(input);
    input.abi_version = GM_ABI_VERSION;
    input.stream_id = stream_id;
    input.direction = direction;
    input.key_epoch = key_epoch;
    std::memcpy(input.session_id, session_id.data(), session_id.size());
    std::memcpy(input.sender_spki_digest, sender_digest.data(), sender_digest.size());
    std::memcpy(input.receiver_spki_digest, receiver_digest.data(), receiver_digest.size());

    std::array<uint8_t, GM_TLS_EXPORTER_CONTEXT_BYTES> context{};
    size_t context_size = 0u;
    gm_status status = gm_crypto_build_exporter_context(
        &input, gm_mut_bytes{context.data(), context.size()}, &context_size);
    if (status != GM_OK || context_size != context.size()) {
        throw std::runtime_error("failed to build Phase 3 TLS exporter context");
    }
    std::array<uint8_t, GM_TLS_EXPORTER_OUTPUT_BYTES> output{};
    status = gm_runtime_tls_export(
        tls, gm_bytes{context.data(), context.size()}, gm_mut_bytes{output.data(), output.size()});
    if (status != GM_OK) {
        throw std::runtime_error(runtime_error("TLS exporter", status));
    }
    gm_directional_keys keys{};
    keys.struct_size = sizeof(keys);
    status = gm_crypto_split_exporter_output(gm_bytes{output.data(), output.size()}, &keys);
    if (status != GM_OK) {
        throw std::runtime_error("failed to split Phase 3 TLS exporter output");
    }
    return keys;
}

std::vector<uint8_t> seal_media_datagram(
    const std::array<uint8_t, GM_SESSION_ID_BYTES> &session_id,
    uint32_t stream_id,
    uint32_t kind,
    uint32_t direction,
    uint32_t key_epoch,
    uint64_t sequence,
    uint64_t media_timestamp,
    const std::vector<uint8_t> &payload,
    const uint8_t *key) {
    gm_media_header header{};
    header.struct_size = sizeof(header);
    header.abi_version = GM_ABI_VERSION;
    header.kind = kind;
    std::memcpy(header.session_id, session_id.data(), session_id.size());
    header.stream_id = stream_id;
    header.direction = direction;
    header.key_epoch = key_epoch;
    header.sequence = sequence;
    header.media_timestamp = media_timestamp;
    header.payload_length = static_cast<uint32_t>(payload.size());

    std::vector<uint8_t> datagram(GM_MEDIA_HEADER_BYTES + payload.size() + GM_MEDIA_TAG_BYTES);
    size_t header_size = 0u;
    gm_status status = gm_media_encode_header(
        &header, gm_mut_bytes{datagram.data(), GM_MEDIA_HEADER_BYTES}, &header_size);
    if (status != GM_OK || header_size != GM_MEDIA_HEADER_BYTES) {
        throw std::runtime_error("failed to encode protected media header");
    }
    std::array<uint8_t, GM_MEDIA_NONCE_BYTES> nonce{};
    status = gm_media_build_nonce(key_epoch, sequence, gm_mut_bytes{nonce.data(), nonce.size()});
    if (status != GM_OK) {
        throw std::runtime_error("failed to build media nonce");
    }
    status = gm_runtime_aes256_gcm_encrypt(
        gm_bytes{key, GM_CRYPTO_KEY_BYTES}, gm_bytes{nonce.data(), nonce.size()},
        gm_bytes{datagram.data(), GM_MEDIA_HEADER_BYTES}, gm_bytes{payload.data(), payload.size()},
        gm_mut_bytes{datagram.data() + GM_MEDIA_HEADER_BYTES, payload.size()},
        gm_mut_bytes{datagram.data() + GM_MEDIA_HEADER_BYTES + payload.size(), GM_MEDIA_TAG_BYTES});
    if (status != GM_OK) {
        throw std::runtime_error(runtime_error("AES-GCM encrypt", status));
    }
    return datagram;
}

gm_media_header open_media_datagram(
    const std::vector<uint8_t> &datagram,
    const uint8_t *key,
    std::vector<uint8_t> &plaintext) {
    gm_media_header header{};
    header.struct_size = sizeof(header);
    gm_status status = gm_media_decode_header(gm_bytes{datagram.data(), datagram.size()}, &header);
    if (status != GM_OK) {
        throw std::runtime_error("received malformed protected UDP datagram");
    }
    std::array<uint8_t, GM_MEDIA_NONCE_BYTES> nonce{};
    status = gm_media_build_nonce(header.key_epoch, header.sequence,
                                  gm_mut_bytes{nonce.data(), nonce.size()});
    if (status != GM_OK) {
        throw std::runtime_error("failed to build received media nonce");
    }
    plaintext.resize(header.payload_length);
    status = gm_runtime_aes256_gcm_decrypt(
        gm_bytes{key, GM_CRYPTO_KEY_BYTES}, gm_bytes{nonce.data(), nonce.size()},
        gm_bytes{datagram.data(), GM_MEDIA_HEADER_BYTES},
        gm_bytes{datagram.data() + GM_MEDIA_HEADER_BYTES, header.payload_length},
        gm_bytes{datagram.data() + GM_MEDIA_HEADER_BYTES + header.payload_length, GM_MEDIA_TAG_BYTES},
        gm_mut_bytes{plaintext.data(), plaintext.size()});
    if (status != GM_OK) {
        throw std::runtime_error("received UDP datagram did not authenticate");
    }
    return header;
}

std::vector<uint8_t> synthetic_pcm_packet(uint64_t packet_index) {
    std::vector<uint8_t> pcm(GM_AUDIO_PCM_S16LE_PAYLOAD_BYTES);
    constexpr double kPi = 3.14159265358979323846;
    for (size_t frame = 0; frame < 240u; ++frame) {
        const double phase = (static_cast<double>(packet_index * 240u + frame) * 440.0 * 2.0 * kPi) / 48000.0;
        const int16_t sample = static_cast<int16_t>(std::sin(phase) * 12000.0);
        const size_t offset = frame * 4u;
        pcm[offset] = static_cast<uint8_t>(sample & 0xff);
        pcm[offset + 1u] = static_cast<uint8_t>((static_cast<uint16_t>(sample) >> 8u) & 0xffu);
        pcm[offset + 2u] = pcm[offset];
        pcm[offset + 3u] = pcm[offset + 1u];
    }
    return pcm;
}

void run_connect(const Options &options) {
    if (options.phase3_test) {
        std::cout << "Phase 3 test mode: pinned mutual TLS and protected UDP are enabled\n";
    } else {
        std::cout << "warning: using pre-TLS framed TCP for first interop only; this is not v1-conformant transport\n";
    }
    SocketHandle socket_handle = connect_tcp(options.host, options.port);
    std::cout << "connected to " << options.host << ':' << options.port << "\n";

    std::optional<IdentityHandle> client_identity;
    std::optional<IdentityHandle> server_identity;
    std::optional<TlsHandle> tls_handle;
    std::optional<UdpHandle> udp_handle;
    std::array<uint8_t, GM_SPKI_DIGEST_BYTES> client_digest{};
    std::array<uint8_t, GM_SPKI_DIGEST_BYTES> server_digest{};
    if (options.phase3_test) {
        client_identity.emplace(phase3_test_identity(kPhase3WindowsPrivateKey));
        server_identity.emplace(phase3_test_identity(kPhase3ApplePrivateKey));
        client_digest = identity_digest(client_identity->get());
        server_digest = identity_digest(server_identity->get());
        std::cout << "Phase 3 test client SPKI SHA-256: "
                  << hex_encode(client_digest.data(), client_digest.size()) << "\n"
                  << "Phase 3 expected server SPKI SHA-256: "
                  << hex_encode(server_digest.data(), server_digest.size()) << "\n";
        gm_runtime_tls_session *tls = nullptr;
        gm_status status = gm_runtime_tls_client_create(
            socket_handle.get(), client_identity->get(),
            gm_bytes{server_digest.data(), server_digest.size()}, &tls);
        if (status != GM_OK || tls == nullptr) {
            throw std::runtime_error(runtime_error("TLS client setup", status));
        }
        tls_handle.emplace(tls);
        status = gm_runtime_tls_handshake(tls_handle->get());
        if (status != GM_OK) {
            throw std::runtime_error(runtime_error("mutual TLS handshake", status));
        }
        gm_runtime_udp_socket *udp = nullptr;
        status = gm_runtime_udp_bind_ipv4(options.udp_port, kDefaultReceiveTimeoutMs, &udp);
        if (status != GM_OK || udp == nullptr) {
            throw std::runtime_error(runtime_error("UDP bind", status));
        }
        udp_handle.emplace(udp);
        std::cout << "mutual TLS 1.3 established; UDP port " << options.udp_port << " prebound\n";
    }
    const ControlConnection connection{socket_handle.get(), tls_handle ? tls_handle->get() : nullptr};

    send_control_json(connection, session_hello_json(options), "session.hello");
    const gm_control_message_info hello_result = receive_result_for_id(connection, 1u, "session.hello result");
    if (std::strcmp(hello_result.role, "apple-output-server") != 0 || hello_result.session_id[0] == '\0') {
        throw std::runtime_error("session.hello result did not include the expected Apple output-server identity");
    }
    if (!options.expected_server_id.empty() && options.expected_server_id != hello_result.server_id) {
        throw std::runtime_error("session.hello result server_id did not match --expect-server-id");
    }
    if (options.expected_server_id.empty()) {
        std::cout << "warning: no --expect-server-id supplied; server_id is logged but not pinned\n";
    }

    send_control_json(connection, transport_bind_json(hello_result.session_id, options.udp_port), "transport.bind");
    const gm_control_message_info bind_result = receive_result_for_id(connection, 2u, "transport.bind result");
    if (std::strcmp(bind_result.path_state, "bound") != 0) {
        throw std::runtime_error("transport.bind result did not report path_state=bound");
    }

    send_control_json(connection, stream_open_json(options.playout_target_ms), "stream.open");
    const gm_control_message_info open_result = receive_result_for_id(connection, 3u, "stream.open result");
    if (std::strcmp(open_result.path_state, "probing") != 0 || open_result.stream_id == 0u || open_result.key_epoch == 0u) {
        throw std::runtime_error("stream.open result did not report a probing stream");
    }

    validate_path_headers(open_result, hello_result.session_id);
    if (options.phase3_test) {
        const auto session_id = decode_session_id(hello_result.session_id);
        const auto forward_keys = derive_phase3_keys(
            tls_handle->get(), session_id, open_result.stream_id, GM_MEDIA_DIRECTION_WIN_TO_APPLE,
            open_result.key_epoch, client_digest, server_digest);
        const auto reverse_keys = derive_phase3_keys(
            tls_handle->get(), session_id, open_result.stream_id, GM_MEDIA_DIRECTION_APPLE_TO_WIN,
            open_result.key_epoch, server_digest, client_digest);
        std::vector<uint8_t> challenge(12u);
        gm_status status = gm_runtime_random_bytes(gm_mut_bytes{challenge.data(), challenge.size()});
        if (status != GM_OK) {
            throw std::runtime_error(runtime_error("path challenge randomness", status));
        }
        const std::vector<uint8_t> protected_challenge = seal_media_datagram(
            session_id, open_result.stream_id, GM_MEDIA_KIND_PATH_CHALLENGE,
            GM_MEDIA_DIRECTION_WIN_TO_APPLE, open_result.key_epoch, 1u, 0u,
            challenge, forward_keys.path_key);
        status = gm_runtime_udp_send_to(
            udp_handle->get(), options.host.c_str(), static_cast<uint16_t>(hello_result.udp_port),
            gm_bytes{protected_challenge.data(), protected_challenge.size()});
        if (status != GM_OK) {
            throw std::runtime_error(runtime_error("PATH_CHALLENGE send", status));
        }
        std::array<uint8_t, GM_MEDIA_MAX_DATAGRAM_BYTES> received_buffer{};
        char source_host[64]{};
        uint16_t source_port = 0u;
        size_t received_size = 0u;
        status = gm_runtime_udp_receive_from(
            udp_handle->get(), gm_mut_bytes{received_buffer.data(), received_buffer.size()}, &received_size,
            source_host, sizeof(source_host), &source_port);
        if (status != GM_OK) {
            throw std::runtime_error(runtime_error("PATH_RESPONSE receive", status));
        }
        std::vector<uint8_t> response_datagram(received_buffer.begin(), received_buffer.begin() + received_size);
        std::vector<uint8_t> response_payload;
        const gm_media_header response = open_media_datagram(response_datagram, reverse_keys.path_key, response_payload);
        if (response.kind != GM_MEDIA_KIND_PATH_RESPONSE || response.stream_id != open_result.stream_id ||
            response.key_epoch != open_result.key_epoch || source_host != options.host ||
            source_port != hello_result.udp_port ||
            response_payload != challenge) {
            throw std::runtime_error("PATH_RESPONSE did not validate the candidate UDP path");
        }
        std::cout << "protected UDP path validated from " << source_host << ':' << source_port << "\n";

        constexpr uint64_t kFirstTimestamp = 48000u;
        send_control_json(connection, stream_start_json(open_result.stream_id, kFirstTimestamp), "stream.start");
        const gm_control_message_info start_result = receive_result_for_id(connection, 4u, "stream.start result");
        if (std::strcmp(start_result.state, "started") != 0) {
            throw std::runtime_error("stream.start result did not report state=started");
        }
        for (uint64_t packet_index = 0u; packet_index < kPhase3PacketCount; ++packet_index) {
            const std::vector<uint8_t> pcm = synthetic_pcm_packet(packet_index);
            const std::vector<uint8_t> audio = seal_media_datagram(
                session_id, open_result.stream_id, GM_MEDIA_KIND_AUDIO,
                GM_MEDIA_DIRECTION_WIN_TO_APPLE, open_result.key_epoch, packet_index + 2u,
                kFirstTimestamp + packet_index * 240u, pcm, forward_keys.media_key);
            status = gm_runtime_udp_send_to(
                udp_handle->get(), options.host.c_str(), static_cast<uint16_t>(hello_result.udp_port),
                gm_bytes{audio.data(), audio.size()});
            if (status != GM_OK) {
                throw std::runtime_error(runtime_error("PCM UDP send", status));
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
        std::cout << "sent " << kPhase3PacketCount << " encrypted synthetic PCM packets\n";
    }
    std::cout << "control interop reached stream.open\n"
              << "  server_id: " << hello_result.server_id << "\n"
              << "  session_id: " << hello_result.session_id << "\n"
              << "  apple_udp_port: " << hello_result.udp_port << "\n"
              << "  stream_id: " << open_result.stream_id << "\n"
              << "  key_epoch: " << open_result.key_epoch << "\n"
              << (options.phase3_test
                  ? "  Phase 3 secure control, path validation, and synthetic sender completed\n"
                  : "  next: add TLS exporter/AES-GCM before sending UDP media\n");
}
} // namespace

int main(int argument_count, char **arguments) {
    try {
        const Options options = parse_options(argument_count, arguments);
        if (options.show_help) {
            print_usage(std::cout);
            return 0;
        }
        if (options.dry_run) {
            run_dry_run(options);
        } else {
            run_connect(options);
        }
        return 0;
    } catch (const std::invalid_argument &) {
        return 2;
    } catch (const std::exception &exception) {
        std::cerr << "error: " << exception.what() << '\n';
        return 1;
    }
}
