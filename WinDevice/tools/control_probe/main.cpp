#include <ghostmedia/gm_core.h>
#include <ghostmedia/gm_runtime.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace {
constexpr uint16_t kDefaultUdpPort = 49152u;
constexpr uint16_t kDefaultPlayoutTargetMs = 30u;
constexpr uint32_t kDefaultReceiveTimeoutMs = 5000u;

struct Options {
    bool dry_run = false;
    bool show_help = false;
    bool allow_plaintext = false;
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

[[noreturn]] void fail_with_usage(const std::string &message);

void print_usage(std::ostream &output) {
    output << "GhostMediaWinControlProbe\n"
           << "  --dry-run\n"
           << "      Validate the scripted Windows-side hello/bind/open flow locally.\n"
           << "  --connect <host> <port> --allow-plaintext [options]\n"
           << "      Run the same framed-control flow against a Mac CLI harness.\n\n"
           << "Options:\n"
           << "  --udp-port <1..65535>             Windows prebound UDP port fixture.\n"
           << "  --playout-target-ms <15..120>     stream.open playout target.\n"
           << "  --client-name <text>              session.hello client name.\n\n"
           << "  --expect-server-id <uuid>         reject mismatched Apple server_id.\n\n"
           << "This probe is pre-TLS and pre-AEAD. It is for first interop tests only,\n"
           << "not a conformant GhostMedia v1 transport.\n";
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
    if (!options.host.empty() && !options.allow_plaintext) {
        fail_with_usage("--connect requires --allow-plaintext for this pre-TLS probe");
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

void send_all(gm_runtime_tcp_socket *socket_handle, const uint8_t *data, size_t size) {
    const gm_status status = gm_runtime_tcp_send_all(socket_handle, gm_bytes{data, size});
    if (status != GM_OK) {
        throw std::runtime_error(runtime_error("send", status));
    }
}

void recv_all(gm_runtime_tcp_socket *socket_handle, uint8_t *data, size_t size) {
    const gm_status status = gm_runtime_tcp_receive_exact(
        socket_handle,
        gm_mut_bytes{data, size});
    if (status != GM_OK) {
        throw std::runtime_error(runtime_error("receive", status));
    }
}

void send_control_json(gm_runtime_tcp_socket *socket_handle, const std::string &json, const std::string &label) {
    const std::vector<uint8_t> frame = encode_control_frame(json, label);
    send_all(socket_handle, frame.data(), frame.size());
    std::cout << "sent " << label << " (" << json.size() << " JSON bytes)\n";
}

ReceivedMessage receive_control_message(gm_runtime_tcp_socket *socket_handle) {
    std::array<uint8_t, GM_CONTROL_FRAME_HEADER_BYTES> header{};
    recv_all(socket_handle, header.data(), header.size());

    gm_control_frame_info frame_info{};
    frame_info.struct_size = sizeof(frame_info);
    gm_status status = gm_control_peek_frame(gm_bytes{header.data(), header.size()}, &frame_info);
    if (status != GM_NEED_MORE_DATA && status != GM_OK) {
        throw std::runtime_error("received invalid frame header: " + std::string(gm_status_string(status)));
    }

    std::vector<uint8_t> frame(frame_info.frame_size);
    std::memcpy(frame.data(), header.data(), header.size());
    recv_all(socket_handle, frame.data() + header.size(), frame.size() - header.size());

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
    gm_runtime_tcp_socket *socket_handle,
    uint32_t expected_id,
    const std::string &label) {
    for (uint32_t frame_count = 0u; frame_count < 8u; ++frame_count) {
        ReceivedMessage received = receive_control_message(socket_handle);
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

void run_connect(const Options &options) {
    std::cout << "warning: using pre-TLS framed TCP for first interop only; this is not v1-conformant transport\n";
    SocketHandle socket_handle = connect_tcp(options.host, options.port);
    std::cout << "connected to " << options.host << ':' << options.port << "\n";

    send_control_json(socket_handle.get(), session_hello_json(options), "session.hello");
    const gm_control_message_info hello_result = receive_result_for_id(socket_handle.get(), 1u, "session.hello result");
    if (std::strcmp(hello_result.role, "apple-output-server") != 0 || hello_result.session_id[0] == '\0') {
        throw std::runtime_error("session.hello result did not include the expected Apple output-server identity");
    }
    if (!options.expected_server_id.empty() && options.expected_server_id != hello_result.server_id) {
        throw std::runtime_error("session.hello result server_id did not match --expect-server-id");
    }
    if (options.expected_server_id.empty()) {
        std::cout << "warning: no --expect-server-id supplied; server_id is logged but not pinned\n";
    }

    send_control_json(socket_handle.get(), transport_bind_json(hello_result.session_id, options.udp_port), "transport.bind");
    const gm_control_message_info bind_result = receive_result_for_id(socket_handle.get(), 2u, "transport.bind result");
    if (std::strcmp(bind_result.path_state, "bound") != 0) {
        throw std::runtime_error("transport.bind result did not report path_state=bound");
    }

    send_control_json(socket_handle.get(), stream_open_json(options.playout_target_ms), "stream.open");
    const gm_control_message_info open_result = receive_result_for_id(socket_handle.get(), 3u, "stream.open result");
    if (std::strcmp(open_result.path_state, "probing") != 0 || open_result.stream_id == 0u || open_result.key_epoch == 0u) {
        throw std::runtime_error("stream.open result did not report a probing stream");
    }

    validate_path_headers(open_result, hello_result.session_id);
    std::cout << "control interop reached stream.open\n"
              << "  server_id: " << hello_result.server_id << "\n"
              << "  session_id: " << hello_result.session_id << "\n"
              << "  apple_udp_port: " << hello_result.udp_port << "\n"
              << "  stream_id: " << open_result.stream_id << "\n"
              << "  key_epoch: " << open_result.key_epoch << "\n"
              << "  next: add TLS exporter/AES-GCM before sending UDP media\n";
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