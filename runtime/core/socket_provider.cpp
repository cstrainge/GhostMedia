#include <ghostmedia/gm_runtime.h>

#include "socket_provider_internal.h"

#include <algorithm>
#include <chrono>
#include <cerrno>
#include <cstring>
#include <limits>
#include <memory>
#include <new>
#include <string>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
using NativeSocket = SOCKET;
constexpr NativeSocket kInvalidSocket = INVALID_SOCKET;
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
using NativeSocket = int;
constexpr NativeSocket kInvalidSocket = -1;
#endif

struct gm_runtime_tcp_socket {
    NativeSocket value = kInvalidSocket;
    std::chrono::steady_clock::time_point opened_at{};
    uint32_t default_timeout_ms = 0u;
};

namespace {
thread_local std::string last_error;

void set_error(const std::string &operation, int code) {
    last_error = operation + " failed (" + std::to_string(code) + ')';
}

int socket_error() {
#ifdef _WIN32
    return WSAGetLastError();
#else
    return errno;
#endif
}

void close_socket(NativeSocket socket) {
    if (socket == kInvalidSocket) {
        return;
    }
#ifdef _WIN32
    closesocket(socket);
#else
    close(socket);
#endif
}

#ifdef _WIN32
bool ensure_socket_runtime() {
    static const bool initialized = [] {
        WSADATA data{};
        return WSAStartup(MAKEWORD(2, 2), &data) == 0;
    }();
    return initialized;
}
#else
bool ensure_socket_runtime() {
    return true;
}
#endif

bool set_timeouts(NativeSocket socket, uint32_t timeout_ms) {
#ifdef _WIN32
    const DWORD timeout = timeout_ms;
    return setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO,
                      reinterpret_cast<const char *>(&timeout), sizeof(timeout)) == 0 &&
           setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO,
                      reinterpret_cast<const char *>(&timeout), sizeof(timeout)) == 0;
#else
    timeval timeout{};
    timeout.tv_sec = static_cast<time_t>(timeout_ms / 1000u);
    timeout.tv_usec = static_cast<suseconds_t>((timeout_ms % 1000u) * 1000u);
    if (setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0 ||
        setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) != 0) {
        return false;
    }
#ifdef __APPLE__
    int no_sigpipe = 1;
    if (setsockopt(socket, SOL_SOCKET, SO_NOSIGPIPE, &no_sigpipe, sizeof(no_sigpipe)) != 0) {
        return false;
    }
#endif
    return true;
#endif
}

bool set_nonblocking(NativeSocket socket, bool enabled) {
#ifdef _WIN32
    u_long mode = enabled ? 1u : 0u;
    return ioctlsocket(socket, FIONBIO, &mode) == 0;
#else
    const int flags = fcntl(socket, F_GETFL, 0);
    return flags >= 0 &&
        fcntl(socket, F_SETFL, enabled ? flags | O_NONBLOCK : flags & ~O_NONBLOCK) == 0;
#endif
}

bool operation_in_progress(int code) {
#ifdef _WIN32
    return code == WSAEWOULDBLOCK || code == WSAEINPROGRESS;
#else
    return code == EINPROGRESS || code == EWOULDBLOCK;
#endif
}

enum class WaitResult {
    ready,
    timeout,
    error,
};

WaitResult wait_for_socket(
    NativeSocket socket,
    bool writable,
    std::chrono::steady_clock::time_point deadline,
    int &error_code) {
#ifndef _WIN32
    if (socket >= FD_SETSIZE) {
        error_code = EINVAL;
        return WaitResult::error;
    }
#endif
    while (true) {
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline) {
            return WaitResult::timeout;
        }
        const auto remaining =
            std::chrono::duration_cast<std::chrono::microseconds>(deadline - now);
        timeval timeout{};
        timeout.tv_sec = static_cast<long>(remaining.count() / 1000000);
        timeout.tv_usec = static_cast<long>(remaining.count() % 1000000);
        fd_set descriptors;
        FD_ZERO(&descriptors);
        FD_SET(socket, &descriptors);
        const int result = select(
#ifdef _WIN32
            0,
#else
            socket + 1,
#endif
            writable ? nullptr : &descriptors,
            writable ? &descriptors : nullptr,
            nullptr,
            &timeout);
        if (result > 0) {
            return WaitResult::ready;
        }
        if (result == 0) {
            return WaitResult::timeout;
        }
        error_code = socket_error();
#ifdef _WIN32
        if (error_code != WSAEINTR) {
#else
        if (error_code != EINTR) {
#endif
            return WaitResult::error;
        }
    }
}

gm_status make_handle(
    NativeSocket socket,
    uint32_t timeout_ms,
    gm_runtime_tcp_socket **output) {
    auto handle = std::unique_ptr<gm_runtime_tcp_socket>(
        new (std::nothrow) gm_runtime_tcp_socket());
    if (!handle) {
        close_socket(socket);
        last_error = "socket handle allocation failed";
        return GM_INTERNAL;
    }
    handle->value = socket;
    handle->opened_at = std::chrono::steady_clock::now();
    handle->default_timeout_ms = timeout_ms;
    *output = handle.release();
    return GM_OK;
}
}

namespace ghostmedia::runtime::detail {

std::chrono::steady_clock::time_point tcp_socket_opened_at(
    const gm_runtime_tcp_socket *socket) {
    return socket == nullptr
        ? std::chrono::steady_clock::time_point{}
        : socket->opened_at;
}

uint32_t tcp_socket_default_timeout_ms(const gm_runtime_tcp_socket *socket) {
    return socket == nullptr ? 0u : socket->default_timeout_ms;
}

gm_status tcp_socket_set_io_timeout(
    gm_runtime_tcp_socket *socket,
    uint32_t timeout_ms) {
    if (socket == nullptr || socket->value == kInvalidSocket || timeout_ms == 0u) {
        return GM_BAD_ARGUMENT;
    }
    if (!set_timeouts(socket->value, timeout_ms)) {
        set_error("setsockopt", socket_error());
        return GM_INTERNAL;
    }
    return GM_OK;
}

}

extern "C" {

gm_status gm_runtime_tcp_listen_ipv4(uint16_t port, uint32_t timeout_ms,
                                    gm_runtime_tcp_socket **out_listener) {
    if (timeout_ms == 0u || out_listener == nullptr) {
        return GM_BAD_ARGUMENT;
    }
    *out_listener = nullptr;
    if (!ensure_socket_runtime()) {
        last_error = "socket runtime initialization failed";
        return GM_INTERNAL;
    }

    NativeSocket socket_value = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (socket_value == kInvalidSocket) {
        set_error("socket", socket_error());
        return GM_INTERNAL;
    }
    int reuse_address = 1;
    if (setsockopt(
            socket_value,
            SOL_SOCKET,
            SO_REUSEADDR,
#ifdef _WIN32
            reinterpret_cast<const char *>(&reuse_address),
#else
            &reuse_address,
#endif
            sizeof(reuse_address)) != 0 ||
        !set_timeouts(socket_value, timeout_ms)) {
        set_error("setsockopt", socket_error());
        close_socket(socket_value);
        return GM_INTERNAL;
    }

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    address.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(socket_value, reinterpret_cast<const sockaddr *>(&address), sizeof(address)) != 0 ||
        listen(socket_value, 1) != 0 ||
        !set_nonblocking(socket_value, true)) {
        set_error("listen", socket_error());
        close_socket(socket_value);
        return GM_INTERNAL;
    }
    return make_handle(socket_value, timeout_ms, out_listener);
}

gm_status gm_runtime_tcp_accept(gm_runtime_tcp_socket *listener, uint32_t timeout_ms,
                               gm_runtime_tcp_socket **out_connection) {
    if (listener == nullptr || listener->value == kInvalidSocket ||
        timeout_ms == 0u || out_connection == nullptr) {
        return GM_BAD_ARGUMENT;
    }
    *out_connection = nullptr;
    int wait_error = 0;
    const WaitResult wait_result = wait_for_socket(
        listener->value,
        false,
        std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms),
        wait_error);
    if (wait_result == WaitResult::timeout) {
        last_error = "accept timed out";
        return GM_INTERNAL;
    }
    if (wait_result == WaitResult::error) {
        set_error("select", wait_error);
        return GM_INTERNAL;
    }
    NativeSocket accepted = accept(listener->value, nullptr, nullptr);
    if (accepted == kInvalidSocket) {
        set_error("accept", socket_error());
        return GM_INTERNAL;
    }
    if (!set_nonblocking(accepted, false) || !set_timeouts(accepted, timeout_ms)) {
        set_error("setsockopt", socket_error());
        close_socket(accepted);
        return GM_INTERNAL;
    }
    return make_handle(accepted, timeout_ms, out_connection);
}

gm_status gm_runtime_tcp_connect(const char *host, uint16_t port, uint32_t timeout_ms,
                                gm_runtime_tcp_socket **out_connection) {
    if (host == nullptr || host[0] == '\0' || port == 0u ||
        timeout_ms == 0u || out_connection == nullptr) {
        return GM_BAD_ARGUMENT;
    }
    *out_connection = nullptr;
    if (!ensure_socket_runtime()) {
        last_error = "socket runtime initialization failed";
        return GM_INTERNAL;
    }

    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    addrinfo *addresses = nullptr;
    const std::string port_text = std::to_string(port);
    const int lookup = getaddrinfo(host, port_text.c_str(), &hints, &addresses);
    if (lookup != 0) {
        set_error("getaddrinfo", lookup);
        return GM_INTERNAL;
    }

    NativeSocket connected = kInvalidSocket;
    int last_code = 0;
    bool timed_out = false;
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    for (addrinfo *address = addresses; address != nullptr; address = address->ai_next) {
        if (std::chrono::steady_clock::now() >= deadline) {
            break;
        }
        NativeSocket candidate = socket(
            address->ai_family,
            address->ai_socktype,
            address->ai_protocol);
        if (candidate == kInvalidSocket) {
            last_code = socket_error();
            continue;
        }
        if (!set_nonblocking(candidate, true)) {
            last_code = socket_error();
            close_socket(candidate);
            continue;
        }
#ifdef _WIN32
        const int address_size = static_cast<int>(address->ai_addrlen);
#else
        const socklen_t address_size = static_cast<socklen_t>(address->ai_addrlen);
#endif
        const int connect_result = connect(candidate, address->ai_addr, address_size);
        if (connect_result != 0) {
            last_code = socket_error();
            if (!operation_in_progress(last_code)) {
                close_socket(candidate);
                continue;
            }
            const WaitResult wait_result =
                wait_for_socket(candidate, true, deadline, last_code);
            if (wait_result != WaitResult::ready) {
                close_socket(candidate);
                if (wait_result == WaitResult::timeout) {
                    last_error = "connect timed out";
                    timed_out = true;
                    break;
                }
                continue;
            }
            int pending_error = 0;
#ifdef _WIN32
            int pending_error_size = sizeof(pending_error);
            const int option_result = getsockopt(
                candidate,
                SOL_SOCKET,
                SO_ERROR,
                reinterpret_cast<char *>(&pending_error),
                &pending_error_size);
#else
            socklen_t pending_error_size = sizeof(pending_error);
            const int option_result = getsockopt(
                candidate,
                SOL_SOCKET,
                SO_ERROR,
                &pending_error,
                &pending_error_size);
#endif
            if (option_result != 0 || pending_error != 0) {
                last_code = option_result != 0 ? socket_error() : pending_error;
                close_socket(candidate);
                continue;
            }
        }
        if (!set_nonblocking(candidate, false) || !set_timeouts(candidate, timeout_ms)) {
            last_code = socket_error();
            close_socket(candidate);
            continue;
        }
        connected = candidate;
        break;
    }
    freeaddrinfo(addresses);
    if (connected == kInvalidSocket) {
        if (!timed_out) {
            set_error("connect", last_code);
        }
        return GM_INTERNAL;
    }
    return make_handle(connected, timeout_ms, out_connection);
}

gm_status gm_runtime_tcp_send_all(gm_runtime_tcp_socket *connection, gm_bytes bytes) {
    if (connection == nullptr || connection->value == kInvalidSocket ||
        (bytes.size != 0u && bytes.data == nullptr)) {
        return GM_BAD_ARGUMENT;
    }
    size_t sent_total = 0u;
    while (sent_total < bytes.size) {
        const size_t remaining = bytes.size - sent_total;
#ifdef _WIN32
        const int chunk_size = static_cast<int>(
            std::min(remaining, static_cast<size_t>(std::numeric_limits<int>::max())));
        const int sent = send(
            connection->value,
            reinterpret_cast<const char *>(bytes.data + sent_total),
            chunk_size,
            0);
        if (sent == SOCKET_ERROR) {
#else
        int send_flags = 0;
#ifdef MSG_NOSIGNAL
        send_flags = MSG_NOSIGNAL;
#endif
        const ssize_t sent = send(
            connection->value,
            bytes.data + sent_total,
            remaining,
            send_flags);
        if (sent < 0) {
#endif
            set_error("send", socket_error());
            return GM_INTERNAL;
        }
        if (sent == 0) {
            last_error = "send returned zero bytes";
            return GM_INTERNAL;
        }
        sent_total += static_cast<size_t>(sent);
    }
    return GM_OK;
}

gm_status gm_runtime_tcp_receive(gm_runtime_tcp_socket *connection, gm_mut_bytes output,
                                size_t *received) {
    if (connection == nullptr || connection->value == kInvalidSocket ||
        output.data == nullptr || output.size == 0u || received == nullptr) {
        return GM_BAD_ARGUMENT;
    }
    *received = 0u;
#ifdef _WIN32
    const int size = static_cast<int>(
        std::min(output.size, static_cast<size_t>(std::numeric_limits<int>::max())));
    const int result = recv(
        connection->value,
        reinterpret_cast<char *>(output.data),
        size,
        0);
    if (result == SOCKET_ERROR) {
#else
    const ssize_t result = recv(connection->value, output.data, output.size, 0);
    if (result < 0) {
#endif
        set_error("recv", socket_error());
        return GM_INTERNAL;
    }
    if (result == 0) {
        last_error = "peer closed the TCP connection";
        return GM_INTERNAL;
    }
    *received = static_cast<size_t>(result);
    return GM_OK;
}

gm_status gm_runtime_tcp_receive_exact(gm_runtime_tcp_socket *connection,
                                      gm_mut_bytes output) {
    if (connection == nullptr || connection->value == kInvalidSocket ||
        (output.size != 0u && output.data == nullptr)) {
        return GM_BAD_ARGUMENT;
    }
    size_t received_total = 0u;
    while (received_total < output.size) {
        size_t received = 0u;
        const gm_status status = gm_runtime_tcp_receive(
            connection,
            gm_mut_bytes{
                output.data + received_total,
                output.size - received_total,
            },
            &received);
        if (status != GM_OK) {
            return status;
        }
        received_total += received;
    }
    return GM_OK;
}

gm_status gm_runtime_tcp_local_port(const gm_runtime_tcp_socket *socket_handle,
                                   uint16_t *port) {
    if (socket_handle == nullptr || socket_handle->value == kInvalidSocket ||
        port == nullptr) {
        return GM_BAD_ARGUMENT;
    }
    sockaddr_in address{};
#ifdef _WIN32
    int address_size = sizeof(address);
#else
    socklen_t address_size = sizeof(address);
#endif
    if (getsockname(
            socket_handle->value,
            reinterpret_cast<sockaddr *>(&address),
            &address_size) != 0 ||
        address.sin_family != AF_INET) {
        set_error("getsockname", socket_error());
        return GM_INTERNAL;
    }
    *port = ntohs(address.sin_port);
    return GM_OK;
}

void gm_runtime_tcp_socket_destroy(gm_runtime_tcp_socket *socket_handle) {
    if (socket_handle != nullptr) {
        close_socket(socket_handle->value);
        socket_handle->value = kInvalidSocket;
        delete socket_handle;
    }
}

const char *gm_runtime_last_error(void) {
    return last_error.c_str();
}

}
