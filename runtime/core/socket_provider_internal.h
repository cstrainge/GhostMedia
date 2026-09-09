#ifndef GHOSTMEDIA_RUNTIME_SOCKET_PROVIDER_INTERNAL_H
#define GHOSTMEDIA_RUNTIME_SOCKET_PROVIDER_INTERNAL_H

#include <ghostmedia/gm_core.h>

#include <chrono>
#include <cstdint>

struct gm_runtime_tcp_socket;

namespace ghostmedia::runtime::detail {

std::chrono::steady_clock::time_point tcp_socket_opened_at(
    const gm_runtime_tcp_socket *socket);
uint32_t tcp_socket_default_timeout_ms(const gm_runtime_tcp_socket *socket);
gm_status tcp_socket_set_io_timeout(
    gm_runtime_tcp_socket *socket,
    uint32_t timeout_ms);

}

#endif
