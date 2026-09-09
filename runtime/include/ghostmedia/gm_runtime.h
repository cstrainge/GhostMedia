#ifndef GHOSTMEDIA_GM_RUNTIME_H
#define GHOSTMEDIA_GM_RUNTIME_H

#include <ghostmedia/gm_core.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct gm_runtime_identity gm_runtime_identity;
typedef struct gm_runtime_tcp_socket gm_runtime_tcp_socket;
typedef struct gm_runtime_tls_session gm_runtime_tls_session;

gm_status gm_runtime_identity_generate(gm_runtime_identity **out_identity);
gm_status gm_runtime_identity_load(gm_bytes private_key_pkcs8, gm_bytes certificate_der,
                                   gm_runtime_identity **out_identity);
gm_status gm_runtime_identity_load_raw_ed25519(gm_bytes private_key_raw,
                                               gm_bytes certificate_der,
                                               gm_runtime_identity **out_identity);
gm_status gm_runtime_identity_renew_raw_ed25519(gm_bytes private_key_raw,
                                                gm_runtime_identity **out_identity);
gm_status gm_runtime_identity_renew_certificate(gm_bytes private_key_pkcs8,
                                                gm_runtime_identity **out_identity);
void gm_runtime_identity_destroy(gm_runtime_identity *identity);

gm_status gm_runtime_identity_private_key_pkcs8(const gm_runtime_identity *identity,
                                                gm_mut_bytes output, size_t *written);
gm_status gm_runtime_identity_certificate_der(const gm_runtime_identity *identity,
                                              gm_mut_bytes output, size_t *written);
gm_status gm_runtime_identity_spki_der(const gm_runtime_identity *identity,
                                      gm_mut_bytes output, size_t *written);
gm_status gm_runtime_identity_spki_sha256(const gm_runtime_identity *identity,
                                         gm_mut_bytes output);
gm_status gm_runtime_identity_sign(const gm_runtime_identity *identity, gm_bytes message,
                                   gm_mut_bytes output, size_t *written);

gm_status gm_runtime_aes256_gcm_encrypt(gm_bytes key, gm_bytes nonce, gm_bytes aad,
                                       gm_bytes plaintext, gm_mut_bytes ciphertext,
                                       gm_mut_bytes tag);
gm_status gm_runtime_aes256_gcm_decrypt(gm_bytes key, gm_bytes nonce, gm_bytes aad,
                                       gm_bytes ciphertext, gm_bytes tag,
                                       gm_mut_bytes plaintext);

gm_status gm_runtime_tls13_exporter_pair(const gm_runtime_identity *client_identity,
                                        const gm_runtime_identity *server_identity,
                                        gm_bytes client_expected_server_spki,
                                        gm_bytes server_expected_client_spki,
                                        gm_bytes exporter_context,
                                        gm_mut_bytes client_output,
                                        gm_mut_bytes server_output);

gm_status gm_runtime_tls_client_create(gm_runtime_tcp_socket *connection,
                                       const gm_runtime_identity *identity,
                                       gm_bytes expected_server_spki,
                                       gm_runtime_tls_session **out_session);
gm_status gm_runtime_tls_server_create(gm_runtime_tcp_socket *connection,
                                       const gm_runtime_identity *identity,
                                       gm_bytes expected_client_spki,
                                       gm_runtime_tls_session **out_session);
gm_status gm_runtime_tls_handshake(gm_runtime_tls_session *session);
gm_status gm_runtime_tls_send_all(gm_runtime_tls_session *session, gm_bytes plaintext);
gm_status gm_runtime_tls_receive(gm_runtime_tls_session *session, gm_mut_bytes output,
                                 size_t *received);
gm_status gm_runtime_tls_receive_exact(gm_runtime_tls_session *session, gm_mut_bytes output);
gm_status gm_runtime_tls_export(gm_runtime_tls_session *session, gm_bytes context,
                                gm_mut_bytes output);
void gm_runtime_tls_session_destroy(gm_runtime_tls_session *session);

gm_status gm_runtime_tcp_listen_ipv4(uint16_t port, uint32_t timeout_ms,
                                    gm_runtime_tcp_socket **out_listener);
gm_status gm_runtime_tcp_accept(gm_runtime_tcp_socket *listener, uint32_t timeout_ms,
                               gm_runtime_tcp_socket **out_connection);
gm_status gm_runtime_tcp_connect(const char *host, uint16_t port, uint32_t timeout_ms,
                                gm_runtime_tcp_socket **out_connection);
gm_status gm_runtime_tcp_send_all(gm_runtime_tcp_socket *connection, gm_bytes bytes);
gm_status gm_runtime_tcp_receive(gm_runtime_tcp_socket *connection, gm_mut_bytes output,
                                size_t *received);
gm_status gm_runtime_tcp_receive_exact(gm_runtime_tcp_socket *connection, gm_mut_bytes output);
gm_status gm_runtime_tcp_local_port(const gm_runtime_tcp_socket *socket, uint16_t *port);
void gm_runtime_tcp_socket_destroy(gm_runtime_tcp_socket *socket);
const char *gm_runtime_last_error(void);

#ifdef __cplusplus
}
#endif

#endif
