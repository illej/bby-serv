#ifndef _CAST_H_
#define _CAST_H_

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

static const char *connection_ns = "urn:x-cast:com.google.cast.tp.connection";
static const char *heartbeat_ns = "urn:x-cast:com.google.cast.tp.heartbeat";
static const char *receiver_ns = "urn:x-cast:com.google.cast.receiver";
static const char *connect_msg = "{\"type\": \"CONNECT\"}";
static const char *ping_msg = "{\"type\": \"PING\"}";
static const char *pong_msg = "{\"type\": \"PONG\"}";
static const char *get_status_msg = "{\"type\": \"GET_STATUS\", \"requestId\": 17}";
static const char *get_app_availability_msg = "{\"type\": \"GET_APP_AVAILABILITY\", \"requestId\": 17, \"appId\": [\"CC1AD845\"]}";
static const char *launch_msg ="{\"type\": \"LAUNCH\", \"requestId\": 17, \"appId\": \"CC1AD845\"}";

bool tls_send_msg (SSL *ssl, const char *namespace, const char *payload);
SSL *tls_socket_setup (int *out_sk, char *ip);
void tls_read (SSL *ssl);

#endif
