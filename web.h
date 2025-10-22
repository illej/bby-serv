#ifndef _WEB_H
#define _WEB_H

#include <stdbool.h>
#include <poll.h>
#include "util.h"

struct web_server
{
    u16 port;
    int listen_sk;

    struct pollfd *clients;
    int client_count;
    u32 streaming;
};

bool http_init (struct web_server *web, struct pollfd *clients, u16 port);
void http_send (int sk, char *buf, size_t len, char *type);
void http_event_send (struct web_server *web, char *msg);
void http_event_send_start (int csk);
void http_accept (struct web_server *web);
int http_read (struct web_server *web, int csk);
bool http_listen_socket_setup (struct web_server *web);

#endif
