#ifndef _APP_H
#define _APP_H

enum fds
{
    MDNS_FD = 0,
    TLS_FD,
    WEB_FD,
    WEB_CLIENT_FD_START,

    MAX_FD = 32
};

char *app_state (void);
int app_nfds (void);

#endif
