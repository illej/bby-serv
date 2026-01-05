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

#define WEB_CLIENT_MAX (MAX_FD - WEB_CLIENT_FD_START)
#define APP_INFO_LEN 512

char *app_state (void);
int app_nfds (void);

#endif
