#include <mdns.h>

#include "event.h"

int
mdns_setup (void)
{
    int sk = mdns_socket_open_ipv4 (NULL);

    printf ("mdns: open socket: %d\n", sk);

#if 0
    if (mdns_discovery_send (sk) != 0)
    {
        printf ("Failed to send DNS-DS discovery: %s\n", strerror (errno));
    }

    unsigned char buf[2048];
    size_t records = 0;
    int ret = 0;

    struct pollfd pfds[1];
    int timeout = 5000;

    pfds[0].fd = sk;
    pfds[0].events = POLLIN;

    do {
        printf ("mdns: wait for response (timeout=%d)\n", timeout);
        ret = poll (pfds, 1, timeout);
        printf ("mdns: ret=%d\n", ret);
        if (ret > 0)
        {
            timeout = 100;
            for (int i = 0; i < 1; i++)
            {
                if (pfds[i].revents & POLLIN)
                {
                    int sk = pfds[i].fd;
                    records += mdns_discovery_recv (sk, buf, sizeof (buf), _query_cb, NULL);
                    printf ("records: %zu\n", records);
                }
            }
        }
    } while (ret > 0);

    mdns_socket_close (sk);

    return records > 0;
#endif

    return sk;
}

static int
_query_cb (int sk, const struct sockaddr *from, size_t from_len, mdns_entry_type_t entry, uint16_t query_id, uint16_t rtype,
        uint16_t rclass, uint32_t ttl, const void *data,
        size_t size, size_t name_offset, size_t name_len, size_t record_offset, size_t record_len, void *user_data)
{
    char ipstr[INET6_ADDRSTRLEN];
    char entrybuf[256];
    char namebuf[256];

    inet_ntop (from->sa_family, &((struct sockaddr_in *) from)->sin_addr, ipstr, sizeof (ipstr));

    const char *entrytype = (entry == MDNS_ENTRYTYPE_ANSWER) ? "answer" :
                            ((entry == MDNS_ENTRYTYPE_AUTHORITY) ? "authority" : "additional");
    mdns_string_t entrystr = mdns_string_extract (data, size, &name_offset, entrybuf, sizeof(entrybuf));

    if (rtype == MDNS_RECORDTYPE_PTR) {
        mdns_string_t namestr = mdns_record_parse_ptr (data, size, record_offset, record_len, namebuf, sizeof (namebuf));

        printf ("  %s : %s %.*s PTR %.*s rclass 0x%x ttl %u length %zu\n",
                ipstr, entrytype, MDNS_STRING_FORMAT (entrystr),
                MDNS_STRING_FORMAT (namestr), rclass, ttl, record_len);

        char *chromecast = "_googlecast._tcp.local";

        if (strncmp (namestr.str, chromecast, strlen (chromecast)) == 0)
        {
            printf ("> chromecase found at %s\n", ipstr);
//            snprintf (app.chromecast_ip, sizeof (app.chromecast_ip), "%s", ipstr);
            event (EVENT_FOUND, ipstr);
        }
    }

    return 0;
}

void
mdns_send (int sk)
{
    printf ("mdns: send\n");

    mdns_discovery_send (sk);
}

void
mdns_recv (int sk)
{
    u8 mdns_rbuf[2048] = {};

    // TODO: pass (app.)cast.ip in as user_data
    mdns_discovery_recv (sk, mdns_rbuf, sizeof (mdns_rbuf), _query_cb, NULL);
}
