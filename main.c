#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <string.h>
#include <stdbool.h>

#include <mdns.h>

#include <netdb.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <sys/time.h>
#include <errno.h>

#include <pb_encode.h>
#include <pb_decode.h>
#include "cast_channel.pb.h"

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#include <tiny-json.h>

#include <poll.h>
#include <dirent.h>

typedef uint64_t u64;
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t  u8;


struct movie
{
    u8 index;
    char *name;
};

static struct movie *movies;
static int movie_count;

static char g__chromecast_ip[INET6_ADDRSTRLEN];
static bool g__chromecast_found;
static uint8_t send_buf[4094];

static const char *connection_ns = "urn:x-cast:com.google.cast.tp.connection";
static const char *heartbeat_ns = "urn:x-cast:com.google.cast.tp.heartbeat";
static const char *receiver_ns = "urn:x-cast:com.google.cast.receiver";
static const char *connect_msg = "{\"type\": \"CONNECT\"}";
static const char *ping_msg = "{\"type\": \"PING\"}";
static const char *pong_msg = "{\"type\": \"PONG\"}";
static const char *get_status_msg = "{\"type\": \"GET_STATUS\", \"requestId\": 17}";
static const char *get_app_availability_msg = "{\"type\": \"GET_APP_AVAILABILITY\", \"requestId\": 17, \"appId\": [\"CC1AD845\"]}";
static const char *launch_msg ="{\"type\": \"LAUNCH\", \"requestId\": 17, \"appId\": \"CC1AD845\"}";

/*
 * TODO:
 *  - actually control the player via "urn:x-cast:com.google.cast.media"
 *    See:
 *      https://developers.google.com/cast/docs/media/messages
 *      https://developers.google.com/cast/docs/media
 *
 * - do web server
 */


#define OPENSSL_DUMP_ERR() \
    do { \
        int err; \
        while ((err = ERR_get_error ())) \
        { \
            printf ("OpenSSL Error: %s\n", ERR_error_string (err, NULL)); \
        } \
    } while (0)

static char
ascii_ (uint8_t val)
{
    if (val > 31 && val < 127)
        return val;
    return ' ';
}

static void
hex_dump (u8 *buf, size_t len)
{
    char line[1024];
    char ascii[512];
    int l = 0;
    char *linep = line;
    char *asciip = ascii;

    printf ("------------------- Hex Dump ------------------\n");

    for (int i = 0; i < len; i++)
    {
        if ((i % 8) == 0 && i != 0)
        {
            printf ("%02d:  %-24s\t%s\n", l++, line, ascii);
            linep = line;
            asciip = ascii;
        }

        linep += sprintf (linep, "%02x ", buf[i]);
        asciip += sprintf (asciip, "%c ", ascii_ (buf[i]));
    }

    if (linep != line)
    {
        printf ("%02d:  %-24s\t%s\n", l, line, ascii);
    }

    printf ("\nBytes: %u\n", len);
    printf ("-----------------------------------------------\n");
}

static void
json_dump (json_t const *json, int indent)
{
    json_t const* child;
    jsonType_t const type = json_getType (json);

    if (type != JSON_OBJ && type != JSON_ARRAY) {
        printf ("Can't dump json\n");
        return;
    }

    printf ("%s\n", type == JSON_OBJ? "{": "[");

    indent++;

    for(child = json_getChild (json); child != 0; child = json_getSibling (child))
    {
        jsonType_t propertyType = json_getType (child);
        char const* name = json_getName (child);

        if (name)
        {
            printf ("%*s\"%s\": ", indent * 4, "", name);
        }

        if (propertyType == JSON_OBJ || propertyType == JSON_ARRAY)
        {
            if (type == JSON_ARRAY)
            {
                printf ("%*s", indent * 4, "");
            }

            json_dump (child, indent);
        }
        else
        {
            char const *value = json_getValue (child);
            if (value)
            {
                bool const text = JSON_TEXT == json_getType (child);
                char const* fmt = text ? "\"%s\"" : "%s";

                printf (fmt, value);
            }
        }

        bool const last = !json_getSibling (child);
        if (last)
            printf ("\n");
        else
            printf (",\n");
    }

    indent--;

    printf ("%*s%s", indent * 4, "", type == JSON_OBJ? "}": "]");

    if (indent == 0)
    {
        printf ("\n");
    }
}

static bool
encode_string (pb_ostream_t *stream, const pb_field_iter_t *field, void * const *arg)
{
    const char *str = (const char *) (*arg);

    if (pb_encode_tag_for_field (stream, field))
        return pb_encode_string (stream, (unsigned char *) str, strlen (str));

    return false;
}

/*
 * https://jpa.kapsi.fi/nanopb/docs/concepts.html#decoding-callbacks
 */
static bool
decode_string (pb_istream_t *stream, const pb_field_iter_t *field, void **arg)
{
    if (field && PB_LTYPE (field->type) == PB_LTYPE_STRING)
    {
        *arg = malloc (stream->bytes_left + 1);
        memset (*arg, 0, stream->bytes_left + 1);

        return pb_read (stream, *arg, stream->bytes_left);
    }

    return false;
}

/**
 * CASTv2 protocol description: docs.rs/crate/gcast/latest/source/PROTOCOL.md
 */

static bool
http_listen_socket_setup (int port, int *sk_out)
{
	struct sockaddr_in server_addr = {
		.sin_family = AF_INET,
		.sin_port = htons (port),
		.sin_addr.s_addr = INADDR_ANY,
	};
	int opt = 1;
	int sk = -1;
	bool ok = false;

	if ((sk = socket (AF_INET, SOCK_STREAM, 0)) < 0)
	{
		perror ("Failed to open socket");
	}
	else if (setsockopt (sk, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof (opt)) != 0)
	{
		perror ("Failed to set SO_REUSEADDR");
	}
	else if (bind (sk, (struct sockaddr *) &server_addr, sizeof (server_addr)) != 0)
	{
		perror ("Failed to bind socket");
	}
	else if (listen (sk, 10) != 0)
	{
		perror ("Failed to listen on socket");
	}
	else
	{
		*sk_out = sk;
		ok = true;
	}

	if (!ok)
	{
		close (sk);
	}

	return ok;
}

static int
build_response (char *buf, size_t len)
{
    FILE *fp;
    int wr = 0;
    long fsize = 0;
    char *html;

    fp = fopen ("index.html", "r");
    if (fp)
    {
        fseek (fp, 0, SEEK_END);
        fsize = ftell (fp);
        fseek (fp, 0, SEEK_SET);

        html = malloc (fsize + 1);
        fread (html, fsize, 1, fp);
        html[fsize] = 0;

        printf ("html len=%ld\n", fsize);

        wr += snprintf (buf + wr, len - wr, "HTTP/1.1 200 OK\r\n");
        wr += snprintf (buf + wr, len - wr, "Content-Type: text/html\r\n");
        wr += snprintf (buf + wr, len - wr, "Content-Length: %ld\r\n", fsize);
        wr += snprintf (buf + wr, len - wr, "\r\n");
        wr += snprintf (buf + wr, len - wr, "%s", html);

        printf ("written=%d\n", wr);

        fclose (fp);
        free (html);
    }

    return wr;
}

static void
http_read (int sk)
{
    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof (client_addr);
    char buf[65535] = {};

    printf ("http_read> Waiting to accept connection..\n");

    int csk = accept (sk, (struct sockaddr *) &client_addr, &addr_len);
    if (csk < 0)
    {
        perror ("Failed to accept connection");
        return;
    }

    int nread = read (csk, buf, sizeof (buf) - 1);
    if (nread < 0)
    {
        printf ("Read failed: errno=%d '%s'\n", errno, strerror (errno));
        return;
    }

    hex_dump ((u8 *) buf, nread);

    printf ("> %s\n", buf);

    char *method = strtok (buf, " \t\r\n");
    char *uri = strtok (NULL, " \t");
    char *proto = strtok (NULL, " \t\r\n");
    int send_len = 0;

    printf ("method   : '%s'\n", method);
    printf ("uri      : '%s'\n", uri);
    printf ("protocol : '%s'\n", proto);

    char send_buf[65535] = {};

    if (strcmp (uri, "/") == 0)
    {
        if (strcmp (method, "GET") == 0)
        {
            send_len = build_response (send_buf, sizeof (send_buf));
        }
    }
    else if (strcmp (uri, "/play") == 0)
    {
        if (strcmp (method, "POST") == 0)
        {

        }
    }
    else if (strcmp (uri, "/test") == 0)
    {
        char response[] = 
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: 3\r\n"
            "\r\n"
            "Off";
        send_len = snprintf (send_buf, sizeof (send_buf), "%s", response);
    }

    printf ("sending:\n");
    printf ("%s\n", send_buf);

    int nwritten = write (csk, send_buf, send_len);
    printf ("sent=%d\n", nwritten);
    if (nwritten < 0)
    {
        perror ("Write error");
    }
}


static bool
send_msg (SSL *ssl, uint8_t *send_buf, size_t send_len, const char *namespace, const char *payload)
{
    extensions_api_cast_channel_CastMessage msg = extensions_api_cast_channel_CastMessage_init_zero;
    pb_ostream_t stream;
    size_t wr;
    bool ok ;

    memset (send_buf, 0, send_len);

    stream = pb_ostream_from_buffer (send_buf + 4, send_len - 4);

    msg.protocol_version = extensions_api_cast_channel_CastMessage_ProtocolVersion_CASTV2_1_0;
    msg.source_id.arg = (void *) "sender-0";
    msg.source_id.funcs.encode = encode_string;
    msg.destination_id.arg = (void *) "receiver-0";
    msg.destination_id.funcs.encode = encode_string;
    msg.namespace.arg = (void *) namespace;
    msg.namespace.funcs.encode = encode_string;
    msg.payload_type = extensions_api_cast_channel_CastMessage_PayloadType_STRING;
    msg.payload_utf8.arg = (void *) payload;
    msg.payload_utf8.funcs.encode = encode_string;

    ok = pb_encode (&stream, extensions_api_cast_channel_CastMessage_fields, &msg);
    if (ok)
    {
        send_buf[0] = (stream.bytes_written >> 24) & 0xFF;
        send_buf[1] = (stream.bytes_written >> 16) & 0xFF;
        send_buf[2] = (stream.bytes_written >>  8) & 0xFF;
        send_buf[3] = (stream.bytes_written >>  0) & 0xFF;

        ok = SSL_write_ex (ssl, send_buf, stream.bytes_written + 4, &wr);
        if (ok)
        {
//            hex_dump (send_buf, wr);
        }
    }

    if (!ok)
    {
        printf ("Send failed\n");
    }

    return ok;
}

enum wire_type
{
    VARINT = 0,
    I64,
    LEN,
    SGROUP,
    EGROUP,
    I32
};

static char *
wire_str (u8 wire)
{
    char *str;

    switch (wire)
    {
        case VARINT: { str = "VARINT"; } break;
        case I64:    { str = "I64";    } break;
        case LEN:    { str = "LEN";    } break;
        case SGROUP: { str = "SGROUP"; } break;
        case EGROUP: { str = "EGROUP"; } break;
        case I32:    { str = "I32";    } break;
        default:     { str = "??";     } break;
    }

    return str;
}

static char *
field_str (u8 fieldno)
{
    char *str;

    // TODO: replace raw ints with extensions_api_cast_channel_CastMessage_*_tag (maybe..)
    switch (fieldno)
    {
        case 1:  { str = "protocol-version"; } break;
        case 2:  { str = "source-id";        } break; 
        case 3:  { str = "destination-id";   } break;
        case 4:  { str = "namespace";        } break;
        case 5:  { str = "payload-type";     } break;
        case 6:  { str = "payload-utf8";     } break;
        case 7:  { str = "payload-binary";   } break;
        default: { str = "??";               } break;
     }

     return str;
}

struct tag
{
    u8 fieldno;
    u8 wire;
};

static int
decode_varint (u8 *buf, u64 *varint)
{
    int bytes = 0;

    for (int i = 0; i < 10; i++)
    {
        u8 b = buf[i];

        *varint |= (u64) (b & 0x7F) << (i * 7);
        bytes++;

        if ((b & 0x80) == 0)
            break;
    }

    return bytes;
}

static int
decode_tag (u8 *buf, size_t len, struct tag *tag)
{
    u64 varint = 0;
    int bytes = 0;

    bytes += decode_varint (buf, &varint);

    tag->fieldno = varint >> 3;
    tag->wire = varint & 0x07;

    return bytes;
}

static void
parse_recv_msg (u8 *buf, size_t len, SSL *ssl)
{
    extensions_api_cast_channel_CastMessage rmsg = extensions_api_cast_channel_CastMessage_init_zero;

    rmsg.source_id.funcs.decode = decode_string;
    rmsg.destination_id.funcs.decode = decode_string;
    rmsg.namespace.funcs.decode = decode_string;
    rmsg.payload_utf8.funcs.decode = decode_string;

    uint32_t rlen = (buf[0] << 24) + (buf[1] << 16) + (buf[2] << 8) + (buf[3] << 0);
    buf += 4;
    len -= 4;

    /**
     * https://protobuf.dev/programming-guides/encoding/
     *
     * Field numbers (defined by cast_channel.proto):
     * 1 = protocol-version
     * 2 = source_id
     * 3 = destination_id
     * 4 = namespace
     * 5 = payload_type
     * 6 = payload_utf8
     * 7 = payload_binary
     *
     * Wire-type:
     * 0 = VARINT
     * 1 = I64
     * 2 = LEN
     * 3 = SGROUP
     * 4 = EGROUP
     * 5 = I32
     *
     * Tag:
     *   (field_number << 3) | wire_type
     * 
     * 0000 1000
     */

    int bytes = 0;
    while (bytes < len)
    {
        struct tag tag = {};
        u64 varint = 0;

        bytes += decode_tag (buf + bytes, len - bytes, &tag);
        if (tag.wire == VARINT)
        {
            bytes += decode_varint (buf + bytes, &varint);
            printf ("%d %s : %" PRIu64 "\n", tag.fieldno, field_str (tag.fieldno), varint);
        }
        else if (tag.wire == LEN)
        {
            bytes += decode_varint (buf + bytes, &varint);
            printf ("%d %s : %s(%" PRIu64 ") '%.*s'\n", tag.fieldno, field_str (tag.fieldno), wire_str (tag.wire), varint, (int) varint, (char *) buf + bytes);
            bytes += (int) varint;
        }
    }

    printf ("consumed %d bytes (out of %d)\n", bytes, len);

    pb_istream_t stream = pb_istream_from_buffer ((uint8_t *) buf, rlen);
    int ret = pb_decode (&stream, extensions_api_cast_channel_CastMessage_fields, &rmsg);

    printf ("decode ok=%d\n", ret);
    if (ret)
    {
        printf ("version        : %d\n", rmsg.protocol_version);
        printf ("source-id      : %s\n", (char *) rmsg.source_id.arg);
        printf ("destination-id : %s\n", (char *) rmsg.destination_id.arg);
        printf ("namespace      : %s\n", (char *) rmsg.namespace.arg);
        printf ("payload-utf8   : %s\n", (char *) rmsg.payload_utf8.arg);

        bool ok;
        if (strstr (rmsg.payload_utf8.arg, "PING"))
        {
            printf ("< PING\n");
            ok = send_msg (ssl, send_buf, sizeof (send_buf), heartbeat_ns, pong_msg);
            if (ok)
            {
                printf ("> PONG\n");
            }
            if (0)
                send_msg (ssl, send_buf, sizeof (send_buf), receiver_ns, get_status_msg);
            if (0)
                send_msg (ssl, send_buf, sizeof (send_buf), receiver_ns, get_app_availability_msg);
            if (0)
                send_msg (ssl, send_buf, sizeof (send_buf), receiver_ns, launch_msg);
        }
        else if (strstr (rmsg.payload_utf8.arg, "PONG"))
        {
            ok = send_msg (ssl, send_buf, sizeof (send_buf), heartbeat_ns, ping_msg);
            printf ("PONG: send PING: %s\n", ok ? "OK" : "Failed");
        }
        else if (strstr (rmsg.namespace.arg, "receiver"))
        {
            json_t pool[128];
            const json_t *data;

            printf ("Parsing JSON\n");

#define JSON_INT(DATA, KEY, J) (((J = json_getProperty (DATA, KEY)) && json_getType (J) == JSON_INTEGER) ? json_getInteger (J) : -1) 
#define JSON_STR(DATA, KEY, J) (((J = json_getProperty (DATA, KEY)) && json_getType (J) == JSON_TEXT) ? json_getValue (J) : NULL) 
#define JSON_OBJ(DATA, KEY, J) (((J = json_getProperty (DATA, KEY)) && json_getType (J) == JSON_OBJ) ? json_getValue (J) : NULL) 
            
            data = json_create (rmsg.payload_utf8.arg, pool, sizeof (pool));
            if (data)
            {
                json_dump (data, 0);
            }
            else
            {
                printf ("Failed to parse json\n");
            }
        }
    }
    else
    {
        printf ("Failed to decode message: %s\n", PB_GET_ERROR (&stream));
    }

    free (rmsg.source_id.arg);
    free (rmsg.destination_id.arg);
    free (rmsg.namespace.arg);
    free (rmsg.payload_utf8.arg);
}


static void
ssl_read (SSL *ssl)
{
    size_t rd;
    u8 recv_buf[1024] = {};

    if (!ssl)
    {
        printf ("Invalid SSL object\n");
        return;
    }

    if (SSL_read_ex (ssl, recv_buf, sizeof (recv_buf), &rd))
    {
#if 0
        printf ("rd=%d\n", rd);
        printf ("----------------\n");
        fwrite (recv_buf, 1, rd, stdout);
        printf ("\n");
        printf ("----------------\n");

        hex_dump (recv_buf, rd);
#endif

        parse_recv_msg (recv_buf, rd, ssl);
    }

    if (SSL_get_error (ssl, 0) != SSL_ERROR_ZERO_RETURN) {
        OPENSSL_DUMP_ERR ();
    }
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

	const char* entrytype = (entry == MDNS_ENTRYTYPE_ANSWER) ? "answer" :
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
            snprintf (g__chromecast_ip, sizeof (g__chromecast_ip), "%s", ipstr);
            g__chromecast_found = true;
        }
    }

	return 0;
}

static bool
mdns_setup (void)
{
    int sk = mdns_socket_open_ipv4 (NULL);

    printf ("mdns: open socket: %d\n", sk);
    printf ("mdns: send discovery (sk=%d)\n", sk);

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
}

/*
 * https://docs.openssl.org/3.3/man7/ossl-guide-tls-client-block
 */
static SSL *
chromecast_socket_setup (int *out_sk)
{
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    BIO *bio = NULL;
    int sk;
    bool ok;

    printf ("SSL: socket setup\n");
    
    SSL_library_init ();
    SSL_load_error_strings ();

    sk = socket (AF_INET, SOCK_STREAM, 0);
    if (sk > -1)
    {
        struct sockaddr_in addr;

        addr.sin_family = AF_INET;
        addr.sin_port = htons (8009);
        inet_pton (AF_INET, g__chromecast_ip, &addr.sin_addr);

        if (connect (sk, (struct sockaddr *) &addr, sizeof (addr)) == 0)
        {
            ctx = SSL_CTX_new (TLS_client_method ());
            if (ctx)
            {
                /* The chromecast has a self-signed cert so we
                 * skip verification */
                SSL_CTX_set_verify (ctx, SSL_VERIFY_NONE, NULL);
                SSL_CTX_set_default_verify_paths (ctx); // TODO: probably don't need this then?
                SSL_CTX_set_min_proto_version (ctx, TLS1_2_VERSION);

                ssl = SSL_new (ctx);
                if (!ssl)
                    goto out;

                bio = BIO_new (BIO_s_socket ());
                if (!bio)
                    goto out;

                BIO_set_fd (bio, sk, BIO_CLOSE);
                SSL_set_bio (ssl, bio, bio);

                int ret = SSL_connect (ssl);
                if (ret != 1)
                    goto out;

                printf ("SSL connect: %d\n", ret);

                *out_sk = sk;

                ok = send_msg (ssl, send_buf, sizeof (send_buf), connection_ns, connect_msg);
                if (ok)
                {
#if 0
                    // TODO: don't do this unless we can queue up messages after a delay
                    ok = send_msg (ssl, send_buf, sizeof (send_buf), heartbeat_ns, ping_msg);
                    printf ("send PING: %s\n", ok ? "OK" : "Failed");
#endif
                }
                else
                {
                    printf ("Failed to send message to chromecast\n");
                }
            }
            else
            {
                perror ("Failed to create SSL context");
            }
        }
        else
        {
            printf ("Failed to connect to server %s\n", g__chromecast_ip);
        }
    }
    else
    {
        perror ("Failed to open socket\n");
    }

out:
    return ssl;
}

static bool
movie_list (void)
{
    const char *movie_dir = "/mnt/usb/movies";
    struct movie *movie;
    struct dirent *ent;
    DIR *dir;

    movie_count = 0;

    dir = opendir (movie_dir);
    if (dir)
    {
        printf ("Loading movies from '%s'\n", movie_dir);

        while ((ent = readdir (dir)))
        {
            if (ent->d_type & DT_REG)
            {
                movie_count++;

                movies = realloc (movies, sizeof (struct movie) * movie_count);

                movie = &movies[movie_count - 1];
                movie->index = movie_count - 1;
                movie->name = strdup (ent->d_name);
            }
        }
    }
    else
    {
        printf ("Failed to open directory '%s'. errno=%d '%s'\n", movie_dir, errno, strerror (errno));
    }

    return (movie_count > 0);
}

int
main (int c, char **v)
{
	int port = 5001;
	int web_sk = -1;
    int ssl_sk = -1;
    int nfds = 2;
    struct pollfd pfds[2];
    SSL *ssl = NULL;

    if (!movie_list ())
    {
        printf ("Failed to get movie list\n");
        return 1;
    }

	if (!http_listen_socket_setup (port, &web_sk))
	{
		return 1;
	}

	if (!mdns_setup ())
	{
		return 1;
	}

    if (!g__chromecast_found)
    {
        printf ("Unable to find chromecast\n");
        return 1;
    }

    ssl = chromecast_socket_setup (&ssl_sk);

    if (ssl_sk == -1)
    {
        printf ("Failed to setup SSL socket\n");
        return 1;
    }

	printf ("Baby's First Web Server\n");
    printf ("Chromecast IP: %s\n", g__chromecast_ip);
	printf ("Listening on port %d\n", port);

    pfds[0].fd = web_sk;
    pfds[0].events = POLLIN;
    pfds[1].fd = ssl_sk;
    pfds[1].events = POLLIN;

	while (1)
	{
        printf ("\npolling\n");
        int ret = poll (pfds, nfds, -1);
        if (ret == -1)
        {
            perror ("poll");
            return 1;
        }
        else if (ret > 0)
        {
            for (int i = 0; i < nfds; i++)
            {
                if (pfds[i].revents & POLLIN)
                {
                    printf ("-----------------------\n");
                    printf ("Received Packet (fd=%d)\n", pfds[i].fd);
                    printf ("-----------------------\n");
                    if (pfds[i].fd == web_sk)
                    {
                        http_read (web_sk);
                    }
                    else if (pfds[i].fd == ssl_sk)
                    {
                        ssl_read (ssl);
                    }
                }
            }
        }
	}

    close (web_sk);

	printf ("Exiting\n");
	return 0;
}
