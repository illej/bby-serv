#include <stdbool.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "cast.h"
#include "util.h"
#include "event.h"

#include <pb_encode.h>
#include <pb_decode.h>
#include "pb_encode.c"
#include "pb_decode.c"
#include "pb_common.c"
#include "cast_channel.pb.h"

#include <tiny-json.h>

#define OPENSSL_DUMP_ERR() \
    do { \
        int err; \
        while ((err = ERR_get_error ())) \
        { \
            printf ("OpenSSL Error: %s\n", ERR_error_string (err, NULL)); \
        } \
    } while (0)

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
//            printf ("%d %s : %" PRIu64 "\n", tag.fieldno, field_str (tag.fieldno), varint);
        }
        else if (tag.wire == LEN)
        {
            bytes += decode_varint (buf + bytes, &varint);
 //           printf ("%d %s : %s(%" PRIu64 ") '%.*s'\n", tag.fieldno, field_str (tag.fieldno), wire_str (tag.wire), varint, (int) varint, (char *) buf + bytes);
            bytes += (int) varint;
        }
    }

    //printf ("consumed %d bytes (out of %d)\n", bytes, len);

    pb_istream_t stream = pb_istream_from_buffer ((uint8_t *) buf, rlen);
    int ret = pb_decode (&stream, extensions_api_cast_channel_CastMessage_fields, &rmsg);

    //printf ("decode ok=%d\n", ret);
    if (ret)
    {
//        printf ("version        : %d\n", rmsg.protocol_version);
//        printf ("source-id      : %s\n", (char *) rmsg.source_id.arg);
//        printf ("destination-id : %s\n", (char *) rmsg.destination_id.arg);
//        printf ("namespace      : %s\n", (char *) rmsg.namespace.arg);
//        printf ("payload-utf8   : %s\n", (char *) rmsg.payload_utf8.arg);

        bool ok;

        /* We've received valid messages from the chromecast so we're now
         * officially connected */
        event (EVENT_CONNECTED, NULL);

        if (strstr (rmsg.payload_utf8.arg, "PING"))
        {
            printf ("tls: <- PING\n");
            enqueue (TLS_SEND_PONG, 0);
#if 0
            ok = send_msg (ssl, send_buf, sizeof (send_buf), heartbeat_ns, pong_msg);
            if (ok)
            {
                printf ("> PONG\n");

                if (0)
                    http_event_send ("Connected");
            }
            if (0)
                send_msg (ssl, send_buf, sizeof (send_buf), receiver_ns, get_status_msg);
            if (0)
                send_msg (ssl, send_buf, sizeof (send_buf), receiver_ns, get_app_availability_msg);
            if (0)
                send_msg (ssl, send_buf, sizeof (send_buf), receiver_ns, launch_msg);
#endif
        }
        else if (strstr (rmsg.payload_utf8.arg, "PONG"))
        {
            printf ("tls: <- P0NG\n");
            enqueue (TLS_SEND_PING, 5000);

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


bool
tls_send_msg (SSL *ssl, const char *namespace, const char *payload)
{
    static uint8_t send_buf[4094];
    size_t send_len = sizeof (send_buf);
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
        printf ("tls: send failed\n");
    }

    return ok;
}


/*
 * https://docs.openssl.org/3.3/man7/ossl-guide-tls-client-block
 */
SSL *
tls_socket_setup (int *out_sk, char *ip)
{
    struct sockaddr_in addr;
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    BIO *bio = NULL;
    int sk;
    bool ok;

    printf ("tls: socket setup\n");
    
    SSL_library_init ();
    SSL_load_error_strings ();

    sk = socket (AF_INET, SOCK_STREAM, 0);
    printf ("tls: socket=%d\n", sk);
    if (sk > -1)
    {
        addr.sin_family = AF_INET;
        addr.sin_port = htons (8009);
        inet_pton (AF_INET, ip, &addr.sin_addr);

        printf ("tls: connecting with %s\n", ip);
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

                printf ("tls: SSL connect: %d\n", ret);

                *out_sk = sk;

                ok = tls_send_msg (ssl, connection_ns, connect_msg);
                if (ok)
                {
#if 0
                    ok = send_msg (ssl, send_buf, sizeof (send_buf), receiver_ns, get_status_msg);
                    printf ("TLS: send GET_STATUS: %s\n", ok ? "OK" : "Failed");
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
            printf ("Failed to connect to server %s\n", ip);
        }
    }
    else
    {
        perror ("Failed to open socket\n");
    }

    printf ("tls: setup: %s\n", ok ? "OK" : "Failed");
out:
    return ssl;
}

void
tls_read (SSL *ssl)
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
        hex_dump (recv_buf, rd);
#endif

        parse_recv_msg (recv_buf, rd, ssl);
    }

    if (SSL_get_error (ssl, 0) != SSL_ERROR_ZERO_RETURN) {
        OPENSSL_DUMP_ERR ();
    }
}

