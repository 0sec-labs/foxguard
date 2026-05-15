// Positive fixture: older conn_event.c RESPONSE dispatch calls the security
// verifier directly with the original skb. No cloned/nonlinear copy gate
// dominates the in-place verifier.
//
// Synthetic minimal reproducer — NOT copied from kernel source. It models the
// direct dispatch shape present in Linux v6.14 conn_event.c.
// MUST be flagged by kernel/dirty-frag/rxrpc-response-no-nonlinear-unshare.

struct sk_buff;
struct rxrpc_connection;

struct rxrpc_security {
        int (*verify_response)(struct rxrpc_connection *conn,
                               struct sk_buff *skb);
        int (*init_connection_security)(struct rxrpc_connection *conn,
                                        void *token);
};

struct rxrpc_connection {
        struct rxrpc_security *security;
        void *key;
};

enum {
        RXRPC_PACKET_TYPE_RESPONSE = 13,
};

struct rxrpc_skb_priv {
        struct {
                int type;
        } hdr;
};

extern struct rxrpc_skb_priv *rxrpc_skb(struct sk_buff *skb);

static int rxrpc_process_event(struct rxrpc_connection *conn,
                               struct sk_buff *skb)
{
        struct rxrpc_skb_priv *sp = rxrpc_skb(skb);
        int ret;

        switch (sp->hdr.type) {
        case RXRPC_PACKET_TYPE_RESPONSE:
                ret = conn->security->verify_response(conn, skb);
                if (ret < 0)
                        return ret;
                return conn->security->init_connection_security(conn, conn->key);
        default:
                return -71;
        }
}
