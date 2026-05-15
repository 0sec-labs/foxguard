// Negative fixture: RxRPC RESPONSE verification copies cloned or non-linear
// skbs before calling the in-place security verifier.
//
// Synthetic minimal reproducer — NOT copied from kernel source.
// MUST NOT be flagged by kernel/dirty-frag/rxrpc-response-no-nonlinear-unshare.

struct sk_buff;
struct rxrpc_connection;

struct rxrpc_security {
        int (*verify_response)(struct rxrpc_connection *conn,
                               struct sk_buff *skb);
};

struct rxrpc_connection {
        struct rxrpc_security *security;
};

extern int skb_cloned(struct sk_buff *skb);
extern int skb_is_nonlinear(struct sk_buff *skb);
extern struct sk_buff *skb_copy(struct sk_buff *skb, unsigned int flags);
extern void rxrpc_new_skb(struct sk_buff *skb, int trace);
extern void rxrpc_free_skb(struct sk_buff *skb, int trace);

static int rxrpc_verify_response(struct rxrpc_connection *conn,
                                 struct sk_buff *skb)
{
        int ret;

        if (skb_cloned(skb) || skb_is_nonlinear(skb)) {
                struct sk_buff *nskb = skb_copy(skb, 0);

                if (!nskb)
                        return -12;

                rxrpc_new_skb(nskb, 1);
                ret = conn->security->verify_response(conn, nskb);
                rxrpc_free_skb(nskb, 2);
        } else {
                ret = conn->security->verify_response(conn, skb);
        }

        return ret;
}
