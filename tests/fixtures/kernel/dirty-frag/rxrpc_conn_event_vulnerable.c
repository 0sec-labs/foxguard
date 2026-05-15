// Positive fixture: RxRPC RESPONSE verification copied only cloned skbs before
// calling the in-place security verifier. Non-linear-but-uncloned skbs can
// still carry splice-backed page-cache frags into the decrypt path.
//
// Synthetic minimal reproducer — NOT copied from kernel source. It models the
// conn_event.c rxrpc_verify_response wrapper shape from the RxRPC fix series.
// MUST be flagged by kernel/dirty-frag/rxrpc-response-no-nonlinear-unshare.

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
extern struct sk_buff *skb_copy(struct sk_buff *skb, unsigned int flags);
extern void rxrpc_new_skb(struct sk_buff *skb, int trace);
extern void rxrpc_free_skb(struct sk_buff *skb, int trace);
extern void rxrpc_see_skb(struct sk_buff *skb, int trace);

static int rxrpc_verify_response(struct rxrpc_connection *conn,
                                 struct sk_buff *skb)
{
        int ret;

        if (skb_cloned(skb)) {
                struct sk_buff *nskb = skb_copy(skb, 0);

                if (nskb) {
                        rxrpc_new_skb(nskb, 1);
                        ret = conn->security->verify_response(conn, nskb);
                        rxrpc_free_skb(nskb, 2);
                } else {
                        rxrpc_see_skb(skb, 3);
                        ret = -12;
                }
        } else {
                ret = conn->security->verify_response(conn, skb);
        }

        return ret;
}
