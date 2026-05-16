// Positive fixture: RxRPC RESPONSE dispatch reaches an opaque verify_response
// backend that performs the actual in-place decrypt elsewhere.
// Models net/rxrpc/conn_event.c on Linux v6.14, where the advisory-named file
// only calls conn->security->verify_response(conn, skb).
// MUST be flagged by kernel/dirty-frag/rxrpc-verify-response-dispatch.

/* Tree-sitter fixture — scanned as text by foxguard, never compiled.
 * Kernel headers replaced with the inline forward decls below to keep clangd quiet. */
struct sk_buff;

struct rxrpc_connection;

struct rxrpc_security {
        int (*verify_response)(struct rxrpc_connection *conn, struct sk_buff *skb);
        int (*init_connection_security)(struct rxrpc_connection *conn, void *token);
};

struct rxrpc_connection {
        int state;
        struct rxrpc_security *security;
};

enum rxrpc_packet_type {
        RXRPC_PACKET_TYPE_CHALLENGE = 1,
        RXRPC_PACKET_TYPE_RESPONSE = 2,
};

int rxrpc_process_event(struct rxrpc_connection *conn,
                        struct sk_buff *skb,
                        int packet_type)
{
        int ret;

        switch (packet_type) {
        case RXRPC_PACKET_TYPE_CHALLENGE:
                return 0;
        case RXRPC_PACKET_TYPE_RESPONSE:
                /* The decrypt is hidden behind the security backend, so the
                 * generic skcipher rule cannot see it from this file alone. */
                ret = conn->security->verify_response(conn, skb);
                if (ret < 0)
                        return ret;
                return conn->security->init_connection_security(conn, 0);
        default:
                return -1;
        }
}
