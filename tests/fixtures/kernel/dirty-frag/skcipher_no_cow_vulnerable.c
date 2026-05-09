// Positive fixture: in-place skcipher decrypt on skb without cow gate.
// Models net/rxrpc/rxkad.c::rxkad_verify_packet_1 (pre-patch).
// MUST be flagged by kernel/dirty-frag/skb-inplace-skcipher-no-cow.


/* Tree-sitter fixture — scanned as text by foxguard, never compiled.
 * Kernel headers replaced with the inline forward decls below to keep clangd quiet. */
struct sk_buff;
struct skcipher_request;
struct scatterlist;

extern int skb_to_sgvec(struct sk_buff *skb, struct scatterlist *sg, int off, int len);
extern void skcipher_request_set_crypt(struct skcipher_request *req,
                                       struct scatterlist *src,
                                       struct scatterlist *dst,
                                       unsigned int cryptlen, void *iv);
extern int crypto_skcipher_decrypt(struct skcipher_request *req);

int rxkad_verify_packet_1(struct sk_buff *skb,
                          struct skcipher_request *req,
                          struct scatterlist *sg,
                          unsigned int len, void *iv)
{
        /* No skb_cow_data / skb_unshare / pskb_expand_head call here:
         * the gate upstream of us only checked skb_cloned, missing
         * non-linear-but-unshared skbs from splice(). */
        skb_to_sgvec(skb, sg, 0, len);
        skcipher_request_set_crypt(req, sg, sg, len, iv);
        return crypto_skcipher_decrypt(req);
}
