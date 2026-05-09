// Negative fixture (Tier 2 known-FP): kTLS-style in-place AEAD decrypt that
// is safe because a cow / unshare gate dominates. Exercises the negative
// regex against an additional cow-gate name (__skb_cow) seen in some TLS
// receive paths and skbuff helpers.
//
// MUST NOT be flagged by kernel/dirty-frag/skb-inplace-aead-no-cow.


/* Tree-sitter fixture — scanned as text by foxguard, never compiled.
 * Kernel headers replaced with the inline forward decls below to keep clangd quiet. */
struct sk_buff;
struct aead_request;
struct scatterlist;

extern int __skb_cow(struct sk_buff *skb, unsigned int headroom, int cloned);
extern int skb_to_sgvec(struct sk_buff *skb, struct scatterlist *sg,
                        int off, int len);
extern void aead_request_set_crypt(struct aead_request *req,
                                   struct scatterlist *src,
                                   struct scatterlist *dst,
                                   unsigned int cryptlen, void *iv);
extern int crypto_aead_decrypt(struct aead_request *req);

int tls_decrypt_inplace_safe(struct sk_buff *skb,
                             struct aead_request *req,
                             struct scatterlist *sg,
                             unsigned int len, void *iv)
{
        /* kTLS-style: copy-on-write the skb pages before the in-place
         * AEAD decrypt. The negative regex must suppress this shape. */
        int err = __skb_cow(skb, 0, 1);
        if (err)
                return err;
        skb_to_sgvec(skb, sg, 0, len);
        aead_request_set_crypt(req, sg, sg, len, iv);
        return crypto_aead_decrypt(req);
}
