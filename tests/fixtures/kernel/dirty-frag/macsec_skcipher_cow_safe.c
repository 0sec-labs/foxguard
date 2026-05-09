// Negative fixture (Tier 2 known-FP): MACsec / dm-crypt-style in-place
// skcipher decrypt that is safe because a cow gate dominates the call.
// Exercises an additional cow-gate name (skb_copy_expand) that appears in
// some L2 receive paths and shows the rule does not over-fire on legitimate
// in-place crypto AFTER cow.
//
// MUST NOT be flagged by kernel/dirty-frag/skb-inplace-skcipher-no-cow.


/* Tree-sitter fixture — scanned as text by foxguard, never compiled.
 * Kernel headers replaced with the inline forward decls below to keep clangd quiet. */
struct sk_buff;
struct skcipher_request;
struct scatterlist;

extern struct sk_buff *skb_copy_expand(const struct sk_buff *skb,
                                       int newheadroom, int newtailroom,
                                       unsigned int gfp_mask);
extern int skb_to_sgvec(struct sk_buff *skb, struct scatterlist *sg,
                        int off, int len);
extern void skcipher_request_set_crypt(struct skcipher_request *req,
                                       struct scatterlist *src,
                                       struct scatterlist *dst,
                                       unsigned int cryptlen, void *iv);
extern int crypto_skcipher_decrypt(struct skcipher_request *req);

int macsec_decrypt_safe(struct sk_buff *skb,
                        struct skcipher_request *req,
                        struct scatterlist *sg,
                        unsigned int len, void *iv)
{
        /* Allocate a fresh non-shared skb up-front, defeating the splice()-
         * shared-frag aliasing that Dirty Frag relies on. */
        struct sk_buff *fresh = skb_copy_expand(skb, 0, 0, 0);
        if (!fresh)
                return -1;
        skb_to_sgvec(fresh, sg, 0, len);
        skcipher_request_set_crypt(req, sg, sg, len, iv);
        return crypto_skcipher_decrypt(req);
}
