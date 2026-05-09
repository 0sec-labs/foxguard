// Positive fixture (Tier 1 sibling): in-place skcipher decrypt on skb without
// a cow gate. Models the structural shape of net/ipv4/ipcomp.c and
// net/ipv6/ipcomp6.c (decompression-adjacent decrypt path), where the
// callee may invoke skcipher in-place over an skb with shared frags.
//
// Synthetic minimal reproducer — NOT copied from kernel source. Authored
// from the patch-hunk shape alone to exercise the regex on a sibling site.
// MUST be flagged by kernel/dirty-frag/skb-inplace-skcipher-no-cow.


/* Tree-sitter fixture — scanned as text by foxguard, never compiled.
 * Kernel headers replaced with the inline forward decls below to keep clangd quiet. */
struct sk_buff;
struct skcipher_request;
struct scatterlist;

extern int skb_to_sgvec(struct sk_buff *skb, struct scatterlist *sg,
                        int off, int len);
extern void skcipher_request_set_crypt(struct skcipher_request *req,
                                       struct scatterlist *src,
                                       struct scatterlist *dst,
                                       unsigned int cryptlen, void *iv);
extern int crypto_skcipher_decrypt(struct skcipher_request *req);

int ipcomp_decompress_inplace(struct sk_buff *skb,
                              struct skcipher_request *req,
                              struct scatterlist *sg,
                              unsigned int len, void *iv)
{
        /* No cow / unshare / make-writable here: caller's gate only checks
         * skb_cloned, missing splice()-shared non-linear frags. */
        skb_to_sgvec(skb, sg, 0, len);
        skcipher_request_set_crypt(req, sg, sg, len, iv);
        return crypto_skcipher_decrypt(req);
}
