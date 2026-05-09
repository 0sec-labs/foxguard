// Positive fixture (Tier 1 sibling): in-place AEAD ICV verify on skb without
// a cow gate. Models the structural shape of net/ipv4/ah4.c::ah_input and
// net/ipv6/ah6.c::ah6_input, where the integrity-check path uses
// aead_request_set_crypt(req, sg, sg, ...) + crypto_aead_decrypt(req).
//
// Synthetic minimal reproducer — NOT copied from kernel source. Authored from
// the patch-hunk shape alone to exercise the regex on a sibling protocol.
// MUST be flagged by kernel/dirty-frag/skb-inplace-aead-no-cow.


/* Tree-sitter fixture — scanned as text by foxguard, never compiled.
 * Kernel headers replaced with the inline forward decls below to keep clangd quiet. */
struct sk_buff;
struct aead_request;
struct scatterlist;

extern int skb_to_sgvec_nomark(struct sk_buff *skb, struct scatterlist *sg,
                               int off, int len);
extern void aead_request_set_crypt(struct aead_request *req,
                                   struct scatterlist *src,
                                   struct scatterlist *dst,
                                   unsigned int cryptlen, void *iv);
extern int crypto_aead_decrypt(struct aead_request *req);

int ah4_input(struct sk_buff *skb,
              struct aead_request *req,
              struct scatterlist *sg,
              unsigned int icv_len, void *iv)
{
        /* AH integrity check: builds an SGL over the skb (incl. shared frags
         * from MSG_SPLICE_PAGES on the egress side) and runs an in-place
         * AEAD decrypt to verify. No skb_cow_data / pskb_expand_head /
         * skb_unshare on this path. */
        skb_to_sgvec_nomark(skb, sg, 0, icv_len);
        aead_request_set_crypt(req, sg, sg, icv_len, iv);
        return crypto_aead_decrypt(req);
}
