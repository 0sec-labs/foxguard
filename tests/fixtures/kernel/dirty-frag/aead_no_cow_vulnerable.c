// Positive fixture: in-place AEAD decrypt on skb without cow gate.
// Models net/ipv4/esp4.c::esp_input (pre-patch f4c50a4034e62ab).
// MUST be flagged by kernel/dirty-frag/skb-inplace-aead-no-cow.


/* Tree-sitter fixture — scanned as text by foxguard, never compiled.
 * Kernel headers replaced with the inline forward decls below to keep clangd quiet. */
struct sk_buff;
struct aead_request;
struct scatterlist;

extern int skb_to_sgvec(struct sk_buff *skb, struct scatterlist *sg, int off, int len);
extern void aead_request_set_crypt(struct aead_request *req,
                                   struct scatterlist *src,
                                   struct scatterlist *dst,
                                   unsigned int cryptlen, void *iv);
extern int crypto_aead_decrypt(struct aead_request *req);

int esp_input(struct sk_buff *skb,
              struct aead_request *req,
              struct scatterlist *sg,
              unsigned int len, void *iv)
{
        /* Pre-patch: only skb_cloned() check upstream; skip_cow takes the
         * fast path even when skb has shared frags from MSG_SPLICE_PAGES. */
        skb_to_sgvec(skb, sg, 0, len);
        aead_request_set_crypt(req, sg, sg, len, iv);
        return crypto_aead_decrypt(req);
}
