// Negative fixture: in-place AEAD decrypt on skb WITH proper cow gate.
// Models post-patch esp_input with skb_cow_data dominating the in-place
// decrypt path. MUST NOT be flagged.


/* Tree-sitter fixture — scanned as text by foxguard, never compiled.
 * Kernel headers replaced with the inline forward decls below to keep clangd quiet. */
struct sk_buff;
struct aead_request;
struct scatterlist;

extern int skb_cow_data(struct sk_buff *skb, int tailbits, struct sk_buff **trailer);
extern int skb_to_sgvec(struct sk_buff *skb, struct scatterlist *sg, int off, int len);
extern void aead_request_set_crypt(struct aead_request *req,
                                   struct scatterlist *src,
                                   struct scatterlist *dst,
                                   unsigned int cryptlen, void *iv);
extern int crypto_aead_decrypt(struct aead_request *req);

int esp_input_safe(struct sk_buff *skb,
                   struct aead_request *req,
                   struct scatterlist *sg,
                   unsigned int len, void *iv)
{
        struct sk_buff *trailer;
        int err = skb_cow_data(skb, 0, &trailer);
        if (err < 0)
                return err;
        skb_to_sgvec(skb, sg, 0, len);
        aead_request_set_crypt(req, sg, sg, len, iv);
        return crypto_aead_decrypt(req);
}
