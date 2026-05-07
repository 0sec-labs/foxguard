// Negative fixture: in-place skcipher decrypt on skb WITH proper cow gate.
// Models the post-patch RxRPC verify path with skb_cow_data dominating
// the in-place decrypt. MUST NOT be flagged.

#include <linux/skbuff.h>
#include <crypto/skcipher.h>

struct sk_buff;
struct skcipher_request;
struct scatterlist;

extern int skb_cow_data(struct sk_buff *skb, int tailbits, struct sk_buff **trailer);
extern int skb_to_sgvec(struct sk_buff *skb, struct scatterlist *sg, int off, int len);
extern void skcipher_request_set_crypt(struct skcipher_request *req,
                                       struct scatterlist *src,
                                       struct scatterlist *dst,
                                       unsigned int cryptlen, void *iv);
extern int crypto_skcipher_decrypt(struct skcipher_request *req);

int rxkad_verify_packet_1_safe(struct sk_buff *skb,
                               struct skcipher_request *req,
                               struct scatterlist *sg,
                               unsigned int len, void *iv)
{
        struct sk_buff *trailer;
        int err = skb_cow_data(skb, 0, &trailer);
        if (err < 0)
                return err;
        skb_to_sgvec(skb, sg, 0, len);
        skcipher_request_set_crypt(req, sg, sg, len, iv);
        return crypto_skcipher_decrypt(req);
}
