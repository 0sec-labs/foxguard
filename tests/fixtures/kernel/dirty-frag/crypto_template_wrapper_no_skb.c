// Negative fixture: crypto template-wrapper shape with no skb-frag semantics.
// Models crypto/*.c false positives such as gcm/ccm/cts template wrappers.
// MUST NOT be flagged when scanned at a crypto/** path.

struct aead_request;
struct skcipher_request;
struct scatterlist;

extern void aead_request_set_crypt(struct aead_request *req,
                                   struct scatterlist *src,
                                   struct scatterlist *dst,
                                   unsigned int cryptlen, void *iv);
extern int crypto_aead_decrypt(struct aead_request *req);
extern void skcipher_request_set_crypt(struct skcipher_request *req,
                                       struct scatterlist *src,
                                       struct scatterlist *dst,
                                       unsigned int cryptlen, void *iv);
extern int crypto_skcipher_decrypt(struct skcipher_request *req);
extern void scatterwalk_map_and_copy(void *buf, struct scatterlist *sg,
                                     unsigned int start, unsigned int nbytes,
                                     int out);

int crypto_template_wrapper(struct aead_request *aead_req,
                            struct skcipher_request *sk_req,
                            struct scatterlist *sg,
                            unsigned int cryptlen,
                            void *iv, void *tag)
{
        aead_request_set_crypt(aead_req, sg, sg, cryptlen, iv);
        crypto_aead_decrypt(aead_req);

        skcipher_request_set_crypt(sk_req, sg, sg, cryptlen, iv);
        crypto_skcipher_decrypt(sk_req);

        scatterwalk_map_and_copy(tag, sg, cryptlen, 16, 1);
        return 0;
}
