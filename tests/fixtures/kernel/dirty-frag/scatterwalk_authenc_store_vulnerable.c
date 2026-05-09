// Positive fixture (Tier 1 sibling): scatterwalk_map_and_copy STORE on
// shared in-place AEAD SGL, sibling of crypto_authenc_esn_decrypt — covers
// the structural shape in crypto/authenc.c::crypto_authenc_decrypt and
// any downstream module that mirrors the authencesn STORE primitive.
//
// Synthetic minimal reproducer — NOT copied from kernel source.
// MUST be flagged by kernel/dirty-frag/scatterwalk-store-on-shared-sgl.


/* Tree-sitter fixture — scanned as text by foxguard, never compiled.
 * Kernel headers replaced with the inline forward decls below to keep clangd quiet. */
struct aead_request;
struct scatterlist;

extern void aead_request_set_crypt(struct aead_request *req,
                                   struct scatterlist *src,
                                   struct scatterlist *dst,
                                   unsigned int cryptlen, void *iv);
extern void scatterwalk_map_and_copy(void *buf, struct scatterlist *sg,
                                     unsigned int start, unsigned int nbytes,
                                     int out);

int authenc_store_inplace(struct aead_request *req,
                          struct scatterlist *sg,
                          unsigned int assoclen,
                          unsigned int cryptlen,
                          void *iv, void *tag)
{
        /* in-place AEAD: src == dst == sg, attacker-controllable. */
        aead_request_set_crypt(req, sg, sg, cryptlen, iv);
        /* The STORE: writes the computed tag into the shared SGL before
         * the AEAD verify decision lands. */
        scatterwalk_map_and_copy(tag, sg, assoclen + cryptlen, 16, 1);
        return 0;
}
