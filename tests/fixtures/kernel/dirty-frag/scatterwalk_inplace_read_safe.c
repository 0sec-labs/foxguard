// Negative fixture (Tier 2 known-FP): in-place AEAD setup followed by a
// scatterwalk_map_and_copy READ (out=0). This tests that the rule's tight
// `out=1` literal does not over-fire on read-back paths in
// crypto_authenc_*_decrypt that pull bytes out of the SGL into a temporary
// buffer for tag comparison.
//
// MUST NOT be flagged by kernel/dirty-frag/scatterwalk-store-on-shared-sgl.


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

int authenc_inplace_read_safe(struct aead_request *req,
                              struct scatterlist *sg,
                              unsigned int assoclen,
                              unsigned int cryptlen,
                              void *iv, void *tmp)
{
        /* in-place AEAD: src == dst == sg. */
        aead_request_set_crypt(req, sg, sg, cryptlen, iv);
        /* READ-back (out=0): pulls tag bytes from the SGL into tmp.
         * Not a STORE primitive, so the rule must not fire. */
        scatterwalk_map_and_copy(tmp, sg, assoclen + cryptlen, 16, 0);
        return 0;
}
