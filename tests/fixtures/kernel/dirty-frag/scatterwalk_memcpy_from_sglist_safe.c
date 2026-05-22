// Negative fixture (Tier 2 known-FP): in-place AEAD setup followed by a
// memcpy_from_sglist READ-back. The modern Linux helper memcpy_from_sglist()
// is the dual of memcpy_to_sglist() — it pulls bytes OUT of the SGL into a
// local buffer for tag comparison and is not a STORE primitive.
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
extern void memcpy_from_sglist(void *buf, struct scatterlist *sg,
                               unsigned int start, unsigned int nbytes);

int authenc_memcpy_from_sglist_read_safe(struct aead_request *req,
                                         struct scatterlist *sg,
                                         unsigned int assoclen,
                                         unsigned int cryptlen,
                                         void *iv, void *tmp)
{
        /* in-place AEAD: src == dst == sg. */
        aead_request_set_crypt(req, sg, sg, cryptlen, iv);
        /* READ-back via the modern memcpy_from_sglist helper: pulls tag
         * bytes from the SGL into tmp. Not a STORE primitive, so the rule
         * must not fire on memcpy_from_sglist. */
        memcpy_from_sglist(tmp, sg, assoclen + cryptlen, 16);
        return 0;
}
