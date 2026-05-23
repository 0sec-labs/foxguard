// Positive fixture (Tier 1 sibling): memcpy_to_sglist STORE on shared in-place
// AEAD SGL — the modern Linux helper that replaced the historical
// scatterwalk_map_and_copy(..., /*out=*/1) idiom in crypto/authenc paths.
//
// The Dirty Frag class STORE primitive is identical in semantics whether it's
// expressed as scatterwalk_map_and_copy(..., 1) or memcpy_to_sglist(...) — both
// write into the destination scatterlist that aliases the attacker-controllable
// AEAD source SGL before AEAD auth has rejected the message.
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
extern void memcpy_to_sglist(struct scatterlist *sg, unsigned int start,
                             const void *buf, unsigned int nbytes);

int authenc_memcpy_to_sglist_inplace(struct aead_request *req,
                                     struct scatterlist *sg,
                                     unsigned int assoclen,
                                     unsigned int cryptlen,
                                     void *iv, void *tag)
{
        /* in-place AEAD: src == dst == sg, attacker-controllable. */
        aead_request_set_crypt(req, sg, sg, cryptlen, iv);
        /* The STORE: writes the computed tag into the shared SGL via the
         * modern memcpy_to_sglist helper, before the AEAD verify decision
         * lands. Same Dirty Frag class write primitive, different spelling. */
        memcpy_to_sglist(sg, assoclen + cryptlen, tag, 16);
        return 0;
}
