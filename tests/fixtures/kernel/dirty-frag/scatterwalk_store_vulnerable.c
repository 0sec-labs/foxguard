// Positive fixture: scatterwalk_map_and_copy STORE on in-place AEAD SGL.
// Models crypto/authencesn.c::crypto_authenc_esn_decrypt — the secondary
// STORE primitive abused by Copy Fail and Dirty Frag.
// MUST be flagged by the authencesn exception at crypto/authencesn.c, and by
// the broad scatterwalk rule when scanned as a non-crypto clone path.


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

int crypto_authenc_esn_decrypt(struct aead_request *req,
                               struct scatterlist *sg,
                               unsigned int assoclen,
                               unsigned int cryptlen,
                               void *iv, void *tmp)
{
        /* in-place AEAD setup: src == dst == sg */
        aead_request_set_crypt(req, sg, sg, cryptlen, iv);
        /* The STORE: writes 4 bytes into the shared SGL at attacker-chosen
         * offset (assoclen+cryptlen) before AEAD auth has rejected the msg. */
        scatterwalk_map_and_copy(tmp, sg, assoclen + cryptlen, 4, 1);
        return 0;
}
