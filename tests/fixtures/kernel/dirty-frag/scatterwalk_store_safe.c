// Negative fixture: scatterwalk_map_and_copy READ (out=0) on in-place AEAD SGL.
// Reading the shared SGL is not a STORE primitive and must not be flagged.
// Also exercises the case where dst is a separate (not-aliased) scatterlist.

#include <crypto/aead.h>
#include <crypto/scatterwalk.h>

struct aead_request;
struct scatterlist;

extern void aead_request_set_crypt(struct aead_request *req,
                                   struct scatterlist *src,
                                   struct scatterlist *dst,
                                   unsigned int cryptlen, void *iv);
extern void scatterwalk_map_and_copy(void *buf, struct scatterlist *sg,
                                     unsigned int start, unsigned int nbytes,
                                     int out);

int authenc_safe_read(struct aead_request *req,
                      struct scatterlist *src,
                      struct scatterlist *dst,
                      unsigned int assoclen,
                      unsigned int cryptlen,
                      void *iv, void *tmp)
{
        /* Not in-place: src != dst. */
        aead_request_set_crypt(req, src, dst, cryptlen, iv);
        /* READ (out=0): pulls bytes out of the SGL into tmp. No STORE. */
        scatterwalk_map_and_copy(tmp, src, assoclen, 4, 0);
        return 0;
}
