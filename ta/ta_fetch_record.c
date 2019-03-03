#include <openssl/ssl.h>
#include "ta_fetch_record.h"

IMPLEMENT_DEFAULT_PARENT_FUNC(fetch_record, requester);
IMPLEMENT_DEFAULT_CHILD_FUNC(requester);

TEE_Result init_requester(struct requester_st *req, void *data)
{
  DEFAULT_CHILD_INIT_FUNC(requester, req);
  req->sctx = (struct tls_context_record_st *)data;
  return TEE_SUCCESS;
}

TEE_Result free_requester(struct requester_st *req)
{
  DEFAULT_FREE(req);
  free(req);
  req = NULL;
  return TEE_SUCCESS;
}
