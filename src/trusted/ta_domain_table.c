#include "ta_file_manager.h"
#include <openssl/x509.h>
#include <string.h>

SEED_Result set_certificate(domain_table_t *tbl, uint8_t *cert, uint32_t clen);
buf_t *get_certificate(domain_table_t *tbl);

SEED_Result set_cross_credential(domain_table_t *tbl, uint8_t *cc, uint32_t cclen);
buf_t *get_cross_credential(domain_table_t *tbl);

IMPLEMENT_GENERIC_GET_NAME(domain_table);

/**
 * @brief default setting of the file table operation
 */
static struct domain_table_vops vops = 
{
  .set_certificate = set_certificate,
  .get_certificate = get_certificate,

  .set_cross_credential = set_cross_credential,
  .get_cross_credential = get_cross_credential,
};

/**
 * @brief Initialize the domain table
 * @param node The newly generated node
 * @return Error code
 */
SEED_Result init_domain_table(domain_table_t *dom, void *data)
{
  efstart("dom: %p, data: %p", dom, data);
  assert(dom != NULL);
  (void) data;
  DEFAULT_CHILD_INIT_FUNC(domain_table, dom);
  dom->vops = &vops;

  effinish();
  return SEED_SUCCESS;
}

/**
 * @brief Free the memory space allocated for the particular domain
 * @param mngr File manager
 * @param name Domain name
 * @param nlen Length of the domain name
 */
SEED_Result free_domain_table(domain_table_t *dom)
{
  efstart("dom: %p", dom);

  if (dom)
  {
    // Free the domain name
    DEFAULT_FREE(dom);

    // Free the origin's cert
    if (dom->cert)
      free_buf(dom->cert);

    // Free the cross credential
    if (dom->cc)
      free_buf(dom->cc);

    free(dom);
  }
  dom = NULL;

  effinish();
  return SEED_SUCCESS;
}

/**
 * @brief Set the certificate of the domain
 * @param Pointer to the domain table
 * @param Pointer to the certificate buffer
 * @param Length of the certificate to be assigned
 * @return Error code
 */
SEED_Result set_certificate(domain_table_t *tbl, uint8_t *cert, uint32_t clen)
{
  efstart("tbl: %p, cert: %p, clen: %d", tbl, cert, clen);
  tbl->cert = init_memcpy_buf_mem(tbl->cert, cert, clen);

  effinish();
  return SEED_SUCCESS;
}
/**
 * @brief Get the certificate of the domain
 * @param Pointer to the domain table
 * @return Error code
 */
buf_t *get_certificate(domain_table_t *tbl)
{
  efstart("tbl: %p", tbl);
  effinish();
  return tbl->cert;
}

/**
 * @brief Set the certificate of the domain
 * @param Pointer to the domain table
 * @param Pointer to the CC buffer
 * @param Length of the CC to be assigned
 * @return Error code
 */
SEED_Result set_cross_credential(domain_table_t *tbl, uint8_t *cc, uint32_t cclen)
{
  efstart("tbl: %p, cc: %p, cclen: %d", tbl, cc, cclen);
  tbl->cc = init_memcpy_buf_mem(tbl->cc, cc, cclen);

  effinish();
  return SEED_SUCCESS;
}
/**
 * @brief Get the CC of the domain
 * @param Pointer to the domain table
 * @return Error code
 */
buf_t *get_cross_credential(domain_table_t *tbl)
{
  efstart("tbl: %p", tbl);
  effinish();
  return tbl->cc;
}
