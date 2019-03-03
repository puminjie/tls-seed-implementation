#include "ta_file_manager.h"
#include <openssl/x509.h>
#include <openssl/pool.h>
#include <string.h>

TEE_Result set_certificate(struct domain_table_st *tbl, uint8_t *cert, uint32_t clen);
struct buf_st *get_certificate(struct domain_table_st *tbl);

TEE_Result set_cross_credential(struct domain_table_st *tbl, uint8_t *cc, uint32_t cclen);
struct buf_st *get_cross_credential(struct domain_table_st *tbl);

IMPLEMENT_DEFAULT_PARENT_FUNC(domain_table, content);

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
TEE_Result init_domain_table(struct domain_table_st *dom, void *data)
{
  (void) data;
  EDGE_MSG("[TA] initialize the value");
  DEFAULT_PARENT_INIT_FUNC(domain_table, dom);
  dom->vops = &vops;
  EDGE_MSG("[TA] after add table to file manager");

  return TEE_SUCCESS;
}

/**
 * @brief Free the memory space allocated for the particular domain
 * @param mngr File manager
 * @param name Domain name
 * @param nlen Length of the domain name
 */
TEE_Result free_domain_table(struct domain_table_st *dom)
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
  dom = NULL;

  return TEE_SUCCESS;
}

/**
 * @brief Set the certificate of the domain
 * @param Pointer to the domain table
 * @param Pointer to the certificate buffer
 * @param Length of the certificate to be assigned
 * @return Error code
 */
TEE_Result set_certificate(struct domain_table_st *tbl, uint8_t *cert, uint32_t clen)
{
  EDGE_LOG("Set Certificate tbl: %p, cert: %p, clen: %d", tbl, cert, clen);
  tbl->cert = init_memcpy_buf_mem(&(tbl->cert), cert, clen);

  return TEE_SUCCESS;
}
/**
 * @brief Get the name of the certificate of the domain
 * @param Pointer to the certificate of the domain
 * @param Pointer to the domain name to be assigned
 * @param Length of the certificate to be assigned
 * @return Error code
 */
struct buf_st *get_certificate(struct domain_table_st *tbl)
{
  return tbl->cert;
}

/**
 * @brief Set the certificate of the domain
 * @param Pointer to the domain table
 * @param Pointer to the certificate buffer
 * @param Length of the certificate to be assigned
 * @return Error code
 */
TEE_Result set_cross_credential(struct domain_table_st *tbl, uint8_t *cc, uint32_t cclen)
{
  tbl->cc = init_memcpy_buf_mem(&(tbl->cc), cc, cclen);

  return TEE_SUCCESS;
}
/**
 * @brief Get the name of the certificate of the domain
 * @param Pointer to the certificate of the domain
 * @param Pointer to the domain name to be assigned
 * @param Length of the certificate to be assigned
 * @return Error code
 */
struct buf_st *get_cross_credential(struct domain_table_st *tbl)
{
  return tbl->cc;
}
