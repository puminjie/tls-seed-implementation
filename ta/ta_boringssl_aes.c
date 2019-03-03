/**
 * @file ta_key_manager.h
 * @author Hyunwoo Lee
 * @date 1 Nov 2018
 * @brief This file is to implement functions for the key manager
 */

#include "ta_key_manager.h"
#include "ta_boringssl_aes.h"

/**
 * @brief Encrypt the plaintext into the ciphertext
 * @param kst the key manager which has the symmetric key
 * @param iv the initialization vector
 * @param ivlen the length of the intitialization vector
 * @param msg the plaintext to be encrypted
 * @param mlen the length of the plaintext
 * @param ciph the resulting ciphertext
 * @param clen the length of the ciphertext
 * @return error code
 */
TEE_Result boringssl_encrypt(struct key_manager_st *kst, const uint8_t *iv, uint32_t ivlen, 
    const uint8_t *msg, uint32_t mlen, uint8_t *ciph, uint32_t *clen)
{
  TEE_Result res;
  res = boringssl_operation(kst, iv, ivlen, msg, mlen, ciph, clen, TA_OP_ENCRYPT);
  return res;
}

/**
 * @brief Decrypt the ciphertext into the plaintext
 * @param kst the key manager which has the symmetric key
 * @param iv the initialization vector
 * @param ivlen the length of the initialization vector
 * @param ciph the ciphertext to be decrypted
 * @param plain the resulting plaintext
 * @param plen the length of the plaintext
 * @return error code
 */
TEE_Result boringssl_decrypt(struct key_manager_st *kst, const uint8_t *iv, uint32_t ivlen, 
    const uint8_t *ciph, uint32_t clen, uint8_t *plain, uint32_t *plen)
{
  TEE_Result res;
  res = boringssl_operation(kst, iv, ivlen, ciph, clen, plain, plen, TA_OP_DECRYPT);
  return res;
}

/**
 * @brief encrypt/decrypt the message by using the boringssl functions
 * @param kst the key manager which has the encryption/decryption key
 * @param iv the initialization vector
 * @param ivlen the length of the IV
 * @param msg1 the first message (plaintext for encryption, ciphertext for
 * decryption)
 * @param mlen1 the length of the first message
 * @param msg2 the second message (ciphertext for encryption, plaintext for
 * decryption)
 * @param mlen2 the length of the second message
 * @param op the operation code (TA_OP_ENCRYPT/TA_OP_DECRYPT)
 * @return error code
 */
TEE_Result boringssl_operation(struct key_manager_st *kst, const uint8_t *iv, uint32_t ivlen,
    const uint8_t *msg1, uint32_t mlen1, uint8_t *msg2, uint32_t *mlen2, uint32_t op)
{
  EDGE_LOG("boringssl_operation: kst: %p, iv: %p, ivlen: %d, msg1: %p, mlen1: %d, msg2: %p, mlen2: %d, op: %d", kst, iv, ivlen, msg1, mlen1, msg2, mlen2, op);

  TEE_Result res;
  EVP_CIPHER_CTX *ctx;
  uint32_t ret;
  uint32_t len;

  ret = 0;
  res = TEE_SUCCESS;
  ctx = EVP_CIPHER_CTX_new();

  EDGE_PRINT("Key Used in function", kst->key, 0, kst->klen, 10);
  EDGE_PRINT("IV Used in function", iv, 0, ivlen, 10);
  EDGE_PRINT("Message in function", msg1, 0, mlen1, 10);
  if (op == TA_OP_ENCRYPT)
  {
    ret = EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, kst->key, iv);
    EDGE_LOG("EVP_EncryptInit_ex(): %d", ret);
    ret = EVP_EncryptUpdate(ctx, msg2, &len, msg1, mlen1);
    EDGE_LOG("EVP_EncryptUpdate(): %d", ret);
  }
  else if (op == TA_OP_DECRYPT)
  {
    ret = EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, kst->key, iv);
    EDGE_LOG("EVP_DecryptInit_ex(): %d", ret);
    ret = EVP_DecryptUpdate(ctx, msg2, &len, msg1, mlen1);
    EDGE_LOG("EVP_DecryptUpdate(): %d", ret);
  }
  else
    res = TEE_ERROR_BAD_PARAMETERS;

  *mlen2 = len;

  if (op == TA_OP_ENCRYPT)
  {
    ret = EVP_EncryptFinal_ex(ctx, msg2 + len, &len);
    EDGE_LOG("EVP_EncryptFinal_ex(): %d", ret);
  }
  else if (op == TA_OP_DECRYPT)
  {
    ret = EVP_DecryptFinal_ex(ctx, msg2 + len, &len);
    EDGE_LOG("EVP_DecryptFinal_ex(): %d", ret);
  }
  else
    res = TEE_ERROR_BAD_PARAMETERS;

  *mlen2 += len;

  if (ret != 1)
    res = TEE_ERROR_SECURITY;

  EVP_CIPHER_CTX_free(ctx);

  return res;
}
