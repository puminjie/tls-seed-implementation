#include "ta_cc.h"

/**
 * @brief Generate Software Assertion
 * @param ssl TLS session context
 * @param ec_digest EC software's digest
 * @param ec_digest_len Length of EC digest
 * @param edge_priv EC's private key
 * @param sa software assertion
 * @param sa_len Length of software assertion
 * @return Success: 1, Failure: 0
 */
int make_software_assertion(SSL *ssl, uint8_t *ec_digest, uint32_t ec_digest_len,
    EVP_PKEY *edge_priv, uint8_t **sa, uint32_t *sa_len)
{
  dmsg("Start: make_software_assertion:");
  int rc;
  EVP_MD_CTX *ctx;
  uint16_t ht, st;
  uint8_t *sig, *p;
  uint32_t sig_len;
  uint8_t random[SSL3_RANDOM_SIZE];
  
  assert(ssl != NULL);
  assert(ec_digest != NULL);
  assert(ec_digest_len > 0);
  assert(edge_priv != NULL);
  assert(sa != NULL);
  assert(sa_len != NULL);
 
  ht = st = NID_sha256;

  ctx = EVP_MD_CTX_create();
  if (!ctx)
    return 0;

  switch(st)
  {
    case NID_sha1:
      rc = EVP_DigestSignInit(ctx, NULL, EVP_sha1(), NULL, edge_priv);
      break;
    case NID_sha224:
      rc = EVP_DigestSignInit(ctx, NULL, EVP_sha224(), NULL, edge_priv);
      break;
    case NID_sha256:
      rc = EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, edge_priv);
      break;
    case NID_sha384:
      rc = EVP_DigestSignInit(ctx, NULL, EVP_sha384(), NULL, edge_priv);
      break;
    case NID_sha512:
      rc = EVP_DigestSignInit(ctx, NULL, EVP_sha512(), NULL, edge_priv);
      break;
    default:
      goto err;
  }

  if (rc != 1) goto err;

  memset(random, 0x0, SSL3_RANDOM_SIZE);
  SSL_get_client_random(ssl, random, SSL3_RANDOM_SIZE);
  rc = EVP_DigestSignUpdate(ctx, random, SSL3_RANDOM_SIZE);
  if (rc != 1) goto err;

  memset(random, 0x0, SSL3_RANDOM_SIZE);
  SSL_get_server_random(ssl, random, SSL3_RANDOM_SIZE);
  rc = EVP_DigestSignUpdate(ctx, random, SSL3_RANDOM_SIZE);
  if (rc != 1) goto err;

  rc = EVP_DigestSignUpdate(ctx, ec_digest, ec_digest_len);
  if (rc != 1) goto err;

  rc = EVP_DigestSignFinal(ctx, NULL, &sig_len);
  if (rc != 1) goto err;
  if (sig_len <= 0) goto err;

  sig = (uint8_t *)OPENSSL_malloc(sig_len);
  if (!sig) goto err;

  rc = EVP_DigestSignFinal(ctx, sig, &sig_len);
  if (rc != 1) goto err;

  *sa_len = 2 + ec_digest_len + 2 + sig_len;
  (*sa) = OPENSSL_malloc(*sa_len);
  p = (*sa);

  VAR_TO_PTR_2BYTES(ht, p);
  memcpy(p, ec_digest, ec_digest_len);
  p += ec_digest_len;
  VAR_TO_PTR_2BYTES(sig_len, p);
  memcpy(p, sig, sig_len);
  p += sig_len;

  EVP_MD_CTX_free(ctx);
  OPENSSL_free(sig);
  return 1;
err:
  if (ctx)
    EVP_MD_CTX_free(ctx);

  if (sig)
    OPENSSL_free(sig);

  dmsg("Finished: make_software_assertion");
  return 0;
}

// Make cc content body
// Input
//   out: BIO for the standard output
//   content: cc content
//   orig_pub: origin's public key
//   ec_pub: edge's public key
//   nid: signature type
//   len: length of the cc content
// Output Success: 1, Failure: 0
int make_cc_content_body(unsigned char **content, EVP_PKEY *orig_pub, EVP_PKEY *ec_pub, 
    const unsigned char *ec_digest, int ec_digest_length, int nid, int *len)
{
	// Declare the variables related to the relation
	unsigned char binding[EVP_MAX_MD_SIZE];
	int rc;
	unsigned int shalen;
	EVP_MD_CTX *ctx;
	BIO *orig, *ec;
	BUF_MEM *orig_mem, *ec_mem;
  unsigned int curr;
#ifdef PLATFORM_OPTEE
  TEE_Time tv;
#endif /* PLATFORM_OPTEE */

	ctx = EVP_MD_CTX_create();
	orig = BIO_new(BIO_s_mem());
	ec = BIO_new(BIO_s_mem());

	// Declare the variables related to the timestamp
#ifdef PLATFORM_OPTEE
  TEE_GetREETime(&tv);
  curr = tv.seconds;
#elif PLATFORM_SGX
  curr = get_current_seconds();
#endif /* PLATFORM_TIME */
  dmsg("curr: %lu", curr);

	uint32_t not_before = curr - 10000000;
	uint32_t not_after = curr + 10000000;

  dmsg("not_before:\t %u\n", not_before);
  dmsg("not_after:\t %u\n", not_after);

	dmsg("PROGRESS: Make H(orig||edge)\n");

	// Set the message digests according to the nid
	switch (nid)
	{
		case NID_sha1:
			rc = EVP_DigestInit(ctx, EVP_sha1());
			shalen = SHA_DIGEST_LENGTH;
			dmsg("PROGRESS: Hash algorithm is set to SHA1");
			break;
		case NID_sha224:
			rc = EVP_DigestInit(ctx, EVP_sha224());
			shalen = SHA224_DIGEST_LENGTH;
			dmsg("PROGRESS: Hash algorithm is set to SHA224");
			break;
		case NID_sha256:
			rc = EVP_DigestInit(ctx, EVP_sha256());
			shalen = SHA256_DIGEST_LENGTH;
			dmsg("PROGRESS: Hash algorithm is set to SHA256");
			break;
    case NID_sha384:
      rc = EVP_DigestInit(ctx, EVP_sha384());
      shalen = SHA384_DIGEST_LENGTH;
      break;
    case NID_sha512:
      rc = EVP_DigestInit(ctx, EVP_sha512());
      shalen = SHA512_DIGEST_LENGTH;
      break;
		default:
			dmsg("PROGRESS: Unknown Hash algorithm");
			return 0;
	}

	// Make the hash, H(alice||carol)
	PEM_write_bio_PUBKEY(orig, orig_pub);
	PEM_write_bio_PUBKEY(ec, ec_pub);
	BIO_get_mem_ptr(orig, &orig_mem);
	BIO_get_mem_ptr(ec, &ec_mem);
	EVP_DigestUpdate(ctx, orig_mem->data, orig_mem->length);
	EVP_DigestUpdate(ctx, ec_digest, ec_digest_length);
	EVP_DigestFinal(ctx, binding, &shalen);

	// Print the info
	dprint("PROGRESS: Print Relation", binding, 0, shalen, 16);

	dmsg("PROGRESS: sizeof(not_before):\t %lu", sizeof(not_before));
	dmsg("PROGRESS: sizeof(not_after):\t %lu", sizeof(not_after));
	dmsg("PROGRESS: not_before:\t %u", not_before);
	dmsg("PROGRESS: not_after:\t %u", not_after);
	dmsg("PROGRESS: hash algorithm type:\t %u", nid);

	// Make the final message
	uint16_t ht = (uint16_t) nid;
	*len = sizeof(not_before) + sizeof(not_after) + sizeof(ht) + shalen;
	dmsg("PROGRESS: length of cc_content_body: %d", *len);
	*content = (unsigned char *)OPENSSL_malloc(*len);
	unsigned char *p;
	p = *content;
	VAR_TO_PTR_4BYTES(not_before, p);
	VAR_TO_PTR_4BYTES(not_after, p);
	VAR_TO_PTR_2BYTES(ht, p);
	memcpy(p, binding, shalen);

	dprint("PROGRESS: print cc_content_body", (*content), 0, (*len), 16);

	return 1;
}

// Make the cc request message
// Input
//   out: BIO for the standard output
//   request: the final message
//   msg: cc content
//   msg_len: length of cc content
//   ec_priv: edge's private key
//   nid: signature algorithm
//   len: the length of the final message
// Output
//   Success: 1, Failure: 0
int make_cc_request(unsigned char **request, unsigned char *msg, int msg_len, 
    EVP_PKEY *ec_priv, int nid, int *len)
{
	unsigned char *sigblk, *p;
	size_t sigblk_len;

	if (!make_signature_block(&sigblk, msg, msg_len, ec_priv, nid, &sigblk_len))
	{
		dmsg("ERROR: make the signature block failed");
		goto err;
	}
	dmsg("PROGRESS: make the signature block for the cc content success");

	*len = sizeof(uint16_t) + msg_len + sigblk_len;

	dmsg("Length of cc request: %d", *len);

	// Make the final message - cc request
	*request = (unsigned char *)OPENSSL_malloc(*len);
	p = *request;
	VAR_TO_PTR_2BYTES(msg_len, p);
	memcpy(p, msg, msg_len);
	p += msg_len;
	memcpy(p, sigblk, sigblk_len);

	OPENSSL_free(sigblk);

	return 1;

err:
	return 0;
}

int make_cc_request_with_verify_cc(unsigned char **request, unsigned char *msg, int msg_len, 
    const unsigned char *ec_digest, int ec_digest_length,
    EVP_PKEY *ec_priv, EVP_PKEY *orig_pub, EVP_PKEY *ec_pub, int nid, int *len)
{
	if (!verify_cc_content_body(msg, orig_pub, ec_pub, ec_digest, ec_digest_length))
	{
		dmsg("ERROR: Verify cc content body failure in make_cc_request_with_verify_cc");
		return 0;
	}
	return make_cc_request(request, msg, msg_len, ec_priv, nid, len);
}

// Make the cc_response message (len || cc_request || Signature type || Signature length || Signature)
// Input
//   out: BIO for the standard output
//   response: the cc_response message
//   request: the cc_request message
//   req_len: the length of the request
//   orig_priv: the alice's private key
//   orig_pub: the alice's public key
//   ec_pub: the carol's public key
//   nid: the signature algorithm
//   len: the length of the cc_response
// Output
//   Success 1
//   Failure 0
int make_cc_response(unsigned char **response, unsigned char *request, int req_len, EVP_PKEY *orig_priv, int nid, int *len)
{
	unsigned char *sigblk, *p;
	size_t sigblk_len;

	dmsg("PROGRESS: Make the cc response");

	if (!make_signature_block(&sigblk, request, req_len, orig_priv, nid, &sigblk_len))
	{
		dmsg("ERROR: make the signature block failed");
		goto err;
	}
	dmsg("PROGRESS: make the signature block for the cc content success");

	*len = sizeof(uint16_t) + req_len + sigblk_len;

	dmsg("Length of cc response: %d", *len);

	// Make the final message - cc response
	*response = (unsigned char *)OPENSSL_malloc(*len);
	p = *response;
	VAR_TO_PTR_2BYTES(req_len, p);
	memcpy(p, request, req_len);
	p += req_len;
	memcpy(p, sigblk, sigblk_len);

	OPENSSL_free(sigblk);

	return 1;

err:
	return 0;
}

int make_cc_response_with_verify_request(unsigned char **response, unsigned char *request, 
    int req_len, EVP_PKEY *orig_priv, EVP_PKEY *orig_pub, EVP_PKEY *ec_pub, 
    const unsigned char *ec_digest, int ec_digest_length, int nid, int *len)
{
	if (!verify_cc_request(request, orig_pub, ec_pub, ec_digest, ec_digest_length))
	{
		dmsg("ERROR: Verify the cc request failed in make_cc_response_with_verify_request");
		return 0;
	}
	dmsg("PROGRESS: Verify the cc request success in make_cc_response_with_verify_request");

	return make_cc_response(response, request, req_len, orig_priv, nid, len);
}

// Make the signature block composed of (Signature Type || Signature Length || Signature)

int make_signature_block(unsigned char **sigblk, unsigned char *msg, int msg_len, 
    EVP_PKEY *priv, int nid, size_t *sigblk_len)
{
	int rc;
	EVP_MD_CTX *ctx;
	unsigned char *sig, *p;
	size_t sig_len;
	uint16_t sig_type;

	ctx = EVP_MD_CTX_create();
	if (ctx == NULL)
	{
		dmsg("EVP_MD_CTX_create failed");
		goto err;
	}

	// Initialize the md according to nid
	switch (nid)
	{
		case NID_sha1:
			rc = EVP_DigestSignInit(ctx, NULL, EVP_sha1(), NULL, priv);
			sig_type = NID_sha1;
			break;
		case NID_sha224:
			rc = EVP_DigestSignInit(ctx, NULL, EVP_sha224(), NULL, priv);
			sig_type = NID_sha224;
			break;
		case NID_sha256:
			rc = EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, priv);
			sig_type = NID_sha256;
			break;
		case NID_sha384:
			rc = EVP_DigestSignInit(ctx, NULL, EVP_sha384(), NULL, priv);
			sig_type = NID_sha256;
			break;
		case NID_sha512:
			rc = EVP_DigestSignInit(ctx, NULL, EVP_sha512(), NULL, priv);
			sig_type = NID_sha256;
			break;

		default:
			dmsg("Unknown Hash algorithm");
			goto err;
	}

	// Make the signature
	if (rc != 1)
	{
		dmsg("PROGRESS: DigestSign Init Failed");
		goto err;
	}

	rc = EVP_DigestSignUpdate(ctx, msg, msg_len);
	if (rc != 1)
	{
		dmsg("PROGRESS: DigestSign Update Failed");
		goto err;
	}

	rc = EVP_DigestSignFinal(ctx, NULL, &sig_len);
	if (rc != 1)
	{
		dmsg("PROGRESS: DigestSign Final Failed");
		goto err;
	}

	if (sig_len <= 0)
	{
		dmsg("PROGRESS: DigestSign Final Failed");
		goto err;
	}

	dmsg("PROGRESS: Signature length: %d\n", (int)sig_len);
	sig = OPENSSL_malloc(sig_len);

	if (sig == NULL)
	{
		dmsg("PROGRESS: OPENSSL_malloc error");
		goto err;
	}

	rc = EVP_DigestSignFinal(ctx, sig, &sig_len);
	if (rc != 1)
	{
		dmsg("PROGRESS: DigestSign Final Failed");
		goto err;
	}

	*sigblk_len = 2 * sizeof(uint16_t) + sig_len;
	*sigblk = (unsigned char *)OPENSSL_malloc(*sigblk_len);
	p = *sigblk;
	VAR_TO_PTR_2BYTES(sig_type, p);
	VAR_TO_PTR_2BYTES(sig_len, p);
	memcpy(p, sig, sig_len);

	dprint("PROGRESS: Sig in make cc >>>", sig, 0, sig_len, 16);
	dmsg("PROGRESS: Length of message: %d", msg_len);
	dmsg("PROGRESS: Signature type: %d", (int)sig_type);
	dmsg("PROGRESS: Length of signature: %d", (int)sig_len);

	OPENSSL_free(sig);
	EVP_MD_CTX_free(ctx);

	return 1;

err:
	EVP_MD_CTX_free(ctx);

	return 0;
}

// Verify the cc content 
// Input
//   out: BIO for the standard output
//   content: cc content
//   orig_pub: origin's public key
//   ec_pub: edge's public key
// Output
//   Success: 1, Failure: 0
int verify_cc_content_body(unsigned char *content, EVP_PKEY *orig_pub, EVP_PKEY *ec_pub,
    const unsigned char *ec_digest, int ec_digest_length)
{
	unsigned char *p = content;
	unsigned char *hash;
	unsigned char binding[EVP_MAX_MD_SIZE];
	uint32_t not_before, not_after;
	uint16_t ht;
	unsigned int len;
	int cmp, rc;
	unsigned int curr;
	EVP_MD_CTX *ctx;
	BIO *orig = NULL, *ec = NULL;
	BUF_MEM *orig_mem, *ec_mem;
#ifdef PLATFORM_OPTEE
  TEE_Time tv;
#endif /* PLATFORM_OPTEE */

	ctx = EVP_MD_CTX_create();
	if (ctx == NULL)
	{
		dmsg("EVP_MD_CTX_create failed");
		goto err;
	}

	orig = BIO_new(BIO_s_mem());
	ec = BIO_new(BIO_s_mem());

	PTR_TO_VAR_4BYTES(p, not_before);
	PTR_TO_VAR_4BYTES(p, not_after);

	dmsg("PROGRESS: verify not_before: %u", not_before);
	dmsg("PROGRESS: verify not_after: %u", not_after);

	// Get the current time
#ifdef PLATFORM_OPTEE
	TEE_GetREETime(&tv);
	curr = tv.seconds;
#elif PLATFORM_SGX
  curr = get_current_seconds();
#endif /* PLATFORM_TIME */
  dmsg("curr: %lu", curr);

	// Verify whether in the valid time
	if ((curr >= not_before) && (curr < not_after))
	{
		dmsg("PROGRESS: current time is in the valid duration: %lu", curr);
	}
	else
	{
		dmsg("PROGRESS: verify error. current time is not in the valid duration: %lu", curr);
		goto err;
	}

	PTR_TO_VAR_2BYTES(p, ht);

	// Set the hash algorithm according to nid
	switch (ht)
	{
		case NID_sha1:
			rc = EVP_DigestInit(ctx, EVP_sha1());
			len = SHA_DIGEST_LENGTH;
			break;
		case NID_sha224:
			rc = EVP_DigestInit(ctx, EVP_sha224());
			len = SHA224_DIGEST_LENGTH;
			break;
		case NID_sha256:
			rc = EVP_DigestInit(ctx, EVP_sha256());
			len = SHA256_DIGEST_LENGTH;
			break;
		case NID_sha384:
			rc = EVP_DigestInit(ctx, EVP_sha384());
			len = SHA384_DIGEST_LENGTH;
			break;
		case NID_sha512:
			rc = EVP_DigestInit(ctx, EVP_sha512());
			len = SHA512_DIGEST_LENGTH;
			break;
		default:
			dmsg("Unknown Hash Algorithm Type");
			goto err;
	}

	// Make the hash H(alice||carol)
	hash = (unsigned char *)OPENSSL_malloc(len);
	memcpy(hash, p, len);

	PEM_write_bio_PUBKEY(orig, orig_pub);
	PEM_write_bio_PUBKEY(ec, ec_pub);
	BIO_get_mem_ptr(orig, &orig_mem);
	BIO_get_mem_ptr(ec, &ec_mem);
	EVP_DigestUpdate(ctx, orig_mem->data, orig_mem->length);
	EVP_DigestUpdate(ctx, ec_digest, ec_digest_length);
	EVP_DigestFinal(ctx, binding, &len);

  dprint("binding", binding, 0, len, 16);

	// Compare whether they are same
	cmp = CRYPTO_memcmp(binding, hash, len);

	dmsg("PROGRESS: CMP Result: %d", cmp);

	if (cmp != 0)
	{
		dmsg("PROGRESS: Verify Error. Hash is not matched");
		goto verify_err;
	}
	else
	{
		dmsg("PROGRESS: Verify Success");
	}

	BUF_MEM_free(orig_mem);
	BUF_MEM_free(ec_mem);
	OPENSSL_free(hash);

	return 1;

verify_err:
	BUF_MEM_free(orig_mem);
	BUF_MEM_free(ec_mem);
	OPENSSL_free(hash);
err:
	return 0;
}

// Verify the cc request
// Input
//   out: BIO for the standard output
//   request: cc request
//   orig_pub: origin's public key
//   ec_pub: edge's public keky
// Output
//   Success 1, Failure 0
int verify_cc_request(unsigned char *request, EVP_PKEY *orig_pub, EVP_PKEY *ec_pub,
    const unsigned char *ec_digest, int ec_digest_length)
{
	size_t len = 0;
	uint16_t sig_type, sig_len;
	unsigned char *p, *cc, *sig;

	dmsg("PROGRESS: Invoke verify_cc_request()");

	p = request;
	PTR_TO_VAR_2BYTES(p, len);
	dmsg("PROGRESS: Length of message: %d", (int)len);

	cc = (unsigned char *)OPENSSL_malloc(len);
	memcpy(cc, p, len);
	p += len;
	PTR_TO_VAR_2BYTES(p, sig_type);
	dmsg("PROGRESS: Type of signature: %d", sig_type);

	PTR_TO_VAR_2BYTES(p, sig_len);
	dmsg("PROGRESS: Length of signature: %d", sig_len);

	sig = (unsigned char *)OPENSSL_malloc(sig_len);
	memcpy(sig, p, sig_len);

	dprint("PROGRESS: Signature in verify >>>", sig, 0, sig_len, 16);

	if (!verify_signature(cc, len, sig_type, sig_len, sig, ec_pub))
	{
		dmsg("ERROR: Verify the signature error");
		return 0;
	}
	dmsg("PROGRESS: Verify the signature success");

	// Verify the cc content body
	if (!verify_cc_content_body(cc, orig_pub, ec_pub, ec_digest, ec_digest_length))
	{
		dmsg("ERROR: Verify cc content body error");
		goto err;
	}

	dmsg("PROGRESS: Verify cc content body success");

	OPENSSL_free(cc);
	OPENSSL_free(sig);

	return 1;

err:
	OPENSSL_free(cc);
	OPENSSL_free(sig);
	return 0;
}

// Verify the cc response
int verify_cc_response(unsigned char *response, EVP_PKEY *orig_pub, EVP_PKEY *ec_pub,
    const unsigned char *ec_digest, int ec_digest_length)
{
	size_t len = 0;
	uint16_t sig_type, sig_len;
	unsigned char *p, *request, *sig;

	dmsg("PROGRESS: Invoke verify_cc_response()");

	p = response;
	PTR_TO_VAR_2BYTES(p, len);
	dmsg("PROGRESS: Length of cc_response: %d", (int)len);

	request = (unsigned char *)OPENSSL_malloc(len);
	memcpy(request, p, len);
	p += len;
	PTR_TO_VAR_2BYTES(p, sig_type);
	dmsg("PROGRESS: Type of signature: %d", sig_type);

	PTR_TO_VAR_2BYTES(p, sig_len);
	dmsg("PROGRESS: Length of signature: %d", sig_len);

	sig = (unsigned char *)OPENSSL_malloc(sig_len);
	memcpy(sig, p, sig_len);

	dprint("PROGRESS: Signature in verify >>>", sig, 0, sig_len, 16);

	if (!verify_signature(request, len, sig_type, sig_len, sig, orig_pub))
	{
		dmsg("ERROR: Verify the cc request signature error");
		return 0;
	}
	dmsg("PROGRESS: Verify the cc request signature success");

	// Verify the cc content body
	if (!verify_cc_request(request, orig_pub, ec_pub, ec_digest, ec_digest_length))
	{
		dmsg("ERROR: Verify cc content body error");
		goto err;
	}

	dmsg("PROGRESS: Verify cc content body success");

	OPENSSL_free(request);
	OPENSSL_free(sig);

	return 1;

err:
	OPENSSL_free(request);
	OPENSSL_free(sig);
	return 0;
}

// Verify the signature
// Input
//    out: BIO related to the standard output
//    sig_type: signature algorithm
//    sig_len: the length of the signature
//    sig: signature to be verified
//    pub: public key to be used for the verification
// Output
//    Success 1, Failure 0
int verify_signature(unsigned char *msg, int msg_len, uint16_t sig_type, uint16_t sig_len, unsigned char *sig, EVP_PKEY *pub)
{
	int rc;
	EVP_MD_CTX *ctx;

	ctx = EVP_MD_CTX_create();
	if (ctx == NULL)
	{
		dmsg("ERROR: EVP_MD_CTX_create error");
		return 0;
	}

	// Verify the signature
	switch (sig_type)
	{
		case NID_sha1:
			rc = EVP_DigestVerifyInit(ctx, NULL, EVP_sha1(), NULL, pub);
			break;
		case NID_sha224:
			rc = EVP_DigestVerifyInit(ctx, NULL, EVP_sha224(), NULL, pub);
			break;
		case NID_sha256:
			rc = EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pub);
			break;
		case NID_sha384:
			rc = EVP_DigestVerifyInit(ctx, NULL, EVP_sha384(), NULL, pub);
			break;
		case NID_sha512:
			rc = EVP_DigestVerifyInit(ctx, NULL, EVP_sha512(), NULL, pub);
			break;
		default:
			dmsg("ERROR: Unknown Signature Type");
	}
	if (rc != 1)
	{
		dmsg("ERROR: EVP_DigestVerifyInit error");
		goto err;
	}

	rc = EVP_DigestVerifyUpdate(ctx, msg, msg_len);
	if (rc != 1)
	{
		dmsg("ERROR: EVP_DigestVerifyUpdate failed");
		goto err;
	}

	rc = EVP_DigestVerifyFinal(ctx, sig, sig_len);
	if (rc != 1)
	{
		dmsg("ERROR: EVP_DigestVerifyFinal failed");
		goto err;
	}
	else
	{
		dmsg("PROGRESS: Verify Success!");
	}

	EVP_MD_CTX_free(ctx);
	return 1;
err:
	EVP_MD_CTX_free(ctx);
	return 0;
}
