/*
 * Delegated Credentials for TLS
 * Generating DC from a server certificate
 *
 * SNU MMLAB
 * Joonhee Lee
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>

#include "delegated.h"

#define DEFAULT_DC_FILE_NAME			"dc.bin"
#define DEFAULT_DC_PRIVKEY_FILE_NAME	"dc_priv.key"

int main(int argc, char** argv) {
	if (argc != 4) {
		printf("Usage: generate_dc <Certificate> <PrivateKey> <ValidDays>\n");
		return 0;
	}

	char* cert_filename = argv[1];
	char* privkey_filename = argv[2];
	int valid_days = atoi(argv[3]);

	if (valid_days <= 0) {
		printf("<ValidDays> must be positive. (valid_days=[%d])\n", valid_days);
		return 0;
	}

	FILE* cert_fp = fopen(cert_filename, "r");
	if (cert_fp == NULL) {
		printf("Failed to read certificate file. (cert_filename=[%s])\n", cert_filename);
		return 0;
	}

	X509* cert = PEM_read_X509(cert_fp, NULL, NULL, NULL);
	fclose(cert_fp);

	if (cert == NULL) {
		printf("Certificate file format error.\n");
		return 0;
	}

	DelegatedCredential dc;
	memset(&dc, 0, sizeof(dc));

	// make Credential
	ASN1_TIME* not_before_asn1 = X509_get_notBefore(cert);
	ASN1_TIME* valid_time_asn1;

	time_t valid_time_t;
	valid_time_t = time(NULL);
	valid_time_asn1 = ASN1_TIME_adj(NULL, valid_time_t, valid_days, 0);
	int temp_day, temp_sec;
	ASN1_TIME_diff(&temp_day, &temp_sec, not_before_asn1, valid_time_asn1);
	dc.cred.valid_time = temp_day*24*60*60 + temp_sec;

	dc.cred.expected_cert_verify_algorithm = SSL_SIGN_ECDSA_SECP256R1_SHA256;	// fixed

	// generate DC's keypair
	EC_KEY* ec_key = EC_KEY_new();
	EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
	EC_KEY_set_group(ec_key, group);
	EC_GROUP_free(group);
	EC_KEY_generate_key(ec_key);

	EVP_PKEY* dc_keypair = EVP_PKEY_new();
	EVP_PKEY_assign_EC_KEY(dc_keypair, ec_key);
	dc.cred.ASN1_subjectPublicKeyInfo.len.uint = i2d_PUBKEY(dc_keypair, &dc.cred.ASN1_subjectPublicKeyInfo.data);
	if (dc.cred.ASN1_subjectPublicKeyInfo.len.uint <= 0) {
		printf("Certificate file format error.\n");
		goto end;
	}
  dprint("DC public key", dc.cred.ASN1_subjectPublicKeyInfo.data, 0, dc.cred.ASN1_subjectPublicKeyInfo.len.uint, 16);

	// make DelegatedCredential
	dc.algorithm = SSL_SIGN_ECDSA_SECP256R1_SHA256;	// fixed

	// cert der encode
	uint8_t* cert_der = NULL;
	int cert_len = i2d_X509(cert, &cert_der);
	if (cert_len < 0) {
		printf("Certificate file format error.\n");
		goto end;
	}

	/*
	 * DelegatedCredential.signature
	 *
	 *  1.  A string that consists of octet 32 (0x20) repeated 64 times. (64 bytes)
	 *  2.  The context string "TLS, server delegated credentials".	(33 bytes)
	 *  3.  A single 0 byte, which serves as the separator. (1 byte)
	 *  4.  The DER-encoded X.509 end-entity certificate used to sign the DelegatedCredential. (cert_len bytes)
	 *  5.  DelegatedCredential.cred. (spki_len + 4 + 2 + 3 bytes)
	 *  6.  DelegatedCredential.algorithm. (2 bytes)
	 */

	// read private key file
	FILE* privkey_fp = fopen(privkey_filename, "r");
	if (privkey_fp == NULL) {
		printf("Failed to read private key file. (privkey_filename=[%s])\n", privkey_filename);
		goto end;
	}

	EVP_PKEY* privkey = PEM_read_PrivateKey(privkey_fp, NULL, NULL, NULL);
	fclose(privkey_fp);

	if (privkey_fp == NULL) {
		printf("Private key file format error.\n");
		goto end;
	}

	CBB spki_cbb;
	CBB_init(&spki_cbb, 0);

	CBB cred_cbb;
	CBB_init(&cred_cbb, 0);
	CBB_add_u32(&cred_cbb, dc.cred.valid_time);
	CBB_add_u16(&cred_cbb, dc.cred.expected_cert_verify_algorithm);
	CBB_add_u24_length_prefixed(&cred_cbb, &spki_cbb);
	CBB_add_bytes(&spki_cbb, dc.cred.ASN1_subjectPublicKeyInfo.data, dc.cred.ASN1_subjectPublicKeyInfo.len.uint);
	CBB_flush(&cred_cbb);

	uint8_t* cred_buf = NULL;
	size_t cred_len;
	CBB_finish(&cred_cbb, &cred_buf, &cred_len);

	// sign
	EVP_MD_CTX* mctx;
	mctx = EVP_MD_CTX_create();
	EVP_SignInit(mctx, EVP_sha256());

	char spaces[64];
	for (int i=0; i<64; i++)
		spaces[i] = 0x20;
	char context[33] = "TLS, server delegated credentials";

	CBB signmsg_cbb;
	CBB_init(&signmsg_cbb, 0);
	CBB_add_bytes(&signmsg_cbb, spaces, 64);
	CBB_add_bytes(&signmsg_cbb, context, 33);
	CBB_add_u8(&signmsg_cbb, 0);
	CBB_add_bytes(&signmsg_cbb, cert_der, cert_len);
	CBB_add_bytes(&signmsg_cbb, cred_buf, cred_len);
	CBB_add_u16(&signmsg_cbb, dc.algorithm);

	uint8_t* signmsg_buf = NULL;
	size_t signmsg_len = 0;
	CBB_finish(&signmsg_cbb, &signmsg_buf, &signmsg_len);

  dprint("Message to be signed in DC", signmsg_buf, 0, signmsg_len, 16);
	EVP_SignUpdate(mctx, signmsg_buf, signmsg_len);
	dc.signature.data = malloc(EVP_PKEY_size(privkey));

	unsigned int sign_len = 0;
	int result = EVP_SignFinal(mctx, dc.signature.data, &sign_len, privkey);

	dc.signature.len = (uint16_t) sign_len;
	if (result != 1) {
		printf("Sign failed.\n");
		goto end;
	}

  EVP_PKEY *pub;
  EVP_MD_CTX *vctx;
  pub = X509_get_pubkey(cert);
  vctx = EVP_MD_CTX_create();
  EVP_VerifyInit(vctx, EVP_sha256());
  EVP_VerifyUpdate(vctx, signmsg_buf, signmsg_len);
  result = EVP_VerifyFinal(vctx, dc.signature.data, dc.signature.len, pub);

  uint8_t *pk_buf;
  size_t pk_len;

  pk_len = i2d_PUBKEY(pub, &pk_buf);
  dprint("Public key", pk_buf, 0, pk_len, 16);

  dprint("Signature", dc.signature.data, 0, dc.signature.len, 16);
	OPENSSL_free(signmsg_buf);
	EVP_MD_CTX_destroy(mctx);

	if (result != 1) {
		printf("Verify failed.\n");
		goto end;
	}

	// DC file write
	CBB sign_cbb;
	CBB_init(&sign_cbb, 0);

	CBB dc_cbb;
	CBB_init(&dc_cbb, 0);
	//printf("cred_len=[%d]\n", cred_len);
	CBB_add_bytes(&dc_cbb, cred_buf, cred_len);
	CBB_add_u16(&dc_cbb, dc.algorithm);
	CBB_add_u16_length_prefixed(&dc_cbb, &sign_cbb);
	CBB_add_bytes(&sign_cbb, dc.signature.data, dc.signature.len);
	CBB_flush(&dc_cbb);

	uint8_t* dc_buf = NULL;
	size_t dc_len;
	CBB_finish(&dc_cbb, &dc_buf, &dc_len);
	//printf("dc_len=[%d]\n", dc_len);

	FILE* dc_fp = fopen(DEFAULT_DC_FILE_NAME, "w");
	fwrite(dc_buf, 1, dc_len, dc_fp);
	//PEM_write(dc_fp, "DELEGATED CREDENTIAL", "", dc_buf, dc_len);
	fclose(dc_fp);
	OPENSSL_free(dc_buf);

	// DC privkey file write
	FILE* dc_privkey_fp = fopen(DEFAULT_DC_PRIVKEY_FILE_NAME, "w");
	i2d_PrivateKey_fp(dc_privkey_fp, dc_keypair);
	fclose(dc_privkey_fp);

end:

	if (cred_buf != NULL)
		OPENSSL_free(cred_buf);

	if (dc_keypair != NULL)
		EVP_PKEY_free(dc_keypair);

	if (dc.signature.data != NULL)
		free(dc.signature.data);

	if (cert_der != NULL) {
		OPENSSL_free(cert_der);
	}

	if (dc.cred.ASN1_subjectPublicKeyInfo.data != NULL)
		OPENSSL_free(dc.cred.ASN1_subjectPublicKeyInfo.data);

	if (cert != NULL)
		X509_free(cert);

	/*if (ec_key != NULL)
		EC_KEY_free(ec_key);*/

	printf("%s and %s are created.\n", DEFAULT_DC_FILE_NAME, DEFAULT_DC_PRIVKEY_FILE_NAME);

	return 0;
}
