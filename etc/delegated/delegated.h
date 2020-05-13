/*
 * Delegated Credentials for TLS
 * Header
 *
 * SNU MMLAB
 * Joonhee Lee
 */

#include <stdint.h>

#ifndef DELEGATED_H_
#define DELEGATED_H_

typedef struct {
	unsigned int uint: 24;
} uint24_t;

typedef struct {
	uint24_t len;
	uint8_t* data;
} vector24;

typedef struct {
	uint16_t len;
	uint8_t* data;
} vector16;

typedef struct {
	uint32_t valid_time;
	uint16_t expected_cert_verify_algorithm;
	vector24 ASN1_subjectPublicKeyInfo;
} Credential;

typedef struct {
	Credential cred;
	uint16_t algorithm;
	vector16 signature;
} DelegatedCredential;

#endif /* DELEGATED_H_ */
