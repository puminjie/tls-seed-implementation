#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <string.h>

#include "keyless.h"
#include "keyless_kssl.h"
#include "keyless_kssl_helpers.h"

unsigned char ipv6[16] = {0x0, 0xf2, 0x13, 0x48, 0x43, 0x01};
unsigned char ipv4[4] = {127, 0, 0, 1};

#if PLATFORM_WINDOWS
#define SOCKET_CLOSE closesocket
#else
#define SOCKET_CLOSE close
#endif

struct hostent *localhost;
static const char *HEX_DIGITS = "0123456789ABCDEF";

// digest_public_ec: calculates the SHA256 digest of the
// hexadecimal representation of the EC public key group and
// point. digest must be initialized with at least 32 bytes of
// space.
void digest_public_ec(EC_KEY *ec_key, BYTE *digest) {
  char *ret, *p;
  unsigned char *buf, *pbuf;
  size_t buf_len = 0, i, ret_len;
  const EC_POINT *ec_pub_key = EC_KEY_get0_public_key(ec_key);
  const EC_GROUP *group = EC_KEY_get0_group(ec_key);
  buf_len = EC_POINT_point2oct(group, ec_pub_key, POINT_CONVERSION_COMPRESSED, NULL, 0, NULL);
  buf = OPENSSL_malloc(buf_len);
  buf_len = EC_POINT_point2oct(group, ec_pub_key, POINT_CONVERSION_COMPRESSED, buf, 
      buf_len, NULL);
  ret_len = buf_len * 2 + 2;
  ret = (char *)OPENSSL_malloc(ret_len);
  p = ret;
  pbuf = buf;
  for (i = buf_len; i > 0; i--)
  {
    int v = (int)*(pbuf++);
    *(p++) = HEX_DIGITS[v >> 4];
    *(p++) = HEX_DIGITS[v & 0x0F];
  }
  *p = '\0';
  OPENSSL_free(buf);

  EVP_MD_CTX *ctx;

  ctx = EVP_MD_CTX_create();
  EVP_DigestInit_ex(ctx, EVP_sha256(), 0);
  EVP_DigestUpdate(ctx, ret, ret_len);
  EVP_DigestFinal_ex(ctx, digest, 0);
  EVP_MD_CTX_destroy(ctx);
}

// ssl_error: call when a fatal SSL error occurs. Exits the program
// with return code 1.
void ssl_error(void)
{
  ERR_print_errors_fp(stderr);
  exit(1);
}

// fatal_error: call to print an error message to STDERR. Exits the
// program with return code 1.
void fatal_error(const char *fmt, ...)
{
  va_list l;
  va_start(l, fmt);
  vfprintf(stderr, fmt, l);
  va_end(l);
  fprintf(stderr, "\n");

  exit(1);
}

// digest_public_rsa: calculates the SHA256 digest of the
// hexadecimal representation of the public modulus of an RSA
// key. digest must be initialized with at least 32 bytes of
// space.
void digest_public_rsa(RSA *key, BYTE *digest)
{
  // QUESTION: can we use a single EVP_MD_CTX for multiple
  // digests?
  char *hex;
  EVP_MD_CTX *ctx;

  ctx = EVP_MD_CTX_create();
  EVP_DigestInit_ex(ctx, EVP_sha256(), 0);
  hex = BN_bn2hex(key->n);
  EVP_DigestUpdate(ctx, hex, strlen(hex));
  EVP_DigestFinal_ex(ctx, digest, 0);
  EVP_MD_CTX_destroy(ctx);
  OPENSSL_free(hex);
}

// test_assert: assert that some condition is true, fatal
// error if not
void test_assert(int a)
{
  if (!a) {
    fatal_error(" test failure");
  }
//  tests += 1;
}

// ok: indicate that some tests passed and free memory
void ok(kssl_header *h)
{
  printf(" ok\n");
  if (h != 0) {
    free(h->data);
    free(h);
  }
}

// kssl: send a KSSL message to the server and read the response
kssl_header *kssl(SSL *ssl, kssl_header *k, kssl_operation *r)
{
  BYTE buf[KSSL_HEADER_SIZE];
  BYTE *req;
  int req_len;
  int n;
  kssl_header h;
  kssl_header *to_return;

  flatten_operation(k, r, &req, &req_len);

//  dump_header(k, "send");
//  dump_request(r);

  n = SSL_write(ssl, req, req_len);
  if (n != req_len) {
    fatal_error("Failed to send KSSL header");
  }

  free(req);

  while (1) {
    n = SSL_read(ssl, buf, KSSL_HEADER_SIZE);
    if (n <= 0) {
      int x = SSL_get_error(ssl, n);
      if (x == SSL_ERROR_WANT_READ || x == SSL_ERROR_WANT_WRITE) {
        continue;
      } else if (x == SSL_ERROR_ZERO_RETURN) {
        fatal_error("Connection closed while reading header\n");
      } else {
        fatal_error("Error performing SSL_read: %x\n", x);
      }
    } else {
      if (n != KSSL_HEADER_SIZE) {
        fatal_error("Error receiving KSSL header, size: %d", n);
      }
    }

    break;
  }

  parse_header(buf, &h);
  if (h.version_maj != KSSL_VERSION_MAJ) {
    fatal_error("Version mismatch %d != %d", h.version_maj, KSSL_VERSION_MAJ);
  }
  if (k->id != h.id) {
    fatal_error("ID mismatch %08x != %08x", k->id, h.id);
  }

  //dump_header(&h, "recv");

  to_return = (kssl_header *)malloc(sizeof(kssl_header));
  memcpy(to_return, &h, sizeof(kssl_header));


  if (h.length > 0) {
    BYTE *payload = (BYTE *)malloc(h.length);
    while (1) {
      n = SSL_read(ssl, payload, h.length);
      if (n <= 0) {
        int x = SSL_get_error(ssl, n);
        if (x == SSL_ERROR_WANT_READ || x == SSL_ERROR_WANT_WRITE) {
          continue;
        } else if (x == SSL_ERROR_ZERO_RETURN) {
          fatal_error("Connection closed while reading payload\n");
        } else {
          fatal_error("Error performing SSL_read: %x\n", x);
        }
      } else {
        if (n != h.length) {
          fatal_error("Error receiving KSSL payload, size: %d", n);
        }
      }

      break;
    }

    if (n != h.length) {
      fatal_error("Failed to read payload got length %d wanted %d", n, h.length);
    }

//    dump_payload(h.length, payload);
    to_return->data = payload;
  }

  return to_return;
}

int kssl_op_rsa_decrypt(connection *c, int flen, unsigned char *from,
			unsigned char *to, RSA *rsa_pubkey)
{
//static int count = 0;
//char kryptos2[255];
  kssl_header decrypt;
  kssl_operation req, resp;
  kssl_header *h;
//int size;
  //test("KSSL_OP_RSA_DECRYPT (%p)", c);
  decrypt.version_maj = KSSL_VERSION_MAJ;
  decrypt.id = 0x1234567a;
  zero_operation(&req);
  req.is_opcode_set = 1;
  req.is_payload_set = 1;
  req.is_digest_set = 1;
  req.is_ip_set = 1;
  req.ip = ipv6;
  req.ip_len = 16;
  req.payload = malloc(flen);
  memcpy(req.payload, from, flen);
  //req.payload = malloc(RSA_size(rsa_pubkey));
  req.payload_len = flen;
  //req.payload_len = RSA_size(rsa_pubkey);
  //req.payload = from; //malloc(RSA_size(rsa_pubkey));
  //req.payload_len = flen; //RSA_size(rsa_pubkey);
  req.digest = malloc(KSSL_DIGEST_SIZE);
  digest_public_rsa(rsa_pubkey, req.digest);
  req.opcode = KSSL_OP_RSA_DECRYPT;

  printf("req.payload_len: %d\n", flen);
  printf("req.payload:\n");
  int n = 0;
  for(n = 0; n < req.payload_len; n++)
  {
    if (n % 9 == 0)
      printf("\n");
    printf("%02X ", req.payload[n]);
  }
//sprintf(kryptos2, "%02x It was totally invisible, how's that possible?", count);
//count += 1;

//size = RSA_public_encrypt(strlen(kryptos2), (unsigned char *)kryptos2,
//                              (unsigned char *)req.payload,
//                              rsa_pubkey, RSA_PKCS1_PADDING);
//if (size == -1) {
//  fatal_error("Failed to RSA encrypt");
//}

  int num = 0;
  printf("******Internal Test 1******\n");
  h = kssl(c->ssl, &decrypt, &req);
  printf("******Internal Test 2******\n");
  test_assert(h->id == decrypt.id);
  test_assert(h->version_maj == KSSL_VERSION_MAJ);
  printf("h->data: \n");
  for(num = 0; num < h->length; num++)
  {
    if (num % 9 == 0)
      printf("\n");
    printf("%02X ", h->data[num]);
  }
  parse_message_payload(h->data, h->length, &resp);
  printf("******Internal Test 3******\n");
  test_assert(resp.opcode == KSSL_OP_RESPONSE);
//test_assert(resp.payload_len == strlen(kryptos2));
//test_assert(strncmp((char *)resp.payload, kryptos2, strlen(kryptos2)) == 0);
  printf("resp.payload_len: %d\n", resp.payload_len);
  printf("resp.payload: \n");
  for(num = 0; num < resp.payload_len; num++)
  {
    if (num % 9 == 0)
      printf("\n");
    printf("%02X ", resp.payload[num]);
  }
  memcpy(to, resp.payload, resp.payload_len);
  ok(h);
  printf("******Internal Test 4******\n");
  free(req.payload);
  printf("******Internal Test 5******\n");
  free(req.digest);
  return resp.payload_len;
}

void kssl_op_ecdsa_sign(connection *c, BYTE *in, int ilen, uint8_t *out, size_t *olen, 
    int opcode)
{
  int i, rc;
  FILE *fp;
  kssl_header *h;
  kssl_header sign;
  kssl_operation req, resp;
  EVP_PKEY *evp_pubkey_tmp;
  EC_KEY *ecdsa_pubkey;

  fp = fopen(PUBKEY_PATH, "r");
  evp_pubkey_tmp = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
  fclose(fp);
  if (!evp_pubkey_tmp)
  {
    fatal_error("Error reading EC pubkey");
  }
  ecdsa_pubkey = EVP_PKEY_get1_EC_KEY(evp_pubkey_tmp);
  if (!ecdsa_pubkey)
  {
    ssl_error();
  }

  sign.version_maj = KSSL_VERSION_MAJ;
  sign.id = 0x1234567a;
  zero_operation(&req);
  req.is_opcode_set = 1;
  req.is_payload_set = 1;
  req.is_digest_set = 1;
  req.is_ip_set = 1;
  req.ip = ipv4;
  req.ip_len = 4;
  req.digest = malloc(KSSL_DIGEST_SIZE);
  digest_public_ec(ecdsa_pubkey, req.digest);
  req.payload = in;
  req.payload_len = ilen;
  req.opcode = ecdsa_algs[opcode];

  h = kssl(c->ssl, &sign, &req);
  test_assert(h->id == sign.id);
  test_assert(h->version_maj == KSSL_VERSION_MAJ);
  parse_message_payload(h->data, h->length, &resp);
  test_assert(resp.opcode == KSSL_OP_RESPONSE);

  *olen = resp.payload_len;
  memcpy(out, resp.payload, *olen);

  free(h);
  free(req.digest);

  ok(0);
}


// ssl_connect: establish a TLS connection to the keyserver on
// the passed in port number
connection *ssl_connect(SSL_CTX *ctx, const char *domain, int port)
{
  struct sockaddr_in addr;
  int rc;
  struct hostent *host;
  connection *c = (connection *)calloc(1, sizeof(connection));

  c->fd = socket(AF_INET, SOCK_STREAM, 0);
  if (c->fd == -1) {
    fatal_error("Can't create TCP socket");
  }

  if ((host = gethostbyname(domain)) == NULL)
  {
    perror(domain);
    abort();
  }

  memset(&addr, 0, sizeof(struct sockaddr_in));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = *(long *)(host->h_addr);
  memset(&(addr.sin_zero), 0, 8);

  if (connect(c->fd, (struct sockaddr *)&addr, sizeof(struct sockaddr_in)) == -1) {
    fatal_error("Failed to connect to keyserver on port %d", port);
  }

  c->ssl = SSL_new(ctx);
  if (!c->ssl) {
    fatal_error("Failed to create new SSL context");
  }
  SSL_set_fd(c->ssl, c->fd);

  rc = SSL_connect(c->ssl);
  if (rc != 1) {
    ERR_print_errors_fp(stderr);
    fatal_error("TLS handshake error %d/%d/%d\n", rc,
                SSL_get_error(c->ssl, rc), errno);
  }

  return c;
}

// ssl_disconnect: drop and cleanup connection to TLS server created using
// ssl_connect
void ssl_disconnect(connection *c)
{
  SSL_shutdown(c->ssl);
  SOCKET_CLOSE(c->fd);
  SSL_free(c->ssl);
  free(c);
}

