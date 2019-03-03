#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <time.h>
#include <resolv.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <pthread.h>
#include <openssl/opensslv.h>
#include <openssl/logs.h>
#include <errno.h>

//#include "log_client.h"

#define FAIL    -1
#define BUF_SIZE 16384

void *run(void *data);
int open_connection(const char *hostname, int port);
SSL_CTX* init_client_ctx(void);
void load_certificates(SSL_CTX* ctx, char* cert_file, char* key_file);
void load_ecdh_params(SSL_CTX *ctx);
SSL_CTX *ctx;
const char *hostname, *portnum, *fname;
log_t time_log[NUM_OF_LOGS];

// Client Prototype Implementation
int main(int count, char *strings[])
{   
  if ( count != 5 )
  {
    EDGE_LOG("usage: %s <hostname> <portnum> <num of threads> <log file>\n", strings[0]);
    exit(0);
  }

	int i, rc, num_of_threads;
	fname = strings[4];

	num_of_threads = atoi(strings[3]);

	pthread_t thread[num_of_threads];
	pthread_attr_t attr;
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
	void *status;

  SSL_library_init();
  hostname = strings[1];
  portnum = strings[2];

  ctx = init_client_ctx();
  load_ecdh_params(ctx);
	INITIALIZE_LOG(time_log);

	unsigned long start, end;

	start = get_current_millis();
	for (i=0; i<num_of_threads; i++)
	{
		rc = pthread_create(&thread[i], &attr, run, NULL);

		if (rc)
		{
			EDGE_LOG("ERROR: return code from pthread_create: %d\n", rc);
			return 1;
		}
	}

	pthread_attr_destroy(&attr);

	for (i=0; i<num_of_threads; i++)
	{
		rc = pthread_join(thread[i], &status);

		if (rc)
		{
			EDGE_LOG("ERROR: return code from pthread_join: %d\n", rc);
			return 1;
		}
	}
	end = get_current_millis();

	EDGE_LOG("TOTAL TIME: %lu ms\n", end - start);

	SSL_CTX_free(ctx);        /* release context */

	FINALIZE(time_log, fname);    

    return 0;
}

void *run(void *data)
{	
	int server, rcvd, sent, ret;
  unsigned char buf[BUF_SIZE];
	SSL *ssl;
  const char *request = 
    "GET / HTTP/1.1\r\n"
    "Host: www.bob.com\r\n\r\n";
  int request_len = strlen(request);

  RECORD_LOG(time_log, CLIENT_TCP_START);
	server = open_connection(hostname, atoi(portnum));
  RECORD_LOG(time_log, CLIENT_TCP_END);
  INTERVAL(time_log, CLIENT_TCP_START, CLIENT_TCP_END);

  ssl = SSL_new(ctx);   
  SSL_enable_ec(ssl);
  SSL_set_fd(ssl, server);
  SSL_set_tlsext_host_name(ssl, hostname);
  SSL_set_time_log(ssl, time_log);
  EDGE_LOG("%s:%s:%d: Set server name: %s", __FILE__, __func__, __LINE__, hostname);

	EDGE_MSG("PROGRESS: TLS Handshake Start");
	RECORD_LOG(SSL_get_time_log(ssl), CLIENT_BEFORE_TLS_CONNECT);

  if ( (ret = SSL_connect(ssl)) < 0 )   /* perform the connection */
  {
    EDGE_LOG("ret after SSL_connect: %d", ret);
    ERR_print_errors_fp(stderr);
  }
	else
	{
		RECORD_LOG(SSL_get_time_log(ssl), CLIENT_AFTER_TLS_CONNECT);
		INTERVAL(SSL_get_time_log(ssl), CLIENT_BEFORE_TLS_CONNECT, CLIENT_AFTER_TLS_CONNECT);
    printf("Connected with %s\n", SSL_get_cipher(ssl));
    RECORD_LOG(SSL_get_time_log(ssl), CLIENT_FETCH_HTML_START);
    sent = SSL_write(ssl, request, request_len);
    EDGE_LOG("Request: %s", request);
    EDGE_LOG("Sent Length: %d", sent);

    do {
      rcvd = SSL_read(ssl, buf, BUF_SIZE);
      EDGE_LOG("Received: %d", rcvd);
    } while (rcvd < 0);

    EDGE_LOG("Received after loop: %d", rcvd);
    EDGE_LOG("Error number: %d", errno);
    RECORD_LOG(SSL_get_time_log(ssl), CLIENT_FETCH_HTML_END);
    INTERVAL(SSL_get_time_log(ssl), CLIENT_FETCH_HTML_START, CLIENT_FETCH_HTML_END);
		buf[rcvd] = 0;
    EDGE_LOG("Response:\n %s\n", buf);
    EDGE_LOG("Rcvd Length: %d\n", rcvd);
	}
  
  PRINT_LOG(SSL_get_time_log(ssl));
  FINALIZE(SSL_get_time_log(ssl), fname);
	SSL_free(ssl);        /* release connection state */
       
	close(server);         /* close socket */
}

int open_connection(const char *hostname, int port)
{   
  int sd;
  struct hostent *host;
  struct sockaddr_in addr;
            
  if ( (host = gethostbyname(hostname)) == NULL )
  {
    perror(hostname);
    abort();
  }
    
  sd = socket(PF_INET, SOCK_STREAM, 0);
  bzero(&addr, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = *(long*)(host->h_addr);

  if ( connect(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
  {
    close(sd);
    perror(hostname);
    abort();
  }
         
  return sd;
}

SSL_CTX* init_client_ctx(void)
{   
  SSL_METHOD *method;
  SSL_CTX *ctx;
        
  //OpenSSL_add_all_algorithms();  /* Load cryptos, et.al. */
  SSL_load_error_strings();   /* Bring in and register error messages */
  method = (SSL_METHOD *)TLS_client_method();  /* Create new client-method instance */
  ctx = SSL_CTX_new(method);   /* Create new context */
  
  if ( ctx == NULL )
  {
    ERR_print_errors_fp(stderr);
    abort();
  }

  SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);

  return ctx;
}
 
void load_certificates(SSL_CTX* ctx, char* cert_file, char* key_file)
{
	if ( SSL_CTX_load_verify_locations(ctx, NULL, "/etc/ssl/certs") != 1)
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
	else
		EDGE_LOG("SSL_CTX_load_verify_locations success\n");

	if ( SSL_CTX_set_default_verify_paths(ctx) != 1)
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
	else
		EDGE_LOG("SSL_CTX_set_default_verify_paths success\n");

  /* set the local certificate from CertFile */
  if ( SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0 )
  {
    ERR_print_errors_fp(stderr);
    abort();
	}
  else
		EDGE_LOG("SSL_CTX_use_certificate_file success\n");

	/* set the private key from KeyFile (may be the same as CertFile) */
  if ( SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0 )
  {
    ERR_print_errors_fp(stderr);
    abort();
  }
	else
		EDGE_LOG("SSL_CTX_use_PrivateKey_file success\n");
    
	/* verify private key */
  if ( !SSL_CTX_check_private_key(ctx) )
  {
    ERR_print_errors_fp(stderr);
    abort();
  }
	else
	   	EDGE_LOG("Private key matches the public certificate\n");

//	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
	ERR_print_errors_fp(stderr);
	SSL_CTX_set_verify_depth(ctx, 4);
	ERR_print_errors_fp(stderr);
  SSL_CTX_set_cipher_list(ctx, "ECDHE-ECDSA-AES128-GCM-SHA256");
}

void load_ecdh_params(SSL_CTX *ctx)
{
  EC_KEY *ecdh;
  ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);

  if (!ecdh)
    perror("Couldn't load the ec key");

  if (SSL_CTX_set_tmp_ecdh(ctx, ecdh) != 1)
    perror("Couldn't set the ECDH parameter (NID_X9_62_prime256v1)");
}
