//	File Name:		MAF_Client.cpp
//	File Purpose:	This file contains detailed implementation of a Client application 
//					which connects to MAF-Serverc to extract credentials
//	Date & Time:	June 08, 2019 | 19:09 PM
//	Author:			Bilal Imran

#include "PEP.h"

int MAFClient::maf_dtls_verify_callback (int ok, X509_STORE_CTX *ctx) {
	/* This function should ask the user
	 * if he trusts the received certificate.
	 * Here we always trust.
	 */
	return 1;
}

unsigned int psk_client_cb(SSL *ssl, const char *hint, char *identity,
                                  unsigned int max_identity_len,
                                  unsigned char *psk,
                                  unsigned int max_psk_len)
{
    int ret;
    long key_len;
    unsigned char *key;

    if (!hint) {
        /* no ServerKeyExchange message */
            printf("NULL received PSK identity hint, continuing anyway\n");
    } else {
        printf("Received PSK identity hint '%s'\n", hint);
    }

    /*
     * lookup PSK identity and PSK key based on the given identity hint here
     */
    ret = snprintf(identity, max_identity_len, "%s", maf_psk_identity);
    if (ret < 0 || (unsigned int)ret > max_identity_len)
        goto out_err;
        printf("created identity '%s' len=%d\n", identity,
                   ret);

    /* convert the PSK key to binary */
    key = OPENSSL_hexstr2buf(maf_psk_key, &key_len);
    if (key == NULL) {
        printf("Could not convert PSK key '%s' to buffer\n",
                   maf_psk_key);
        return 0;
    }
    if (max_psk_len > INT_MAX || key_len > (long)max_psk_len) {
        printf("psk buffer of callback is too small (%d) for key (%ld)\n",
                   max_psk_len, key_len);
        OPENSSL_free(key);
        return 0;
    }

    memcpy(psk, key, key_len);
    OPENSSL_free(key);

    printf("created PSK len=%ld\n", key_len);

    return key_len;

 out_err:
    printf("Error in PSK client callback\n");
    return 0;
}

int MAFClient::MAFClientDTLSInitialize() {	

/* Module 01:
 * [Start] SSL Session Creation via Context _ctx */
	OpenSSL_add_ssl_algorithms();
	SSL_load_error_strings();
	maf_ctx = SSL_CTX_new(DTLSv1_2_client_method());

/* We accept all ciphers, including NULL.
 * Not recommended beyond testing and debugging */	
// SSL_CTX_set_cipher_list(ctx, "ECDHE-ECDSA-AES256-GCM-SHA384");
	
	SSL_CTX_set_cipher_list(maf_ctx, "ALL:NULL:eNULL:aNULL");
	SSL_CTX_set_session_cache_mode(maf_ctx, SSL_SESS_CACHE_OFF);

#ifdef MAF_USE_CERT	 
	if (!SSL_CTX_use_certificate_file(maf_ctx, srvFILE, SSL_FILETYPE_PEM))
		printf("\nERROR: no certificate found!");
		
	if (!SSL_CTX_use_PrivateKey_file(maf_ctx, srvKEY, SSL_FILETYPE_PEM))
		printf("\nERROR: no private key found!");

	if (!SSL_CTX_check_private_key (maf_ctx))
		printf("\nERROR: invalid private key!");

	/* Client has to authenticate */
	SSL_CTX_set_verify(maf_ctx, SSL_VERIFY_NONE, maf_dtls_verify_callback);
#endif

#ifdef MAF_USE_PSK
	/* Use Psk & it's Psk-Hint */
	SSL_CTX_set_psk_client_callback(maf_ctx, &psk_client_cb);
#endif

	SSL_CTX_set_read_ahead(maf_ctx, 1);
			
	maf_ssl = SSL_new(maf_ctx);

	/* Create BIO*/ 
	maf_bio = BIO_new_dgram(maf_sockfdUnicast, BIO_CLOSE);
	connect(maf_sockfdUnicast, (struct sockaddr *) &maf_addru, sizeof(struct sockaddr_in));
	BIO_ctrl(maf_bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, &maf_addru);

	SSL_set_bio(maf_ssl, maf_bio, maf_bio); 
// [END]
	return 0;
}

int MAFClient::MAFClientDTLSHandshake() {	
/* Finish handshake */
	int ret;
	do { 
		ret = SSL_connect(maf_ssl);
	}
	while (ret <= 0);
	
	char* buf;
	if (ret < 0) {
		perror("SSL_connect");
		printf("%s\n", ERR_error_string(ERR_get_error(), buf));
		return ret;
	}
	
/* Set and activate timeouts */
	maf_timeout.tv_sec = 5;
	maf_timeout.tv_usec = 0;
	BIO_ctrl(SSL_get_rbio(maf_ssl), BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &maf_timeout);

#ifdef MAF_USE_CERT
	if (SSL_get_peer_certificate(maf_ssl)) {
		printf ("------------------------------------------------------------\n");
		X509_NAME_print_ex_fp(stdout, X509_get_subject_name(SSL_get_peer_certificate(maf_ssl)), 1, XN_FLAG_MULTILINE);
		printf("\n\n Cipher: %s", SSL_CIPHER_get_name(SSL_get_current_cipher(maf_ssl)));
		printf ("\n------------------------------------------------------------\n\n");
	}
#endif	
		
return 0;
}

int MAFClient::MAFClientUDPPortOpen()
{
	char loopch = 0;
	const int reuse = 1;

	if (maf_uniPortNo == 0)
	{
		printf("error portNo undefined in UDPPort::open\n");
		return -1;
	}

	uint32_t ip = inet_addr(maf_ipAddress);
	
	/*------ Create unicast socket --------*/
	maf_sockfdUnicast = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (maf_sockfdUnicast < 0)
	{
		printf("error can't create unicast socket in UDPPort::open\n");
		return -1;
	}

	setsockopt(maf_sockfdUnicast, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

	maf_addru.sin_family = AF_INET;
	maf_addru.sin_port = htons(maf_uniPortNo);
	maf_addru.sin_addr.s_addr = INADDR_ANY;

	return 0;
}

int MAFClient::MAFClientSend() {
	return SSL_write(maf_ssl, maf_send_buf, MAF_MAX_PACKET_SIZE);
}

int MAFClient::MAFClientRecieve() {
	return SSL_read(maf_ssl, maf_recv_buf, MAF_MAX_PACKET_SIZE);
}

int MAFClient::MAFClientClose() {
	close(maf_sockfdUnicast);
	SSL_shutdown(maf_ssl);
	SSL_free(maf_ssl);
}

int MAFClient::StartMAFClient(){
	int rc;
	MAFClientUDPPortOpen();
	MAFClientDTLSInitialize();
	
	if ((rc = MAFClientDTLSHandshake()) != 0) {
		printf("MAFClientDTLSHandshake [Status = Failed] \n");
		return -1;	
	}
	else {
		printf("MAFClientDTLSHandshake [Status = Ok] \n");
		ISMAFClientConnected = true;
	}
    return 0;
}

/*	Main Function
int main () {
	int rc;
	char input;
	wchar_t* srvrespbuf;
	MAFClient mafclient; 

	if ((rc = mafclient.StartMAFClient()) != 0) {
		printf("StartMAFClient [Status: Failed]\n");
	}
	printf("StartMAFClient [Status: OK]\n");

	mafclient.MAFClientClose();
	return 0;
} 
*/
