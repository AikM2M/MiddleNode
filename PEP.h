#ifndef _MAF_CLIENT_H_
#define _MAF_CLIENT_H_

//	File Name:		MAF_Client.cpp
//	File Purpose:	This file contains detailed implementation of a Client application 
//					which connects to MAF-Serverc to extract credentials
//	Date & Time:	June 08, 2019 | 19:09 PM
//	Author:			Bilal Imran

#include <string>

#include <stdio.h>
#include <iostream>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <regex>
#include <string>
#include <stdlib.h>

#include <sys/time.h>
#include <netinet/in.h>

//#include <openssl/ssl.h>
//#include <openssl/bio.h>
//#include <openssl/err.h>
//#include <openssl/rand.h>
//#include <openssl/hmac.h>

using namespace std;

/* DTLS Control Parameter 
 * <DTLS-with-PSK> USE_PSK
 * <DTLS-with-CERT> USE_CERT
 * */
//#define MAF_USE_CERT 			
#define MAF_USE_PSK

#define MAF_MAX_PACKET_SIZE			1500
#define MAF_PSK_KEY_LENGTH			5 			
#define MAF_COOKIE_SECRET_LENGTH 	8
#define MAF_MaxRows					3
#define MAF_MaxColumns				3
#define MaxUpperBytes				8		// 16 Bytes or (32 hex characters)
#define MaxLowerBytes				16		// 32 Bytes or (64 hex characters)
#define MAXIDLength					22

static unsigned int psk_client_cb(SSL *ssl, const char *hint, char *identity,
	                                  unsigned int max_identity_len,
	                                  unsigned char *psk,
	                                  unsigned int max_psk_len);

static const char *keymatexportlabel 		= "oneM2M-Key-Export";
static const char *maf_psk_key				= "0102030405";
static const char *maf_psk_identity 		= "AE123-LOCK@in.provider.com";
static int maf_uniPortNo 					= 10001;
static int keymatexportlen					= 24;
static const char* maf_ipAddress 			= "127.0.0.1";
static bool ISMAFClientRegistered 			= false;
static bool ISMAFClientKeyRegistered 		= false;
static bool ISMAFClientConnected 			= false;

// class MAFClient
class MAFClient {
public:
	// Global Variables
	const char* maf_caFILE;
	const char* maf_caKEY;
	const char* maf_srvFILE;
	const char* maf_srvKEY;

	char* maf_send_buf;
	char maf_recv_buf[MAF_MAX_PACKET_SIZE];
	unsigned char* exportedkeymat;
	
	sockaddr_in maf_addru;
	int maf_sockfdUnicast;
	   	
	SSL_CTX *maf_ctx;
	SSL *maf_ssl;
	BIO *maf_bio;
	struct timeval maf_timeout;
	struct pass_info *maf_info;

	//	Function Declarations
	int maf_dtls_verify_callback (int ok, X509_STORE_CTX *ctx); 
	int MAFClientUDPPortOpen();
	int MAFClientDTLSInitialize();
	int MAFClientDTLSHandshake();
	int MAFClientSend();
	int MAFClientRecieve();
	int MAFClientClose();
	int StartMAFClient();
};

#endif

//	File Name:		MAF_Client.cpp
//	File Purpose:	This file contains detailed implementation of a Client application 
//					which connects to MAF-Serverc to extract credentials
//	Date & Time:	June 08, 2019 | 19:09 PM
//	Author:			Bilal Imran

//#include "PEP.h"


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

