#ifndef _PEP_CLIENT_H_
#define _PEP_CLIENT_H_

//	File Name:		PEP_Client.cpp
//	File Purpose:	This file contains detailed implementation of a Client application 
//					which connects to PEP-Serverc to extract credentials
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

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>

using namespace std;

/* DTLS Control Parameter 
 * <DTLS-with-PSK> USE_PSK
 * <DTLS-with-CERT> USE_CERT
 * */
//#define PEP_USE_CERT 			
#define PEP_USE_PSK

#define PEP_MAX_PACKET_SIZE			1500
#define PEP_PSK_KEY_LENGTH			5 			
#define PEP_COOKIE_SECRET_LENGTH 	8
#define PEP_MaxRows					3
#define PEP_MaxColumns				3
#define MaxUpperBytes				8		// 16 Bytes or (32 hex characters)
#define MaxLowerBytes				16		// 32 Bytes or (64 hex characters)
#define MAXIDLength					22

static unsigned int psk_client_cb(SSL *ssl, const char *hint, char *identity,
	                                  unsigned int max_identity_len,
	                                  unsigned char *psk,
	                                  unsigned int max_psk_len);

extern const char *pep_psk_key;
extern const char *pep_psk_identity;
extern int pep_uniPortNo;
extern const char* pep_ipAddress;
static bool ISPEPClientRegistered 			= false;
static bool ISPEPClientKeyRegistered 		= false;
static bool ISPEPClientConnected 			= false;

// class PEPClient
class PEPClient {
public:
	// Global Variables
	const char* pep_caFILE;
	const char* pep_caKEY;
	const char* pep_srvFILE;
	const char* pep_srvKEY;

	char* pep_send_buf;
	char pep_recv_buf[PEP_MAX_PACKET_SIZE];
	unsigned char* exportedkeymat;
	
	sockaddr_in pep_addru;
	int pep_sockfdUnicast;
	   	
	SSL_CTX *pep_ctx;
	SSL *pep_ssl;
	BIO *pep_bio;
	struct timeval pep_timeout;
	struct pass_info *pep_info;

	//	Function Declarations
	int pep_dtls_verify_callback (int ok, X509_STORE_CTX *ctx); 
	int PEPClientUDPPortOpen();
	int PEPClientDTLSInitialize();
	int PEPClientDTLSHandshake();
	int PEPClientSend();
	int PEPClientRecieve();
	int PEPClientClose();
	int StartPEPClient();
};

#endif

// Test Code
//#include "PEP.h"


/*	Main Function
int main () {
	int rc;
	char input;
	wchar_t* srvrespbuf;
	PEPClient pepclient; 

	if ((rc = pepclient.StartPEPClient()) != 0) {
		printf("StartPEPClient [Status: Failed]\n");
	}
	printf("StartPEPClient [Status: OK]\n");

	pepclient.PEPClientClose();
	return 0;
} 
*/

