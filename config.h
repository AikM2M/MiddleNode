#define TLS
#define TLS_PSK
//#define TLS_CERT
//#define	debug

#ifdef TLS
    #ifndef TLS_CERT
        #define TLS_PSK
    #endif
#endif

#define ADDRESS     "tcp://192.168.0.61:1883"

#ifdef TLS
#define ADDRESS     "ssl://192.168.0.61:8883"
#endif

#define CLIENTID    "MiddleNode"
#define QOS         1
#define TIMEOUT     10000L

char* const URI = "ssl://192.168.0.61:8883";

const char *pep_psk_key				= "0102030405";
const char *pep_psk_identity 		= "AE123-LOCK@in.provider.com";
int pep_uniPortNo 					= 10001;
const char* pep_ipAddress 			= "127.0.0.1";

char* CertAuth = "CERT/CertAuth.pem";
char* MNCert = "CERT/MiddleNode.pem";
char* PassCode = "ahsan";
char* MNKey = "CERT/MiddleNode.key";
