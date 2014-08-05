#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/time.h>
#include <time.h>
#include <signal.h>

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h> // iphdr
#include <netdb.h>  //hostent
#include <net/if.h>
#include <net/ethernet.h> //ETH_P_ALL
#include <linux/if_packet.h> //sll
/* For Parsing Certificates */
#include <openssl/x509v3.h>
#include <openssl/bn.h>
#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/md5.h>
/* end */
typedef unsigned short u16;
typedef unsigned short ushort;
typedef unsigned long u32;
typedef unsigned char u8;
typedef unsigned char uchar;

#define SSL_MAX_SIZE 5000
#define RECORD_HDR_LEN 5
#define SSL_INNER_HDR_LEN 4

/**********
 Record Protocol Header
 **********/
typedef enum {
        change_cipher_spec = 20, alert = 21, handshake = 22,
        application_data = 23
} ContentType;

typedef struct {
          uchar major;
          uchar minor;
} ProtocolVersion;

typedef struct {
        ContentType type;
        ProtocolVersion version;
        u16 length;
} RecordHdrPlainTxt;
/**********
 Record Protocol Header
 **********/
typedef enum {          
          hello_request=0, client_hello=1, server_hello=2,
          certificate=11, server_key_exchange =12,
          certificate_request=13, server_hello_done=14,
          certificate_verify=15, client_key_exchange=16,
          finished=20
} HandshakeType;


typedef struct {
		int state;
        uchar *buff;
        int buffLen;
        char srcIP[20];
        ushort srcPort;
        char sessionIDLen;
        char sessionID[40];
        int versionResp[2];
        int handshakeResp;
		RSA *rsa_key;
		// Stuff needed to create MasterSecret
		uchar clientHandshakeMsgs[6000];
		int clientHandshakeMsgsIndex;
		uchar random[32];
		uchar serverRandom[32];
		uchar preMasterSecret[48];
		uchar masterSecret[48];
} sslStruct;

typedef struct {
	int		event;
	uchar	*p_buff;
	int		p_buffLen;
	sslStruct *sslC;
} fsmEvent_t;

typedef struct {
        int sock;
        int sessionID;

        // Self
        char selfIP[20];
	char interface[20];
        ushort startPort;
	ushort sslPort;

        // Unit under test
        struct sockaddr_in server_addr;
        struct          sockaddr_ll sll;
        char utIP[20];

        // Multiple SSL clients
        sslStruct *sslC;
} sslCfg;
// TBD - change the following as _1 and _2 
#define TLS_RSA_WITH_NULL_MD5 "0x00,0x01"
#define TLS_RSA_WITH_NULL_SHA "0x00,0x02"
#define TLS_RSA_WITH_NULL_SHA256 "0x00,0x3B"
#define TLS_RSA_WITH_RC4_128_MD5 "0x00,0x04"
#define TLS_RSA_WITH_RC4_128_SHA_1 0x00
#define TLS_RSA_WITH_RC4_128_SHA_2 0x05
#define TLS_RSA_WITH_3DES_EDE_CBC_SHA "0x00,0x0A"
#define TLS_RSA_WITH_AES_128_CBC_SHA  "0x00,0x2F"
#define TLS_RSA_WITH_AES_256_CBC_SHA  "0x00,0x35"
#define TLS_RSA_WITH_AES_128_CBC_SHA256 "0x00,0x3C"
#define TLS_RSA_WITH_AES_256_CBC_SHA256 "0x00,0x3D"

// FSM Defines
#define NO_CHANGE 99
int fsmRoutine();

typedef struct {
	int (*funcPtr)(sslStruct *sslC , uchar *p_buff, int event);
	int nextState;
} fsm;

int sslError(sslStruct *sslC, uchar *p_buff, int event);
int sendClientKeyExchange(sslStruct *sslC, uchar *p_buff, int event);
int recvChangeCipherSpec(sslStruct *sslC, uchar *p_buff, int event);
int recvCertificate(sslStruct *sslC, uchar *p_buff, int event);
int recvServerHello(sslStruct *sslC, uchar *p_buff, int event);
int recvServerHelloAgain(sslStruct *sslC, uchar *p_buff, int event);

