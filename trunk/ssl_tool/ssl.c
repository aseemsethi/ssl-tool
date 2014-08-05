/*
 * openssl API use from the URL:
 * zakird.com/2013/10/13/certificate-parsing-with-openssl
 *
 * Intersting Paper on Certificates in the Internet URL:
 * 		https://jhalderm.com/pib/papers/https-imc13.pdf
 * Over 98% of browser-trusted leaf certs were signed by 2048-bit RSA key.
 * Over 99% leaf certs contain RSA Public Keys
 * 98% of leaf certs were signed by intermediate authorites that were 1 
 * intermediate away from a root authority.
 *
 */
#include "util.h"
#include "ssl.h"

/*
#define SERVER "206.190.36.45"
#define SSL_PORT 443
*/
#define SSL_VERSION_1 3
#define SSL_VERSION_2 0
// SSL 3.0 (0x0300) needs Version as part of Encrypted Key Client Key Exchange
// TLS 1.0 (0x0301) onwards needs Length in Client Key Exchange
sslCfg cfg;
struct sigaction sigact;
/************** FSM *****************/
// Events
#define HELLO_REQ 		0
#define CLIENT_HELLO 	1
#define SERVER_HELLO	2
#define CERTIFICATE		3
#define SERVER_KEY_EXCHANGE	4
#define CERTIFICATE_REQ		5
#define SERVER_HELLO_DONE	6
#define CERTIFICATE_VERIFY	7
#define CLIENT_KEY_EXCHANGE	8
#define FINISHED			9
#define CHANGE_CIPHER_SPEC	10
#define NULL_EVENT			99
// States
#define SSL_INIT 0
#define SSL_HELLO_DONE_RECVD 1
#define SSL_CHANGE_CIPHER_SPEC_RECVD 2
#define SSL_FINISHED_RECVD 3
#define SSL_CLEANUP 4

fsm sslFsm[5][11] = {
{ /* SSL_INIT */
	{sslError, NO_CHANGE}, // hello_req
	{sslError, NO_CHANGE}, // client_hello
	{recvServerHello, NO_CHANGE}, // server_hello
	{recvCertificate, NO_CHANGE}, // certificate
	{sslError, NO_CHANGE}, // server_key_exchange
	{sslError, NO_CHANGE}, // certificate_req
	{sendClientKeyExchange, SSL_HELLO_DONE_RECVD}, // server_hello_done
	{sslError, NO_CHANGE}, // certificate_verify
	{sslError, NO_CHANGE}, // client_key_exchange
	{sslError, NO_CHANGE}, // finished
	{sslError, NO_CHANGE}, // change_cipher_spec
},
{ /* SSL_HELLO_DONE_RECVD */
	{sslError, NO_CHANGE}, // hello_req
	{sslError, NO_CHANGE}, // client_hello
	{recvServerHelloAgain, SSL_CLEANUP}, // server_hello
	{sslError, NO_CHANGE}, // certificate
	{sslError, NO_CHANGE}, // server_key_exchange
	{sslError, NO_CHANGE}, // certificate_req
	{sslError, NO_CHANGE}, // server_hello_done
	{sslError, NO_CHANGE}, // certificate_verify
	{sslError, NO_CHANGE}, // client_key_exchange
	{sslError, NO_CHANGE}, // finished
	{recvChangeCipherSpec, SSL_CHANGE_CIPHER_SPEC_RECVD}, // change_cipher_spec
},
{ /* SSL_CHANGE_CIPHER_SPEC_RECVD */
	{sslError, NO_CHANGE}, // hello_req
	{sslError, NO_CHANGE}, // client_hello
	{sslError, NO_CHANGE}, // server_hello
	{sslError, NO_CHANGE}, // certificate
	{sslError, NO_CHANGE}, // server_key_exchange
	{sslError, NO_CHANGE}, // certificate_req
	{sslError, NO_CHANGE}, // server_hello_done
	{sslError, NO_CHANGE}, // certificate_verify
	{sslError, NO_CHANGE}, // client_key_exchange
	{sslError, NO_CHANGE}, // finished
	{sslError, NO_CHANGE}, // change_cipher_spec
},
{ /* SSL_FINISHED_RECVD */
	{sslError, NO_CHANGE}, // hello_req
	{sslError, NO_CHANGE}, // client_hello
	{sslError, NO_CHANGE}, // server_hello
	{sslError, NO_CHANGE}, // certificate
	{sslError, NO_CHANGE}, // server_key_exchange
	{sslError, NO_CHANGE}, // certificate_req
	{sslError, NO_CHANGE}, // server_hello_done
	{sslError, NO_CHANGE}, // certificate_verify
	{sslError, NO_CHANGE}, // client_key_exchange
	{sslError, NO_CHANGE}, // finished
	{sslError, NO_CHANGE}, // change_cipher_spec
},
{ /* SSL_CLEANUP */
	{sslError, NO_CHANGE}, // hello_req
	{sslError, NO_CHANGE}, // client_hello
	{sslError, NO_CHANGE}, // server_hello
	{sslError, NO_CHANGE}, // certificate
	{sslError, NO_CHANGE}, // server_key_exchange
	{sslError, NO_CHANGE}, // certificate_req
	{sslError, NO_CHANGE}, // server_hello_done
	{sslError, NO_CHANGE}, // certificate_verify
	{sslError, NO_CHANGE}, // client_key_exchange
	{sslError, NO_CHANGE}, // finished
	{sslError, NO_CHANGE}, // change_cipher_spec
}
};

char* msgToString(int msg) {
	switch (msg) {
    case hello_request: return "hello_req";
	case client_hello: return "client_hello";
	case server_hello: return "server_hello";
	case certificate: return "certificate";
	case server_key_exchange: return "server_key_xchange";
	case certificate_request: return "certificate_req";
	case server_hello_done: return "server_hello_done";
	case certificate_verify: return "server_verify";
	case client_key_exchange: return "client_key_xchange";
	case finished: return "finished";
	}
}

/*
 * Check for:
 *  - cert identity matching domain name
 *  - cert is within validity perios
 *  - digital sig is valid
 * Notes:
 * The default certificate format for openssl is PEM, which is base64
 * encoded DER with header/footer lines.
 * Certs in SSL protocol travel on the wire using DER encoding of ASN.1.
 * Refer to RFC 5280 for X.509 PKI Cert and CRL Profile
 * d2i (Der to Internal) APIs are used to convert certs on wire into internal
 * storage format for certs.
 */
verifyCertificate(sslStruct *sslC) {
	uchar *buff, *subj, *issuer;
	int version;
	const uchar *ptr, *tmpPtr;
	const uchar *data;
	size_t len, msgLen, totalCertLen, serverCertLen;
	size_t parsedLen = 0;
	size_t verifyCertLen;
	int count = 0;

#define CERT_LEN_INDEX 1
	// buff[0] points to Handshake Type - certificate
	buff = cfg.sslC->buff;
	len = cfg.sslC->buffLen; // Length of Certificate Packet
	msgLen = GET_BE16(&buff[CERT_LEN_INDEX+1]); // len - 4

	// From here is the payload. Starts from Cert Len (includes all Certs)
	totalCertLen = GET_BE16(&buff[CERT_LEN_INDEX+1+3]);
	// Now is the 1st Certificate - i.e. Server Cert
	serverCertLen = GET_BE16(&buff[CERT_LEN_INDEX+1+3+3]);
	printf(" Pkg Len = %d, Total Cert Len = %d\n", msgLen, totalCertLen);
    printf(" Server Certificate verification, Len: %d\n", serverCertLen);

	// Parse the Server Cert
	ptr = &buff[10];
	X509 *cert = d2i_X509(NULL, &ptr, serverCertLen);	
	if (cert == NULL) {
		printf("\n d2i_X509 returns NULL for Cert verification");
		return -1;
	}
	printf(".........Server Certificate........................\n");
	subj = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
	issuer = X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0);
	version = ((int)X509_get_version(cert)) + 1; // 0 indexed
	printf("Subject: %s, \nIssuer: %s, \n Version: %d", 
		subj, issuer, version);
	// Get Public Key Algorith Name
	int pkey = OBJ_obj2nid(cert->cert_info->key->algor->algorithm);
	if (pkey == NID_undef) {
		printf ("\n Cert Verify: unable to find signature algo");
		goto clean;
	}
	char sigalgo[100];
	const char * sslbuf = OBJ_nid2ln(pkey);
	if (strlen(sslbuf) > 100) {
		printf ("\n Cert Verify: len is greater than allocated");
		goto clean;
	}
	strncpy(sigalgo, sslbuf, 100);
	printf(", Public Key Algorithm Algorithm: %s", sigalgo);
	EVP_PKEY *public_key = X509_get_pubkey(cert);
	if (pkey == NID_rsaEncryption) {
		if (public_key == NULL) {
			printf("\nUnable to get public key from certificate");
			return -1;
		}
		char *rsa_e_dec, *rsa_n_hex;
		sslC->rsa_key = public_key->pkey.rsa;
		// Both the following are printable strings and need to be freed 
		// by caling OPENSSL_free()
		rsa_e_dec = BN_bn2dec(sslC->rsa_key->e); // RSA Exponent
		rsa_n_hex = BN_bn2hex(sslC->rsa_key->n); // RSA Modulus
		//printf("\n RSA Exponent = %s, \n RSA Modulus = %s", rsa_e_dec, rsa_n_hex);
	}
	EVP_PKEY_free(public_key);
clean:
	OPENSSL_free(subj); 
	OPENSSL_free(issuer); 

	// Parse the Server Cert Chain
	ptr = &buff[10+serverCertLen]; // Set ptr to point to next Cert Len field
	parsedLen = serverCertLen+3;
	tmpPtr = ptr+3;
	while (parsedLen < totalCertLen) {
		printf("\n.........Server Certificate Chain %d.............", count++);
		//printf("\n Len: Parsed: %d, Total: %d", parsedLen, totalCertLen);
		verifyCertLen = GET_BE16(&ptr[1]);
		printf("\nCert Chain Len: %d", verifyCertLen);
		X509 *cert = d2i_X509(NULL, &tmpPtr, serverCertLen);	
		if (cert == NULL) {
			printf("\n d2i_X509 returns NULL for Cert verification chain");
			return -1;
		}
		subj = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
		printf("\nSubject: %s", subj);
		OPENSSL_free(subj); 
		ptr += verifyCertLen + 3; // Set ptr to point to next Cert Len field
		tmpPtr = ptr+3;
		parsedLen += verifyCertLen+3;
	} // End parsing Cert Chain
	printf("\n..................................................\n");
}

recvServerHelloAgain (sslStruct *sslC, uchar *p_buff, int event) {
	printf("Server Hello Recvd after Server Hello Done - Error");
}

recvServerHello (sslStruct *sslC, uchar *p_buff, int event) {
	int i;
	
	// Get the packet bytes and save to handshakeMsgs
	// buff[0] points to Handshake Type - ServerHello
	memcpy(&(sslC->clientHandshakeMsgs[sslC->clientHandshakeMsgsIndex]), 
		&(sslC->buff[0]), sslC->buffLen);
	sslC->clientHandshakeMsgsIndex += sslC->buffLen;
	printf("ServerHello saved bytes: %d\n", sslC->buffLen);

	// Get the random value from the packet for master secret
	// buff[0] points to Handshake Type - ServerHello
	// random bytes start from index 6 (including time stamp)
	memcpy(&(sslC->serverRandom[0]), &(sslC->buff[6]), 32);
	/* printf("Server Random recvd: ");
	for(i = 0; i <32; i++)
		printf("%02x ", sslC->serverRandom[i]);
	printf("\n");
	*/
}

recvCertificate (sslStruct *sslC, uchar *p_buff, int event) {
	int status;
	
	// Get the packet bytes and save to handshakeMsgs
	// buff[0] points to Handshake Type - ServerHello
	memcpy(&(sslC->clientHandshakeMsgs[sslC->clientHandshakeMsgsIndex]), 
		&(sslC->buff[0]), sslC->buffLen);
	sslC->clientHandshakeMsgsIndex += sslC->buffLen;
	printf("Certificate saved bytes: %d\n", sslC->buffLen);

	status = verifyCertificate(sslC);
	if (status == -1) {
		printf("\n Certificate verification failed");
		return -1;
	}
	return 0;
}

recvChangeCipherSpec (sslStruct *sslC, uchar *p_buff, int event) {
	printf("\n Change Cipher Spec recvd. ");
	return 0;
}

sslError (sslStruct *sslC, uchar *p_buff, int event) {
	printf("\n SSL FSM: Current State: %d, Event: %d", sslC->state, event);
	return 0;
}

/*********** Enqueue/Dequeue routines ***********/
#define Q_MAX 10
fsmEvent_t* queue[Q_MAX];
int freeSlot = 0;
int readSlot = 0;

queueInit() {
	readSlot = freeSlot;
}

enqueue(fsmEvent_t *event) {
	if (freeSlot == Q_MAX) {
		printf ("\n Queue Wrap !!");
		freeSlot = 0;
		if(queue[freeSlot] != NULL) {
			printf("\n We have a problem. Increase Q size");
			exit(1);
		}
	}
	queue[freeSlot] = event;
	printf("Enqueue: slot %d:%x...\n", freeSlot,event);
	freeSlot++;
}

fsmEvent_t* dequeue() {
	fsmEvent_t* ptr;

	if(queue[readSlot] == NULL)
		return NULL;
	printf("Dequeue: slot %d:%x......\n",
		readSlot,queue[readSlot]);
	ptr = queue[readSlot];
	queue[readSlot] = NULL;
	readSlot++;
	return ptr;
}
/*********** Enqueue/Dequeue routines ***********/
fsmFunction() {
	fsmEvent_t *fsmEvent;
	sslStruct *sslC;
	uchar *p_buff;
	int p_buffLen;

	int event;
	while(1) {
		fsmEvent = dequeue();
		if(fsmEvent == NULL) {
			continue;
		}
		p_buff = fsmEvent->p_buff;
		p_buffLen = fsmEvent->p_buffLen;
		event = fsmEvent->event;
		// Since for a specific sslC client, the FSM is not re-entrant, 
		// i.e. a client finished executing a packet entirely, before
		// moving to the next packet, it is safe at this point to point
		// sslC->buff to p_buff;
		sslC = fsmEvent->sslC;
		sslC->buff = p_buff;
		sslC->buffLen = p_buffLen;

		if (event == NULL_EVENT) return;
		sslFsm[sslC->state][event].funcPtr(sslC, p_buff, event);
		if (sslFsm[sslC->state][event].nextState != NO_CHANGE)
			sslC->state = sslFsm[sslC->state][event].nextState;
		free(fsmEvent->p_buff);
		free(fsmEvent);
	} // end while()
}


fsmExecute(sslStruct *sslC, uchar *p_buff, int p_buffLen, int event) {
	fsmEvent_t *fsmEvent;

	fsmEvent = malloc(sizeof(fsmEvent_t));
	fsmEvent->p_buff = p_buff;
	fsmEvent->p_buffLen = p_buffLen;
	fsmEvent->event = event;
	fsmEvent->sslC = sslC;

	/* Comment out the "return" & "enqueue" for synchronous fsm execution */
	enqueue(fsmEvent);
	return;
/*
	if (event == NULL_EVENT) return;
	sslFsm[sslC->state][event].funcPtr(sslC, p_buff, event);
	if (sslFsm[sslC->state][event].nextState != NO_CHANGE)
		sslC->state = sslFsm[sslC->state][event].nextState;
	free(p_buff);
*/
}

static void signal_handler(int sig) {
	int i;
        if (sig == SIGINT) {
            printf("Caught signal for Ctrl+C\n");
            exit(1);
        }
        if (sig == SIGTSTP) { // CTRL-z
        printf("\n...................SSL Info........................\n");
		printf("\n Current State: %d, ", cfg.sslC->state);
        printf("Version Req = %d, %d\n", cfg.sslC->versionResp[0],
                                        cfg.sslC->versionResp[1]);
        printf("  cfg.sslC->sessionID: Len: %d, Value: ", cfg.sslC->sessionIDLen);
        for (i=0;i<cfg.sslC->sessionIDLen;i++)
                printf("%hhx ", cfg.sslC->sessionID[i]);
        printf("\n  Handshake Responses: ");
        for (i=0;i<32;i++) {
                if (cfg.sslC->handshakeResp & (1<<i)) {
                        printf("%s ", msgToString(i));
                        fflush(stdout);

                }
        }
        }
        printf("\n...................................................\n");

}

initSignals() {
	sigact.sa_handler = signal_handler;
	sigemptyset(&sigact.sa_mask);
	sigact.sa_flags = 0;
	sigaction(SIGINT, &sigact, (struct sigaction*) NULL); //Ctrl+C
	sigaction(SIGTSTP, &sigact, (struct sigaction*) NULL); //Ctrl+z
}

getSelfIP() {
	int fd;
	struct ifreq ifr;
	
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, cfg.interface, IFNAMSIZ-1);
	ioctl(fd, SIOCGIFADDR, &ifr);
	close(fd);
	strcpy(cfg.selfIP, 
                inet_ntoa(((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr));
	printf("\nSelf IP Address: %s", cfg.selfIP);
	if (strcmp(cfg.selfIP, "0.0.0.0") == 0) {
		printf("\n No Self IP Address Found");
		exit(1);
	}
}

/*
 * For now, return NULL for those events that are not supported in the FSM
 */
int getEvent(int handshakeType) {
		switch(handshakeType) {
        case hello_request:
                printf(": Hello Request\n");
				return NULL_EVENT;
        case client_hello:
                printf(": Client Hello \n");
				return NULL_EVENT;
        case server_hello:
                printf(":  Server Hello\n");
				return SERVER_HELLO;
        case certificate:
                printf(": Certificate\n");
				return CERTIFICATE;
        case server_key_exchange:
                printf(": Server Key Exchange\n");
				return NULL_EVENT;
        case certificate_request:
                printf(": Certificate Request\n");
				return NULL_EVENT;
        case server_hello_done:
                printf(":  Server Hello Done\n");
				return SERVER_HELLO_DONE;
        case certificate_verify:
                printf(": Certificate Verify\n"); break;
				return NULL_EVENT;
        case client_key_exchange:
                printf(": Client Key Exchange\n"); break;
				return NULL_EVENT;
        case finished:
                printf(": Finished\n");
				return NULL_EVENT;
		default:
                printf(": Unknown\n");
				return NULL_EVENT;
	}
}

int getProtocol(protocol) {
	switch(protocol) {
	case change_cipher_spec:
		printf("	<- SSL: Change Cipher, "); break;
	case alert:
		printf("	<- SSL: Alert, "); break;
	case handshake:
		printf("	<- SSL: Handshake, "); break;
	case application_data:
		printf("	<- SSL: App data, "); break;
	default:
		printf("	<- SSL: Error pkt recvd: %d, ", protocol);
		return -1;
	}
	return 0;
}


/*
 * This is the start of the recvThread. Runs parallel to the main thread
 * Never returns
 *
 * Stays in a select loop
 *   Receives packets from network
 *   Copies the packet from the stack into the sslC's buffer. This way we 
 *   Can have multiple clients being instantiated, with the same recvFucntion
 *   Invokes the sslFSM[state][event]
 *   FSM is invoked in the same thread and context as the recvFunction().
 *   Will change this later to be invoked via another thread, so that we can
 *   have multiple sslC clients work together.
 */
recvFunction() {
	uchar buff[SSL_MAX_SIZE];  // uchar is important
	int recvd, bytes_recv, index;
	int protocol;
	int remBytes = 0;
	ushort RecordHdrLengthRecvd = 0;
	uchar *p_buff;
	int p_buffLen;

	/* Notes on SSL Length
 	 * 1st Byte      2nd Byte    3rd Byte 
 	 * # S Length    Length      Padding Length
 	 * # - number of bytes in header. 0 indicates 3 byte hdr. 1 a 2 byte header
 	 * S - security escape, not implemented 
 	 * Example: For "Certificate" pkt sent by Server:
 	 * Outer Hdr Len: 12 91
 	 * Inner Hdr Len: 00 12 8d
 	 */

	while(1) {
		bytes_recv = recv(cfg.sock,&buff[0], 5, MSG_PEEK);
		printf("\n bytes_recv = %d, ", bytes_recv);
        if (bytes_recv == -1) { perror("-1: Error during recv: "); exit(1); }
        if (bytes_recv == 0) { 
			perror("0: Socket close in recv: "); 
			// Server has closed the connection, but keep process running
			// to get stats etc.
			sleep(100); exit(1);
		}

		protocol = getProtocol(buff[0]);
		if (protocol == -1) {
			// We have some junk data. Throw it away
			recvd = recv(cfg.sock,&buff[0],SSL_MAX_SIZE, 0);
			printf("..discarding %d len data\n", recvd); continue;
		}

        printf(" Ver: %d.%d : ", buff[1], buff[2]);
        cfg.sslC->versionResp[0] = buff[1];
        cfg.sslC->versionResp[1] = buff[2];
		buff[3] = buff[3] & 0x7F; // clears the MSB # flag in MSByte
        RecordHdrLengthRecvd = GET_BE16(&buff[3]);
        //printf("  Record Hdr Length: %d", RecordHdrLengthRecvd);
		recvd = recv(cfg.sock,&buff[0],
				RecordHdrLengthRecvd+RECORD_HDR_LEN, MSG_WAITALL);
        //printf("  recvd %d\n", recvd);
		index = RECORD_HDR_LEN;

		// Process the packet via FSM. FSM is processed via a separate
		// thread. We copy the buffer into p_buff and invoke the FSM.
		// Thus, the client fsm could be invoked multiple times, and 
		// each time a different buffer is passed to it.
		// The FSM should delete the p_buff
		// Change Cipher Spec
		if (protocol == change_cipher_spec) {
			printf("  <- Change Cipher Spec\n");
			fsmExecute(cfg.sslC, NULL, 0, CHANGE_CIPHER_SPEC);
			continue;
		}

		// Alert Messages - TBD

		// Handshake Messages
		p_buff = malloc(RecordHdrLengthRecvd);
		memcpy(p_buff, &buff[index], RecordHdrLengthRecvd);
		p_buffLen = RecordHdrLengthRecvd;
		cfg.sslC->handshakeResp |= (0x01<<buff[index]);
		fsmExecute(cfg.sslC, p_buff, p_buffLen, getEvent(buff[index]));
		continue;
	}
}

sendChangeCipherSpec(sslStruct *sslC) {
	uchar buff[1024];
	uchar *p = &buff[0];
	ushort length = 0;
	struct timeval tv;
	time_t curtime;
	int i;

	// Record Hdr (Type, Version, Length)
	p[0] = change_cipher_spec; //0x14
	// TLS ver 1.2 uses version value 3.3
	p[1] = SSL_VERSION_1;
	p[2] = SSL_VERSION_2;
	PUT_BE16(&p[3], 1); // This pkt is only 1 byte in length
	length = RECORD_HDR_LEN;

	// Note that we have done 5 bytes by now, which should be substracted
	// from the pkt length for the RecordProtocol.
	p[5] = 1; // change ciper spec = 1
	length = length + 1;

	printf("\n-> Send Change Cipher Spec");
	sendData(cfg.sslC, buff, length);
}

encrypt (sslStruct *sslC, char *buff, char *encryptedBuf, int len) {
	int padding = RSA_PKCS1_PADDING;
	int result;

	// The encrypted bufer must be of size RSA_size(rsa_key)
	printf("\nRSA Size = %d", RSA_size(sslC->rsa_key));
	result = RSA_public_encrypt(len, buff, encryptedBuf, 
				sslC->rsa_key, padding);
	return result;

}

void computeMD5(char *str, uchar *digest) {
	MD5_CTX ctx;
	MD5_Init(&ctx);
	MD5_Update(&ctx, str, strlen(str));
	MD5_Final(digest, &ctx);
}
void computeSHA1(char *str, uchar *sha1Hash) {
	SHA1(str, strlen(str), sha1Hash);
}

sendClientFinished (sslStruct *sslC) {
	uchar buff[1024];
	uchar plainText[256];
	uchar verifyData[256];
	uchar *p = &buff[0];
	ushort length = 0;
	struct timeval tv;
	time_t curtime;
	uchar digest[16];
	uchar sha1Hash[20];
	int result;
	int i;

	// Record Hdr (Type, Version, Length)
	p[0] = handshake; //0x16
	// TLS ver 1.2 uses version value 3.3
	// SSL v3 is version 0300
	p[1] = SSL_VERSION_1;
	p[2] = SSL_VERSION_2;
	PUT_BE16(&p[3], 0); // **** fill in this later at this point
	// current length, used by sendData, and also in pkt
	length = RECORD_HDR_LEN;

	// Note that we have done 5 bytes by now, which should be substracted
	// from the pkt length for the RecordProtocol.

	p[5] = finished; // 20
	p[6] = 0;  // 3rd MSByte of the Length, usualy 0
	// length of Handshake pkt following length field = 1 byte
	PUT_BE16(&p[7], 0); // **** fill in this later at this point
	length = length + 4;

	// Calculate Master Secret
	// TLS1.0+
	// Function call - tls1_prf()
	// master_secret = PRF(pre_master_secret, "master secret", 
	// 				ClientHello.random + ServerHello.random)
	// Note: randoms are 32 bytes (include the timestamps)
	// sslC->masterSecret = PRF (sslC->preMasterSecret, "master secret", 
	// sslC->random, sslC->serverRandom)
	
	// SSLv3 : Tested with openssl s_server and master_secret is correctly
	// generated.
	// Function: ssl3_generate_master_secret()
	// File: sslV3MasterSecret.c
	// master_secret = 
	// 	MD5(pre_master_secret + SHA1('A' + pre_master_secret + randbytes)) +
	// 	MD5(pre_master_secret + SHA1('BB' + pre_master_secret + randbytes)) +
	// 	MD5(pre_master_secret + SHA1('CCC' + pre_master_secret + randbytes)) +
	{
		uchar *dest;
		dest = malloc(48);
		if (dest == NULL) { printf("\n Out of memory"); exit(1); }
		ssl3_generate_master_secret(sslC,
			dest, sslC->preMasterSecret, 48);
		printf("\n Master Secret ");
		for(i = 0; i <48; i++)
			printf("%02x ", dest[i]);
		memcpy(sslC->masterSecret, dest, 48);
		free(dest);
	};
	
	// Calculate verify_data for Finished Msg - for SSLv3
	// Sender: client = 0x434C4E54; server = 0x53525652
	// md5_hash[16] = MD5(masterSecret + pad2 + 
	// 			      MD5(handshakeMsgs + Sender + masterSecret + pad1));
	// sha_hash[20] = SHA(masterSecret + pad2 + 
	// 			      SHA(handshakeMsgs + Sender + masterSecret + pad1));
	// m = MD5(sslC->handshakeMsgs)
	{
	uchar *out;
	out = malloc(36);
	sslC->clientHandshakeMsgs[sslC->clientHandshakeMsgsIndex] = '\0';
	MD5_CTX md5_ctx;
	MD5_Init(&md5_ctx);
	MD5_Update(&md5_ctx, sslC->clientHandshakeMsgs, 
			strlen(sslC->clientHandshakeMsgs));
	printf("\n Length of Handshake Msgs sent by Client: %d", 
		sslC->clientHandshakeMsgsIndex);

	SHA_CTX sha1_ctx;
	SHA1_Init(&sha1_ctx);
	SHA1_Update(&sha1_ctx, sslC->clientHandshakeMsgs, 
			strlen(sslC->clientHandshakeMsgs));
	sslGenerateFinishedHash(&md5_ctx, &sha1_ctx, 
					sslC->masterSecret, out);
	memcpy(&p[9], out, 36);

	// TBD: The Finished message in hashed an encrypted. This currently 
	// generates an error on the other side of - bad record MAC.
	// Need to use ssl3_setup_key_block and _generate_key_block routines
	free(out);
	}
	
	length += 36;
	// Finally fill in the lengths of Record and Handshake headers
	PUT_BE16(&p[3], length-RECORD_HDR_LEN);
	PUT_BE16(&p[7], length-RECORD_HDR_LEN-4);
	printf("\n-> Send Client Finished");
	sendData(cfg.sslC, buff, length);
}

int recvServerHelloDone(sslStruct *sslC) {
	// Get the packet bytes and save to handshakeMsgs
	// buff[0] points to Handshake Type - ServerHello
	memcpy(&(sslC->clientHandshakeMsgs[sslC->clientHandshakeMsgsIndex]), 
		&(sslC->buff[0]), sslC->buffLen);
	sslC->clientHandshakeMsgsIndex += sslC->buffLen;
	printf("\n ServerHelloDone saved bytes: %d", sslC->buffLen);
}

sendClientKeyExchange (sslStruct *sslC, uchar *p_buff, int event) {
	uchar buff[1024];
	uchar plainText[256];
	uchar encryptedBuf[256];
	uchar *p = &buff[0];
	ushort length = 0;
	struct timeval tv;
	time_t curtime;
	int status, result;
	int i;

	// First parse ServerHelloDone
	status = recvServerHelloDone(sslC);

	// Construct Client Key Exchange
	// Record Hdr (Type, Version, Length)
	p[0] = handshake; //0x16
	// TLS ver 1.2 uses version value 3.3
	// SSL v3 is version 0300
	p[1] = SSL_VERSION_1;
	p[2] = SSL_VERSION_2;
	PUT_BE16(&p[3], 0); // **** fill in this later at this point
	// current length, used by sendData, and also in pkt
	length = RECORD_HDR_LEN;

	// Note that we have done 5 bytes by now, which should be substracted
	// from the pkt length for the RecordProtocol.

	p[5] = client_key_exchange; // 16
	p[6] = 0;  // 3rd MSByte of the Length, usualy 0
	// length of Handshake pkt following length field = 1 byte
	PUT_BE16(&p[7], 0); // **** fill in this later at this point
	length = length + 4;

	// pre-master secret encrypted with Server's public key
	// Total Len = 48 bytes (2 byte version, 46 byte key)
	// Fil in the 2 Byte Version first
	plainText[0] = SSL_VERSION_1; 
	plainText[1] = SSL_VERSION_2;
	// Now fill in the secret key of 46 Bytes
	// Also save in sslC struct to create master secret
	strcpy(&plainText[2], "aseem sethi's private key01234567890123456789");
	memcpy(&(sslC->preMasterSecret[0]), &plainText[0], 48);
	result = encrypt(sslC, &plainText[0], &encryptedBuf[0], 48);
	printf("\n Encrypted Len = %d", result); // 256 Bytes
	memcpy(&p[9], &encryptedBuf[0], result);
	length = length + result;

	printf("\n Pre Master Secret: ");
	for(i = 0; i <48; i++)
		printf("%02x ", sslC->preMasterSecret[i]);

	// Finally fill in the lengths of Record and Handshake headers
	PUT_BE16(&p[3], length-RECORD_HDR_LEN);
	PUT_BE16(&p[7], length-RECORD_HDR_LEN-4);
	// Save Client Msgs for making the Finished Msg
	memcpy(&(sslC->clientHandshakeMsgs[sslC->clientHandshakeMsgsIndex]), 
		&(p[5]), length-RECORD_HDR_LEN);
	sslC->clientHandshakeMsgsIndex = 
		sslC->clientHandshakeMsgsIndex + length-RECORD_HDR_LEN;
	printf("\n-> Send Client Key Exchange");
	sendData(cfg.sslC, buff, length);

	sendChangeCipherSpec(sslC);
	sendClientFinished(sslC);
}


sendHello(sslStruct *sslC) {
	uchar buff[100];
	uchar *p = &buff[0];
	ushort length = 0;
	struct timeval tv;
	time_t curtime;
	int i;

	gettimeofday(&tv, NULL);
	curtime=tv.tv_sec;

	// Record Hdr (Type, Version, Length)
	p[0] = handshake; //0x16
	// TLS ver 1.2 uses version value 3.3, TLS 1.0 is 3.1
	// SSL 3.0 is 0x0300
	p[1] = SSL_VERSION_1;
	p[2] = SSL_VERSION_2;
	PUT_BE16(&p[3], 0); // **** fill in this later at this point
	// current length, used by sendData, and also in pkt
	length = RECORD_HDR_LEN;

	// Note that we have done 5 bytes by now, which should be substracted
	// from the pkt length for the RecordProtocol.

	p[5] = 0x1; //clientHello
	p[6] = 0;  // 3rd MSByte of the Length is 0
	// length of Handshake pkt following length field = 1 byte
	PUT_BE16(&p[7], 0); // **** fill in this later at this point
	length = length + 4;

	// This is the 2nd version field in the Record Layer - indicates the 
	// lowest version. But, not used in practice. Implementations mostly
	// use same version
	// TLS ver 1.2 uses version value 3.3
	p[9] = SSL_VERSION_1;
	p[10] = SSL_VERSION_2;
	length = length + 2;

	// Client Random Structure
	PUT_BE32(&p[11], curtime);
	length = length + 4;
	for (i=1; i<=28; i++)
			p[14+i] = 0;
	length += 28;

	// Save the random value into sslC. Used later in the Finished msg
	memcpy(&(sslC->random[0]), &p[11], 32);
	p[43] = 0; // sessionID
	length++;

	// Format for cipher suites - TLS_Kx_[Au]_WITH_Enc_MAC
	// Kx - Key, Au - Authentication, Enc - Symmetric Encryption
	// Au = Kx if not specified
	// thesprawl.org/research/tls-and-ssl-cipher-suites
	p[44] = 0; // Length of cypher suite
	p[45] = 2; // Length of cypher suite
	p[46] = TLS_RSA_WITH_RC4_128_SHA_1;
	p[47] = TLS_RSA_WITH_RC4_128_SHA_2;
	length += 4;

	p[48] = 1; //length of compression vector
	p[49] = 0; //compression algorithm
	length += 2;

	// Next are extensions. SSL3.0 does not support extensions and thus
	// no SNI field.

	// Finally fill in the lengths of Record and Handshake headers
	PUT_BE16(&p[3], length-RECORD_HDR_LEN);
	PUT_BE16(&p[7], length-RECORD_HDR_LEN-4);
	// Save Client Msgs for making the Finished Msg
	memcpy(&(sslC->clientHandshakeMsgs[sslC->clientHandshakeMsgsIndex]), 
		&(p[5]), length-RECORD_HDR_LEN);
	sslC->clientHandshakeMsgsIndex 
		= sslC->clientHandshakeMsgsIndex + length-RECORD_HDR_LEN;
	printf("\n-> Send Client Hello");
	sendData(cfg.sslC, buff, length);
}

sslStruct* createClient() {
	cfg.sslC = malloc(sizeof(sslStruct));
	if (cfg.sslC == NULL)
		return NULL;
	cfg.sslC->buff = malloc(SSL_MAX_SIZE);
	if (cfg.sslC->buff == NULL)
		return NULL;
	cfg.sslC->state = SSL_INIT;
	cfg.sslC->srcPort = cfg.startPort++;
	cfg.sslC->handshakeResp = 0; // Bit Wise map of response pkts
	cfg.sslC->clientHandshakeMsgsIndex = 0; // Msgs saved for MD5/SHA1
	// srcIP in sslC struct us not used as of now
	strcpy(cfg.sslC->srcIP, cfg.selfIP);
	memset(cfg.sslC->buff, 0, 1024);
	printf("\n SSL Client created: %x", cfg.sslC);
	return cfg.sslC;
}

sendData(sslStruct *sslC, uchar *ptr, int length) {
        int sent;

        //printf("\n Sending %d Bytes", length);
        sent = sendto(cfg.sock, ptr, length, 0,
                (struct sockaddr*)&cfg.server_addr, sizeof(cfg.server_addr));
        if(sent == -1) {
                perror("send error: ");
        } else {
                printf(" :%d Bytes", sent);
        }
        fflush(stdout);

}

/* 
 * Set up a INET socket and connect to SERVER on SSL_PORT
 * SSL_PORT = 443 for real SSL servers
 */
initConnectionToServer() {
        struct sockaddr_in;

        if((cfg.sock=socket(AF_INET, SOCK_STREAM, 0)) == -1) {
                perror("socket:");
                exit(1);
        }
        cfg.server_addr.sin_family = AF_INET;
        cfg.server_addr.sin_port = htons(cfg.sslPort);
        if(inet_aton(cfg.utIP, &cfg.server_addr.sin_addr) == 0) {
                printf("inet_aton() failed\n");
        }
        if(connect(cfg.sock, (struct sockaddr *)&cfg.server_addr,
                    sizeof(struct sockaddr)) == -1) {
            perror("Connect");
            exit(1);
        }
        printf("\nTCP connection created to %s", cfg.utIP);
}

/* 
 * This is Resource file for all test parameters
 * Initialize start port to 10,000
 * Set SERVER to point to  server that we want to connect to
 * Set INTERFACE to point to our Network Interface
 * Set up a socket and connect to SERVER
 */
initCfg() {
#define INTERFACE "eth0"
#define SERVER "127.0.0.1"
#define SSL_PORT 4433
	cfg.startPort = 10000; // client src port start
	strcpy(cfg.utIP, SERVER);
	strcpy(cfg.interface, INTERFACE);
	cfg.sslPort = SSL_PORT;
	getSelfIP();
	queueInit();
}

/*
 * Start of the ssl client
 * There is a main thread and a receive thread
 * Main:
 *
 * Recv:
 */
main() {
	int status;
	pthread_t recvThread;
	pthread_t fsmThread;
	sslStruct *sslC;

	// For now this is just a function where we set all variables
	// Ultimately this should be read from a resource file
	initCfg();
	// Connect to Unit under Test (UT)
	initConnectionToServer();
	// Ctrl-Z to give stats
	initSignals();

	status = pthread_create(&recvThread, NULL, &recvFunction, (void*)NULL);
	if (status != 0) {
		perror("Start Thread Error:"); return -1;
	}
	status = pthread_create(&fsmThread, NULL, &fsmFunction, (void*)NULL);
	if (status != 0) {
		perror("Start Thread Error:"); return -1;
	}
	fflush(stdout);

	// For now just create 1 Client to test Server
	sslC = createClient();
	if (sslC == NULL)
		return -1;
	sendHello(sslC);
	while(1);
}
