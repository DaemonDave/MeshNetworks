/*
   Copyright 2009 Intel Corporation

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

#ifndef __MeshCore_h__
#define __MeshCore_h__

#ifdef WINSOCK1
	#include <winsock.h>
#elif WINSOCK2
	#include <winsock2.h>
    #include <ws2tcpip.h>
    #include <iphlpapi.h>
#endif

#include <stdio.h>


#ifndef WIN32
#include <unistd.h>
#endif

#ifndef __UPNP_CONTROLPOINT_STRUCTS__
#include "UPnPControlPointStructs.h"
#endif

#ifndef __ILibParsers__
#include "ILibParsers.h"
#endif

#ifndef __ILibWebClient__
#include "ILibWebClient.h"
#endif

#ifndef __ILibWebServer__
#include "ILibWebServer.h"
#endif

#ifndef ___ILibAsyncSocket___
#include "ILibAsyncSocket.h"
#endif

#ifndef ___ILibAsyncUDPSocket___
#include "ILibAsyncUDPSocket.h"
#endif

#ifndef __ILibMulticastSocket__
#include "ILibMulticastSocket.h"
#endif

#ifndef ___ILibAsyncServerSocket___
#include "ILibAsyncServerSocket.h"
#endif

#ifndef __MeshConfig_h__
#include "meshconfig.h"
#endif


 
//! \fn CreateRSA creates memory and fills it for use elsewhere
RSA_t * CreateRSA();


// Perform a MD5 hash on the data
void util_md5(char* data, int datalen, char* result);




// General methods
void  util_openssl_init();
void  util_openssl_uninit();

// Symetric Crypto methods
void  util_nodesessionkey(char* nodeid, char* key);
int   util_cipher(char* key, char* nodeid, char* data, int datalen, char** result, int sendresponsekey);
int   util_decipher(char* data, int datalen, char** result, char* nodeid);
void  util_genusagekey(char* inkey, char* outkey, char usage);

// Network security methods
int	  util_antiflood(int rate, int interval);
int   util_ExtractWwwAuthenticate(char *wwwAuthenticate, void *request);
void  util_GenerateAuthorizationHeader(void *request, char *requestType, char *uri, char *authorization, char* cnonce);

// Certificate & crypto methods
void  util_freecert(struct util_cert* cert);
int   util_to_p12(struct util_cert cert, char *password, char** data);
int   util_from_p12(char* data, int datalen, char* password, struct util_cert* cert);
int   util_to_cer(struct util_cert cert, char** data);
int   util_from_cer(char* data, int datalen, struct util_cert* cert);
int   util_mkCert(struct util_cert *rootcert, struct util_cert* cert, int bits, int days, char* name, enum CERTIFICATE_TYPES certtype);
void  util_printcert(struct util_cert cert);
void  util_printcert_pk(struct util_cert cert);
void  util_sendcert(struct ILibWebServer_Session *sender, struct util_cert cert);
void  util_md5(char* data, int datalen, char* result);
void  util_md5hex(char* data, int datalen, char *out);

int   util_keyhash(struct util_cert cert, char* result);
int   util_keyhash2(X509* cert, char* result);
int   util_sign(struct util_cert cert, char* data, int datalen, char** signature);
int   util_verify(char* signature, int signlen, struct util_cert* cert, char** data);
int   util_encrypt(struct util_cert cert, char* data, int datalen, char** encdata);
int   util_encrypt2(STACK_OF(X509) *certs, char* data, int datalen, char** encdata);
int   util_decrypt(char* encdata, int encdatalen, struct util_cert cert, char** data);



struct sockaddr;


void StopMesh();
int StartMesh(char* exefile);

void BroadcastUdpPacket(char* data, int datalen, int count);
void UnicastUdpPacket(struct sockaddr* target, char* data, int datalen);
void SendCryptoUdpToTarget(struct sockaddr *addr, char* nodeid, char* key, char* data, int datalen, int sendresponsekey);
void PerformHttpRequest(int tls, struct sockaddr *addr, char *path, struct HttpRequestBlock* user, char* post, int postlen);

#endif
