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

#ifndef __MeshCtrl_h__
#define __MeshCtrl_h__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

//! \note - added OpenSSL headers from system here and removed by replacements.
#include <openssl/ssl.h>
#include <openssl/err.h>

#if defined(WIN32) && !defined(_WIN32_WCE)
#define _CRTDBG_MAP_ALLOC
#include <crtdbg.h>
#endif

#ifdef WINSOCK1
	#include <winsock.h>
#elif WINSOCK2
	#include <winsock2.h>
    #include <ws2tcpip.h>
#endif


#ifndef __MeshInfo_h__
#include "meshinfo.h"
#endif




//! \note - all data enums and defines were moved to the new meshconfig.h header for nonredundants.






int ctrl_MeshInit();
void ctrl_MeshUnInit();

struct util_cert* ctrl_GetCert();
struct util_cert* ctrl_GetTlsCert();
struct util_cert* ctrl_GetTlsClientCert();
char* ctrl_GetSelfNodeId();

// Node information block master methods
unsigned int ctrl_GetSignedBlockSyncCounter();
struct NodeInfoBlock* ctrl_GetCurrentNodeInfoBlock();
int ctrl_GetCurrentSignedNodeInfoBlock(char** block);
struct NodeInfoBlock* ctrl_ParseSignedNodeInfoBlock(unsigned short xsize, char* xblock, char* blockid);
int ctrl_ProcessDataBlock(char* block, int blocklen, char* blockid, char* nodeid, struct sockaddr_in6 *remoteInterface, char* returnkey);
int ctrl_ProcessDataBlocks(char* block, int blocklen, char* blockid, char* nodeid, struct sockaddr_in6 *remoteInterface, char* returnkey);
void ctrl_SyncToNodeUDP(struct sockaddr *addr, char *nodeid, int state, char* key, char* nextsyncblock, unsigned int lastcontact, unsigned int serial);
void ctrl_SyncToNodeTCP(struct sockaddr *addr, char *nodeid, int state, char* key, char* nextsyncblock, unsigned int lastcontact, unsigned int serial);
struct NodeInfoBlock* ctrl_GetNodeInfoBlock(char* nodeid);
int ctrl_Distance(char* nodeid);
void ctrl_AnalyseNewPushBlock(struct NodeInfoBlock* node, int newnode);

// Local subscription chain
void ctrl_AddSubscription(unsigned short port);
void ctrl_SendSubscriptionEvent(char *data, int datalen);
void ctrl_RemoveSubscription(unsigned short port);

// Node identity challenge methods
int ctrl_GetNodeChallenge(char* secret, int counter, char** challenge);
int ctrl_PerformNodeChallenge(struct util_cert cert, char* challenge, int len, char** response);
int ctrl_CheckNodeChallenge(char* secret, char* response, int len, char* nodeid, int* counter);

// Intel AMT state gathering
void ctrl_SyncToIntelAmt(int tls, struct sockaddr *addr, unsigned short port, char* nodeid, char* username, char* password);
void ctrl_SetLocalIntelAmtAdmin(int tls, char* username, char* password);

// Node self-updating system
void ctrl_PerformSelfUpdate(char* selfpath, char* exepath);

#endif
