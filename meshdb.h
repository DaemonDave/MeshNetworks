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

#ifndef intel_mdb
#define intel_mdb



#if defined(WIN32) && !defined(_WIN32_WCE)
	#define _CRTDBG_MAP_ALLOC
	#include <crtdbg.h>
#endif

#if defined(WIN32)
#define snprintf _snprintf
#endif

#if defined(WINSOCK2)
	#include <winsock2.h>
	#include <ws2tcpip.h>
#elif defined(WINSOCK1)
	#include <winsock.h>
	#include <wininet.h>
#endif

#ifdef _POSIX
#include <sys/stat.h>
#include <sys/types.h>
#include <limits.h>
#endif


#include "sqlite3.h"
#include <malloc.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdarg.h>

#ifdef WIN32
#include <shlobj.h>
#endif

#include <openssl/rand.h>

#ifndef __ILibParsers__
#include "ILibParsers.h"
#endif

#ifndef __ILibWebClient__
#include "ILibWebClient.h"
#endif

#ifndef __ILibWebServer__
#include "ILibWebServer.h"
#endif


#ifndef __MeshConfig_h__
#include "meshconfig.h"
#endif

//! \struct LocalSubscription for internal data ports subscribed to.
typedef struct LocalSubscription
{
	unsigned long time;
	unsigned short port;
}LocalSubscription_t;
LocalSubscription_t ctrl_SubscriptionChain[8]; // Keeps the list of up to 8 subscribers locally

//! \var ctrl_SubscriptionChainCount is the overall subscription 
// Local event subscription list
int ctrl_SubscriptionChainCount = 0; // Keeps an approximate (equal or above) count of subscribers. Useful for event optimization.

unsigned int mdb_getsynccounter();
unsigned int mdb_addsynccounter();



// Database handling
//! \fn mdb_open start sql and use local version or not.
int   mdb_open( int local );
// shut it down by sending data to db
void  mdb_close();
// stat operations
void  mdb_begin();
// store state
void  mdb_commit();

void  mdb_checkerror();


//! \fn mdb_create start run create commands on the database file
int   mdb_create( char * filename );

// Settings handling
void  mdb_set(char* key, char* value, int length);
void  mdb_set_i(char* key, int value);
int   mdb_get(char* key, char** data);
int   mdb_get_i(char* key);
void  mdb_remove(char* key);
void  mdb_free(char* ptr);

// Block and node handling
unsigned int mdb_getserial(char* nodeid);
void  mdb_setserial(char* nodeid, unsigned int serial);
int   mdb_blockexist(char* blockid);
int   mdb_blockget(char* blockid, char** block);
void  mdb_blockclear(char* blockid);
void  mdb_clearall();
int   mdb_blockset(char* nodeid, int serial, char* node, int nodelen);
void  mdb_sendallpushblocksasync(struct ILibWebServer_Session *sender, unsigned int syncounter, char* skipnode, unsigned int mask);
void  mdb_attempttarget(struct sockaddr *addr);
void  mdb_updatetarget(char* nodeid, struct sockaddr *addr, unsigned char state, unsigned char power);
unsigned char mdb_gettargetstate(struct sockaddr *addr, char* nodeid, unsigned char* power, char* key, unsigned int* serial);
void  mdb_synctargets();
void  mdb_sendalltargetsasync(struct ILibWebServer_Session *sender, unsigned int syncounter, unsigned int mask);
void  mdb_sendasync(struct ILibWebServer_Session *sender, unsigned int syncounter, char* skipnode, unsigned int mask);
void  mdb_setsessionkey(char* nodeid, char* key);
int   mdb_getmetadatablock(char* startnodeid, int maxsize, char** result, char* skipnodeid);
void  mdb_performsync(char* meta, int metalen, char* nodeid, struct sockaddr *addr, char* key, unsigned int nodeidserial);

// Mesh balance handling
void  mdb_refreshbuckets();
void  mdb_changebuckets(char* nodeid, int added);
int   mdb_isbucketfilled(char* nodeid);

// Event log handling
#ifdef _DEBUG
void  mdb_addevent(char* msg, int msglen);
void  mdb_sendevents(struct ILibWebServer_Session *sender);
void  mdb_deleteevents();
void  mdb_sendallblocksdebugasync(struct ILibWebServer_Session *sender);
void  mdb_sendalltargetsdebugasync(struct ILibWebServer_Session *sender);
#endif

#endif

