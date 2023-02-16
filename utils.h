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

#ifndef __MeshUtils__
#define __MeshUtils__

#if defined(WIN32) && !defined(_WIN32_WCE)
#define _CRTDBG_MAP_ALLOC
#include <crtdbg.h>
#endif
//! global includes

#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include <zlib.h>

#include <stdlib.h>
#include <time.h>

#if defined(WIN32)
#define snprintf _snprintf
#endif

#ifndef __ILibParsers__
#include "ILibParsers.h"
#endif


#ifndef __MeshConfig_h__
#include "meshconfig.h"
#endif


//! \ designed to work with Open SSL 1.0 to start and forever?
//! \note local only openssl include in this directory so the crypto is internal.

///global defines

#define UTIL_HASHSIZE     32
#define MAX_TOKEN_SIZE    1024
#define SMALL_TOKEN_SIZE  256
#define NONCE_SIZE        32
#define HALF_NONCE_SIZE   16 



// DRE 2022
//! \internal includes

// Debugging features
//#if defined(_DEBUG)
extern  char spareDebugMemory[];
extern  int  spareDebugLen;
// moved from meshctrl 
extern int ctrl_SubscriptionChainCount;
// moved from meshconfig
extern char NullNodeId[];








enum ProtocolBlocks
{
	PB_NODEPUSH		  = 1,	// Used to send the node block to another peer
	PB_NODEPULL		  = 2,	// Used to send a pull block to another peer
	PB_NODENOTIFY	  = 3,	// Used to indicate the node ID to other peers
	PB_NODECHALLENGE  = 4,	// Used to challenge a node identity
	PB_NODECRESPONSE  = 5,  // Used to respond to a node challenge
	PB_TARGETSTATUS   = 6,	// Used to send the peer connection status list
	PB_LOCALEVENT     = 7,	// Used to send local events to subscribers
	PB_AESCRYPTO      = 8,	// Used to send an encrypted block of data
	PB_SESSIONKEY     = 9,	// Used to send a session key to a remote node
	PB_SYNCSTART      = 10,	// Used to send kick off the SYNC request, send the start NodeID.
	PB_SYNCMETADATA   = 11,	// Used to send a sequence of NodeID & serial numbers
	PB_SYNCREQUEST    = 12,	// Used to send a sequence of NodeID's to request.
	PB_NODEID	      = 13, // Used to send the NodeID in the clear. Used for multicast.
	PB_AGENTID	      = 14	// Used to send the AgentID & version to the other node
};
// Agent identifiers, this is the type of agent executable, used for self-update
enum AgentIdentifiers
{
	AGENTID_UNKNOWN				= 0, // Self-update not supported
	AGENTID_WIN32_CONSOLE		= 1, // Windows x86 console app
	AGENTID_WIN64_CONSOLE		= 2, // Windows x86-64 console app
	AGENTID_WIN32_SERVICE		= 3, // Windows x86 service
	AGENTID_WIN64_SERVICE		= 4, // Windows x86-64 service
};


void  util_free(char* ptr);
void  util_tohex(char* data, int len, char* out);
int   util_hexToint(char *hexString, int hexStringLength);


// File and data methods
int    util_compress(char* inbuf, unsigned int inbuflen, char** outbuf, unsigned int headersize);
int    util_decompress(char* inbuf, unsigned int inbuflen, char** outbuf, unsigned int headersize);
size_t util_writefile(char* filename, char* data, int datalen);
size_t util_readfile(char* filename, char** data);
int    util_deletefile(char* filename);
#ifdef _POSIX
int util_readfile2(char* filename, char** data);
#endif

//! \fn ctrl_Distance moved from meshctrl.c
int ctrl_Distance(char* nodeid);

void  util_random(int length, char* result);
void  util_randomtext(int length, char* result);
// Local event subscription methods
void info_event_updatetarget(char* nodeid, char* addrptr, int addrlen, unsigned char state, unsigned char power);

#endif

