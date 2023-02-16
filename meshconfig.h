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

//! \note DRE 2022

/**
 * DRE notes:
 *
 * Unsure what the version of OpenSSL that this meshnetworks source uses.
 *
 * Tried OpenSSL 1.1.0
 * Tried OpenSSL 3.0
 * Tried OpenSSL SSLeay
 *
 * And there was no immediate match across the board.
 *
 * Rather than the arduous attempt I was making at converting over all the OpenSSL functionality, I will port into this mesh-werk the needed
 * OpenSSL functions from the original source.  That makes this a contained source code with the specific encrypted / decrypted functions needed herein.
 *
 * This is a reuse cannibalize in reverse: it takes outside source into the code base to complete it without altering the internal function.
 *
 * This makes the amount of code that needs to be searched and understood down to a minimum.
 *
 * I changed my mind overnight: I am going to comment out for now and the reason is below:
 *
 * NOTE: I have commented out the cipher / decipher
 * 	                              certify / decertify
 *                                encrypt / decrypt functions in order to get the mesh working without encryption.
 *
 * At a later date, I will reintroduce encryption from the better OpenSSL examples.
 *
 *
 * The meshnetwork pulled out a couple of certification, decertification, cipher and decipher, encrypt and decrypt methods when OpenSSL comes ready to do all at once for any kind of traffic.
 *
 * The s_client.c demos really show how to make one client work on many which could be useful.
 *
 * I think rather than trying to find the right source code to get a partial cipher system working it would be better
 * to invest some time later on within the OpenSSL versions I have to make the mesh work with many encryption types so that the
 * system can use any kind of traffic.
 *
 * For now, the goal is open in the clear mesh communication for many servers / clients as mesh members.
 *
 * Later improvement or other improvement is secured comms.
 *
 * The network is one level of latency.
 *
 * Secured comms is another level of latency.
 *
 * */

/**
 * DRE 2022
 * 
 * This is a de-conflicted version of meshctrl.h that doesn't reference ssl
 * 
 * There's lots one could fix to make this multi-threaded, multi-process, and so on. But that seems out of scope. 
 * Here are the basic divisions of the data and tasks.
 * 
 * meshcntrl.c will handle challenges, certificates etc. on it's own.
 *   meshctrl.c 
 * meshconfig is bound to fcns and data that handles configurations and get / set .
 * 
 * meshconfig - handles get  / set operations for the main mesh struct operations, finite state machine, and core functionality.
 * 
 * meshcore - renamed to meshcomms to handle all communications so it is the SPOT single point of truth that can handle various communication schemes, \
 * meshcommns - handles all communication from other divisions of labour.
 * \todo change the comms architecture to a ring buffer to compress / combine messages of various types into more efficient comms. This is an entire area of development. 
 * 
 * 
 * util -  to be divided into the other functional divisions listed above so it's not needed. 
 * 
 * meshdb - is the database related functionality only from state updates
 * 
 * meshinfo - handles state outside of core operations
 * 
 *   
 * 
 * Sublibrary but kept internal:
 * 
 * Networking by Intel:
 * 
 * ILibAsyncUDPSocket.c     ILibSSDPClient.c   ILibILibAsyncServerSocket.c  ILibWebClient.c
 * ILibAsyncServerSocket.c  ILibMulticastSocket.c        ILibWebServer.c   
 * ILibAsyncSocket.c        ILibParsers.c   
 * 
 * HLAPI  Hardware API AMT devices by Intel
 *  PTHICommand.c
 * 
 * Host Embedded Controller Interface (HECI)
 * The HECI bus allows the host operating system (OS) to communicate directly with the Management Engine (ME) integrated in the chipset. 
 * 
 * HECILinux.c   
 * 
 * HECI_Linux - is an Intel based comms protocol for the CPU.
 * Host-Initiated Messages

    Read battery status
    Read thermal data
    Enable/disable wake devices
    Notify devices to change power state (thermal, performance, or power throttling)
    * 
Management Engine-Initiated Messages

    Alert Host to battery event
        Low or Critical battery level
        Switch between A/C (wall socket power) and D/C (battery)
    Alert Host to thermal event (Hot or Critical thermal trip)
    Change Fan Speed
    Detect network wake
    Boot/Shutdown System
    Detected Host Intrusion
    Change boot device
    Report system inventory
 *
 * This seems like a good interface to keep for a variety of embedded systems and small UxV.
 * 
 * \todo Make this a common function for hardware platforms. Has to be pulled into a separate library.  
 * t_mesh.c -  for testing mesh configurations.
 * unittest.c - for sub unit testing for all the divisions. 
 *     
 * sslecho.c - as the main() file for transition to new paradigms as new_sslecho.c
 * 
 * 
 * 
 * */
#ifndef __MeshConfig_h__
#define __MeshConfig_h__


#define _POSIX

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
/// DRE 2022 - added global header to remove other file dependencies
#include <sys/ioctl.h>
#include <net/if.h>
#include <sys/socket.h>
#include <netinet/in.h>
/// DRE 2022

#if defined(WIN32) && !defined(_WIN32_WCE)
#define _CRTDBG_MAP_ALLOC
#include <crtdbg.h>
#endif




#include "sqlite3.h"
#include <malloc.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdarg.h>

#ifdef WINSOCK1
	#include <winsock.h>
#elif WINSOCK2
	#include <winsock2.h>
    #include <ws2tcpip.h>
#endif



// DRE 2022
#include <sys/ioctl.h>
#include <net/if.h>
// DRE 2022

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined(WIN32) && !defined(_WIN32_WCE)
#define _CRTDBG_MAP_ALLOC
#include <crtdbg.h>
#endif

#if defined(WINSOCK2)
    #ifndef WIN32_LEAN_AND_MEAN
        #define WIN32_LEAN_AND_MEAN
    #endif
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <iphlpapi.h>
#elif defined(WINSOCK1)
    #include <winsock.h>
    #include <wininet.h>
#elif defined(_POSIX)
    #include <unistd.h>
    #include <string.h>
    #include <errno.h>

    #include <sys/socket.h>
    #include <sys/types.h>
    #include <net/if.h>

    #include <sys/ioctl.h>
    #include <net/if_arp.h>
    #include <arpa/inet.h>

    #define inaddrr(x) (*(struct in_addr *) &ifr->x[sizeof sa.sin_port])
    #define IFRSIZE   ((int)(size * sizeof (struct ifreq)))
#endif

#ifdef _POSIX
#ifndef __HECI_LINUX_H__
#include "HECILinux.h"
#endif
#endif



#ifndef __PTHI_COMMAND_H__
#include "PTHICommand.h"
#endif

#ifndef __ILibMulticastSocket__
#include "ILibMulticastSocket.h"
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



#ifndef MeshGlobals_h
#include "globals.h"
#endif




//! temporary workaround


#define MESH_AGENT_PORT 16990
#define MESH_AGENT_VERSION 12					// Used for self-update system
#define MESH_MCASTv4_GROUP "239.255.255.250"	// Borrowed from UPnP group
#define MESH_MCASTv6_GROUP "FF02:0:0:0:0:0:0:C" // Borrowed from UPnP group
#define MESH_CYCLETIME 4						// Number of seconds between each mesh timer check.
#define MESH_LOCAL_EVENT_SUBSCRIPTION_TIMEOUT 2	// Number of minutes before a local event subscriber expires.
#define MESH_TLS_FALLBACK_TIMEOUT 50			// Number of seconds after which the agent will switch from UDP to TLS.
#define MESH_MAX_TARGETS_IN_BUCKET 5			// Maximum numbers of targets in a single distance bucket.
#define MESH_MCAST_TIMER_MIN 30					// Minimum number of minutes between multicast
#define MESH_MCAST_TIMER_VAR 30					// Number of minutes randomized above the minimum

// DRE 2022 added from utils.h

	// Display & log
#define MSG(x) printf("%s",x);//mdb_addevent(x, (int)strlen(x));
#define MSG2(t,x) spareDebugLen = snprintf(spareDebugMemory,4000,t,x);printf("%s",spareDebugMemory);//mdb_addevent(spareDebugMemory, spareDebugLen);
#define MSG3(t,x,y) spareDebugLen = snprintf(spareDebugMemory,4000,t,x,y);printf("%s",spareDebugMemory);//mdb_addevent(spareDebugMemory, spareDebugLen);
#define MSG4(t,x,y,z) spareDebugLen = snprintf(spareDebugMemory,4000,t,x,y,z);printf("%s",spareDebugMemory);//mdb_addevent(spareDebugMemory, spareDebugLen);
#define MSG5(t,x,y,z,a) spareDebugLen = snprintf(spareDebugMemory,4000,t,x,y,z,a);printf("%s",spareDebugMemory);//mdb_addevent(spareDebugMemory, spareDebugLen);




// #1 - Computer information structure
struct ComputerInformationStruct
{
	unsigned short structtype;
	unsigned short structsize;
	unsigned short agenttype;
	unsigned short agentbuild;
	unsigned int   agentversion;
	unsigned char  name[64];
	unsigned char  osdesc[64];
	unsigned short agentport;
};

// #2 - Local interface structure
struct LocalInterfaceStruct
{
	unsigned short structtype;
	unsigned short structsize;
	unsigned short index;		// Counts down to zero, zero being the last interface.
	unsigned short iftype;
	unsigned long  address;
	unsigned char  address6[16];
    unsigned long  subnet;
	unsigned long  gateway;
	unsigned char  mac[6];
	unsigned char  gatewaymac[6];
	char           fqdn[64];
};

// #3 - Intel(R) ME information structure
struct MeInformationStruct
{
	unsigned short structtype;
	unsigned short structsize;
	unsigned long  version;
	unsigned char  provisioningstate;
	unsigned char  provisioningmode;
	unsigned char  tlsenabled;
	unsigned char  guestuser[32];
	unsigned char  guestpassword[32];
	unsigned char  hostmac[6];
    unsigned char  dedicatedmac[6];
    unsigned char  platformid[16];
};


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



// Computer information methods
struct ComputerInformationStruct* info_GetComputerInformation();
int info_CheckComputerInformation(struct ComputerInformationStruct* computerinfo, int len);
void info_PrintComputerInformation(struct ComputerInformationStruct* computerinfo);

// Local interface methods
struct LocalInterfaceStruct* info_GetLocalInterfaces();
int info_CheckLocalInterfaces(struct LocalInterfaceStruct* interfaces, int len);
void info_PrintLocalInterfaces(struct LocalInterfaceStruct* interfaces);

// Intel(R) ME information methods
struct MeInformationStruct* info_GetMeInformation();
int info_CheckMeInformation(struct MeInformationStruct* meinfo, int len);
void info_PrintMeInformation(struct MeInformationStruct* meinfo);
int info_ProcessAmtWebPage(char* page, int pagelen, unsigned char* state, char** guid);

// Node information block basic methods
struct NodeInfoBlock* info_CreateInfoBlock(unsigned short* includes, int headersize);
struct NodeInfoBlock* info_ParseInfoBlock(char* rawblock, int rawblocksize, int headersize);
void info_PrintInfoBlock(struct NodeInfoBlock* nodeblock);
void info_FreeInfoBlock(struct NodeInfoBlock* nodeblock);

int   util_hexToint(char *hexString, int hexStringLength);
#ifdef _POSIX
int util_readfile2(char* filename, char** data);
#endif


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


enum mdb_TargetStates
{
	MDB_UNKNOWN			= 0,
	MDB_AGENT			= 1,
	MDB_AMTONLY			= 2,
	MDB_GOTMULTICAST	= 3
};

// Async enumeration mask
enum mdb_AsyncEnums
{
	MDB_SELFNODE		= 0x00000001,
	MDB_PUSHBLOCKS		= 0x00000002,
	MDB_TARGETS			= 0x00000004,
	MDB_SESSIONKEY		= 0x00000008,
	MDB_AGENTID			= 0x00000010
};


enum CERTIFICATE_TYPES
{
	CERTIFICATE_ROOT = 1,
	CERTIFICATE_TLS_SERVER = 2,
	CERTIFICATE_TLS_CLIENT = 3,
};

// Signed information block
struct HttpRequestBlock
{
	// Reference counter
	int refcount;

	// Basic request information
	void *requestmanager;
	void *addr;
	int  requesttype;
	char *nodeid;
	int  tryCount;
	char *ip;
	unsigned short port;

	// HTTP digest data
	char *username;
	char *password;
	char *realm;
	char *nonce;
	char *qop;
	int  nc;

	// File transfer handle
	FILE* pfile;
};
///
// DRE 2022 transfered over from meshcore.c
///
struct MeshDataObject
{
    void *Timer;
    void *HTTPServer;	// TLS server
    void *HTTPClient;	// TLS client
    void *HTTPCClient;	// Clear client
    void *MulticastSocket;
    unsigned int LastMulticastPushSerial;
};



// #6 - Target status information element
struct TargetStatusElement
{
	unsigned char address[64];
	unsigned char nodeid[32];
	unsigned char state;
	unsigned char power;
};

//! \todo improve to combined messages and protocol buffers for efficiency.
// There are 1 byte UDP packets used between a local subscriber and the agent
enum LocalSubscriptionCodes
{
	LOCALEVENT_SUBSCRIBE   = 1, // Application <-> Agent
	LOCALEVENT_UNSUBSCRIBE = 2, // Application <-> Agent
	LOCALEVENT_MULTI_ECHO  = 3, // Agent <-> Application
	LOCALEVENT_AGENT_EXIT  = 4, // Agent --> Application
};

//! \struct util_cert is the meshnetwork struct
// Certificate structure
struct util_cert
{
/*
	X509 *x509;
	EVP_PKEY *pkey;	
*/
};
//! \typedef  RSA_t that encasulates all RSA vars needed or not.
typedef struct RSA_st
{
/*
	unsigned int primes;
	unsigned int bits;
	OSSL_PARAM params[3];
	EVP_PKEY *pkey;
	EVP_PKEY_CTX *pctx;
*/
}RSA_t;

// DRE 2022
//! \internal includes


///
// DRE 2022 transfered over from meshcore.c
///
#define UTIL_HASHSIZE     32




//! \note DRE 2022 these are local changes into configuration only
// extern from inside meshcore.c
//! \struct MeshDataObject Mesh is the key struct for  all mesh activities
struct MeshDataObject Mesh;

///
// DRE 2022 transfered over from meshctrl.c
///



int GetMeshPort();

// imports from utils.c
void  util_startChronometer();
long  util_readChronometer();
unsigned long  util_gettime();
void  util_sha256(char* data, int datalen, char* result);
int   util_sha256file(char* filename, char* result);

int ctrl_MeshInit();
void ctrl_MeshUnInit();

//struct util_cert* ctrl_GetCert();
//struct util_cert* ctrl_GetTlsCert();
//struct util_cert* ctrl_GetTlsClientCert();
char* ctrl_GetSelfNodeId();

// Node information block master methods
unsigned int ctrl_GetSignedBlockSyncCounter();
NodeInfoBlock_t* ctrl_GetCurrentNodeInfoBlock();
int ctrl_GetCurrentSignedNodeInfoBlock(char** block);
// commented out for meshctrl
NodeInfoBlock_t* ctrl_ParseSignedNodeInfoBlock(unsigned short xsize, char* xblock, char* blockid);
int ctrl_ProcessDataBlock(char* block, int blocklen, char* blockid, char* nodeid, struct sockaddr_in6 *remoteInterface, char* returnkey);
int ctrl_ProcessDataBlocks(char* block, int blocklen, char* blockid, char* nodeid, struct sockaddr_in6 *remoteInterface, char* returnkey);
void ctrl_SyncToNodeUDP(struct sockaddr *addr, char *nodeid, int state, char* key, char* nextsyncblock, unsigned int lastcontact, unsigned int serial);
// commented out for meshctrl
//void ctrl_SyncToNodeTCP(struct sockaddr *addr, char *nodeid, int state, char* key, char* nextsyncblock, unsigned int lastcontact, unsigned int serial);
//NodeInfoBlock_t* ctrl_GetNodeInfoBlock(char* nodeid);

void ctrl_AnalyseNewPushBlock(NodeInfoBlock_t* node, int newnode);

// Local subscription chain
void ctrl_AddSubscription(unsigned short port);
void ctrl_SendSubscriptionEvent(char *data, int datalen);
void ctrl_RemoveSubscription(unsigned short port);

// Node identity challenge methods
//int ctrl_GetNodeChallenge(char* secret, int counter, char** challenge);
//int ctrl_PerformNodeChallenge(struct util_cert cert, char* challenge, int len, char** response);
//int ctrl_CheckNodeChallenge(char* secret, char* response, int len, char* nodeid, int* counter);

// Intel AMT state gathering
void ctrl_SyncToIntelAmt(int tls, struct sockaddr *addr, unsigned short port, char* nodeid, char* username, char* password);
void ctrl_SetLocalIntelAmtAdmin(int tls, char* username, char* password);

// Node self-updating system
void ctrl_PerformSelfUpdate(char* selfpath, char* exepath);


void  util_free(char* ptr);
void  util_tohex(char* data, int len, char* out);



// File and data methods
int    util_compress(char* inbuf, unsigned int inbuflen, char** outbuf, unsigned int headersize);
int    util_decompress(char* inbuf, unsigned int inbuflen, char** outbuf, unsigned int headersize);
// Decrypt an incoming block of data
// If this packet is not encrypted correctly or uses an old key, we return zero.
int util_decipher(char* data, int datalen, char** result, char* nodeid);
size_t util_writefile(char* filename, char* data, int datalen);
size_t util_readfile(char* filename, char** data);
int    util_deletefile(char* filename);


//! \fn ctrl_Distance moved from meshctrl.c
int ctrl_Distance(char* nodeid);

void  util_random(int length, char* result);
void  util_randomtext(int length, char* result);
// Local event subscription methods
void info_event_updatetarget(char* nodeid, char* addrptr, int addrlen, unsigned char state, unsigned char power);


#endif
