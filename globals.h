//! \file globals.h for a common location for g_ globals - a one stop shop

//! \note DRE 2022 

#ifndef MeshGlobals_h
#define MeshGlobals_h

#include <stddef.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h> /* superset of previous */
       
//! \ designed to work with Open SSL 1.0 to start and forever?
//! \note local only openssl include in this directory so the crypto is internal.

///global defines

#define UTIL_HASHSIZE     32
#define MAX_TOKEN_SIZE    1024
#define SMALL_TOKEN_SIZE  256
#define NONCE_SIZE        32
#define HALF_NONCE_SIZE   16 

// Agent identifiers, this is the type of agent executable, used for self-update
enum AgentIdentifiers
{
	AGENTID_UNKNOWN				= 0, // Self-update not supported
	AGENTID_WIN32_CONSOLE		= 1, // Windows x86 console app
	AGENTID_WIN64_CONSOLE		= 2, // Windows x86-64 console app
	AGENTID_WIN32_SERVICE		= 3, // Windows x86 service
	AGENTID_WIN64_SERVICE		= 4, // Windows x86-64 service
};

//! \note - I had to make a common file for all the redundant and confused outer and inner data object references festooned around this garbage.
/// 
// Debugging features
// for debugging...
extern char spareDebugMemory[4000];
extern int  spareDebugLen;
extern char* g_signedblock;
extern int g_signedblocklen;
extern char* g_signedblockhash;
extern unsigned int g_signedblocksynccounter;
// moved from meshconfig
extern char NullNodeId[];
extern char g_selfid_mcast[];
extern char g_selfid[];
extern unsigned int g_serial;
extern unsigned int g_SessionRandomId;
extern unsigned int g_nextiv;
extern char g_SessionRandom[32];
extern int g_PerformingSelfUpdate;
extern int g_outstanding_outbound_requests;
extern int g_PerformingSelfUpdate;
extern int g_outstanding_outbound_requests;
// moved from meshconfig
extern char NullNodeId[];
extern  unsigned char g_distancebuckets[];
//! \var Chain is th 
extern void *Chain;
extern char g_SessionNonce[];
extern char g_SelfExeHash[];
extern char *g_SelfExe;
extern char *g_UpdateExe;
extern char *g_SelfExeMem;
extern int   g_outstanding_outbound_requests;
extern int   g_IPv6Support;
extern unsigned int g_SessionRandomId;
extern unsigned int g_nextiv;
extern char g_SessionRandom[];
extern unsigned short g_agentid;
// Local event subscription list
extern struct sockaddr_in ctrl_SubscriptionLoopback;


// Signed information block
typedef struct NodeInfoBlock
{
	int headersize;
	char* rawdata;									// Point to a block of memory containing all of the raw data in a single run.
	unsigned int rawdatasize;						// Total size of the raw data
	struct ComputerInformationStruct*	compinfo;	// Computer information struct
	struct LocalInterfaceStruct*		netinfo;	// Local network information struct
	struct MeInformationStruct*			meinfo;		// Intel(R) ME information struct
}NodeInfoBlock_t;
extern NodeInfoBlock_t* g_nodeblock;

//! \struct LocalSubscription for internal data ports subscribed to.
typedef struct LocalSubscription
{
	unsigned long time;
	unsigned short port;
}LocalSubscription_t;
extern LocalSubscription_t ctrl_SubscriptionChain[8]; // Keeps the list of up to 8 subscribers locally

//! \var ctrl_SubscriptionChainCount is the overall subscription 
// Local event subscription list
extern int ctrl_SubscriptionChainCount; // Keeps an approximate (equal or above) count of subscribers. Useful for event optimization.


#endif
