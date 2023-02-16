//! \file globals.h for a common location for g_ globals - a one stop shop

//! \note DRE 2022 

#ifndef MeshGlobals_h
#include "globals.h"
#endif


//! \ designed to work with Open SSL 1.0 to start and forever?
//! \note local only openssl include in this directory so the crypto is internal.

///global defines


//! \note - I had to make a common file for all the redundant and confused outer and inner data object references festooned around this garbage.
/// 
// Debugging features
//#if defined(_DEBUG)
// for debugging...
char spareDebugMemory[4000];
int  spareDebugLen;
char* g_signedblock= NULL;
int g_signedblocklen = 0;
char* g_signedblockhash = NULL;
unsigned int g_signedblocksynccounter = 0;
// moved from meshconfig
char NullNodeId[];
char g_selfid_mcast[4 + UTIL_HASHSIZE];
char g_selfid[UTIL_HASHSIZE];
unsigned int g_serial;
unsigned int g_SessionRandomId;
unsigned int g_nextiv;
char g_SessionRandom[32];
int g_PerformingSelfUpdate;
int g_outstanding_outbound_requests;
int g_PerformingSelfUpdate = 0;
int g_outstanding_outbound_requests;
// moved from meshconfig
char NullNodeId[32] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
unsigned char g_distancebuckets[32];
//! \var Chain is th 
void *Chain = NULL;
char g_SessionNonce[17];
char g_SelfExeHash[UTIL_HASHSIZE];
char *g_SelfExe = NULL;
char *g_UpdateExe = NULL;
char *g_SelfExeMem = NULL;
int   g_outstanding_outbound_requests = 0;
int   g_IPv6Support;
unsigned int g_SessionRandomId;
unsigned int g_nextiv = 0;
char g_SessionRandom[32];
unsigned short g_agentid = AGENTID_UNKNOWN;
// Local event subscription list
struct sockaddr_in ctrl_SubscriptionLoopback;
NodeInfoBlock_t* g_nodeblock;

LocalSubscription_t ctrl_SubscriptionChain[8]; // Keeps the list of up to 8 subscribers locally

//! \var ctrl_SubscriptionChainCount is the overall subscription 
// Local event subscription list
int ctrl_SubscriptionChainCount = 0; // Keeps an approximate (equal or above) count of subscribers. Useful for event optimization.
