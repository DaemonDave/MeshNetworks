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
/**  \file
 * DRE 2022
 * 
 * This is a de-conflicted version of meshcomms.c that combines networking, crypto, and ssl in one
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

#ifndef __MeshCore_h__
#include "meshcore.h"
#endif

#define INET_SOCKADDR_LENGTH(x) ((x==AF_INET6?sizeof(struct sockaddr_in6):sizeof(struct sockaddr_in)))
#define INET_SOCKADDR_PORT(x) (x->sa_family==AF_INET6?(unsigned short)(((struct sockaddr_in6*)x)->sin6_port):(unsigned short)(((struct sockaddr_in*)x)->sin_port))



extern unsigned char g_distancebuckets[32];
int g_UpdateOnExit = 0;
extern int g_PerformingSelfUpdate;


// Event sink methods definitions
void TimerTriggered(void *data);
void TimerDestroyed(void *data);
void HttpServerSessionSink(struct ILibWebServer_Session *SessionToken, void *user);
void HttpServerSessionReceiveSink(struct ILibWebServer_Session *sender, int InterruptFlag, struct packetheader *header, char *bodyBuffer, int *beginPointer, int endPointer, int done);
void HttpServerSessionDisconnect(struct ILibWebServer_Session *session);

#ifdef WINSOCK2
DWORD UpnpMonitorSocketReserved;
WSAOVERLAPPED UpnpMonitorSocketStateObject;
SOCKET NetworkMonitorSocket;
#endif

// Called with a 5 second lag time when an interface changes
void IPAddressMonitorUpdate(void *data)
{
    // Setup the multicast timer
    //MSG("IPAddressMonitorUpdate.\r\n");

#ifdef WIN32
    // In Windows, just reset the broadcast timer to 5 seconds
    ILibLifeTime_Remove(Mesh.Timer, (void*)2);
    ILibLifeTime_Add(Mesh.Timer, (void*)2, 5, &TimerTriggered, &TimerDestroyed);
#else
    // In Linux, we need to check to see if the push block has changed
    ctrl_GetCurrentSignedNodeInfoBlock(NULL);
    if (Mesh.LastMulticastPushSerial != g_serial)
    {
        Mesh.LastMulticastPushSerial = g_serial;
        ILibLifeTime_Remove(Mesh.Timer, (void*)2);
        ILibLifeTime_Add(Mesh.Timer, (void*)2, 5, &TimerTriggered, &TimerDestroyed);
    }
#endif
}

// Method gets periodically executed on the microstack thread to update the list of known IP addresses.
#ifdef WINSOCK2
void CALLBACK IPAddressMonitor
(
    IN DWORD dwError,
    IN DWORD cbTransferred,
    IN LPWSAOVERLAPPED lpOverlapped,
    IN DWORD dwFlags
)
#else
void IPAddressMonitor(void *data)
#endif
{
#ifdef WINSOCK2
    UNREFERENCED_PARAMETER( dwError );
    UNREFERENCED_PARAMETER( cbTransferred );
    UNREFERENCED_PARAMETER( lpOverlapped );
    UNREFERENCED_PARAMETER( dwFlags );
#endif

    // We are in the process of cleaning up, lets exit now
    if (Mesh.MulticastSocket == NULL) return;

#ifdef WINSOCK2
    // Call the interface update with a lab timer. The short lag allows interfaces to stabilize.
    ILibLifeTime_Remove(Mesh.Timer, &IPAddressMonitorUpdate);
    ILibLifeTime_Add(Mesh.Timer, &IPAddressMonitorUpdate, 6, &IPAddressMonitorUpdate, NULL);
    WSAIoctl(NetworkMonitorSocket, SIO_ADDRESS_LIST_CHANGE, NULL, 0, NULL, 0, &UpnpMonitorSocketReserved, &UpnpMonitorSocketStateObject, &IPAddressMonitor);
#else
    // Call the interface update directly. TODO: This is very innefficient, we need to fix this.
    IPAddressMonitorUpdate(NULL);
    ILibLifeTime_Add(Mesh.Timer, NULL, 20, &IPAddressMonitor, NULL);
#endif
}



// Send an encrypted UDP packet to a target
void SendCryptoUdpToTarget(struct sockaddr *addr, char* nodeid, char* key, char* data, int datalen, int sendresponsekey)
{
    char* cdata = NULL;
    int cdatalen;

    cdatalen = util_cipher(key, nodeid, data, datalen, &cdata, sendresponsekey);
    if (cdata != NULL)
    {
        UnicastUdpPacket(addr, cdata, cdatalen);
        free(cdata);
    }
}

// Called when a UDP packet is received
void UDPSocket_OnData(ILibAsyncUDPSocket_SocketModule socketModule, char* buffer, int bufferLength, struct sockaddr_in6 *remoteInterface, void *user, void *user2, int *PAUSE)
{
    unsigned short ptr = 0;
    char blockid[UTIL_HASHSIZE];

#ifdef _DEBUG
    char str[200];

    if (remoteInterface->sin6_family == AF_INET) ILibInet_ntop(AF_INET, &(((struct sockaddr_in*)remoteInterface)->sin_addr), str, 200);
    if (remoteInterface->sin6_family == AF_INET6) ILibInet_ntop(AF_INET6, &(((struct sockaddr_in6*)remoteInterface)->sin6_addr), str, 200);

    /*
    if (bufferLength > 2)
    {
    	MSG4("Received UDP data, type=%d, len=%d, from=%s\r\n", ((unsigned short*)(buffer))[0], bufferLength, str);
    }
    else
    {
    	MSG3("Received UDP data, len=%d, from=%s\r\n", bufferLength, str);
    }
    */
#endif

    UNREFERENCED_PARAMETER( socketModule );
    UNREFERENCED_PARAMETER( user );
    UNREFERENCED_PARAMETER( user2 );
    UNREFERENCED_PARAMETER( PAUSE );

    // Perform basic checks before processing this packet
    if (remoteInterface->sin6_family != AF_INET && remoteInterface->sin6_family != AF_INET6) return;

    // If this is a event subscription packet, handle it now
    if (ILibIsLoopback((struct sockaddr*)remoteInterface) && bufferLength == 1)
    {
        ptr = remoteInterface->sin6_family == AF_INET ? (((struct sockaddr_in*)remoteInterface)->sin_port) : (((struct sockaddr_in6*)remoteInterface)->sin6_port);
        if (buffer[0] == 1) ctrl_AddSubscription(ptr); // Add or update a local event subscription in the database
        else if (buffer[0] == 2) ctrl_RemoveSubscription(ptr); // Remove subscription
#ifdef _DEBUG
        else if (buffer[0] == 3)
        {
            // Send debug event echo
            char echo = 3;
            ctrl_SendSubscriptionEvent(&echo, 1);
        }
#endif
        return;
    }

    // Apply type filter. We only accept Encrypted AES-128 and NodeID (TODO: If type 13, also check length!)
    if ( !(((unsigned short*)buffer)[0] == 8 || (bufferLength == 36 && ((unsigned short*)buffer)[0] == 13)) ) 
    {
        MSG("UDP BADTYPE\r\n");
        return;
    }

    // Apply anti-flooing filter, stops excessive battery drain & CPU use.
    if (util_antiflood(100, 10) == 0) 
    {
        MSG("UDP ANTIFLOOD ACTIVATED\r\n");    // Maximum of 100 packets each 10 seconds
        return;
    }

    // Update the database with this new information
    memset(blockid, 0, UTIL_HASHSIZE);
    ctrl_ProcessDataBlocks(buffer, bufferLength, blockid, NULL, remoteInterface, NULL);

    // If this node is not known, add it to the rotation.
    if (memcmp(blockid, NullNodeId, UTIL_HASHSIZE) != 0)
    {
        // We add the first NodeID in the received data, this should be our expected NodeID for this target.
        mdb_updatetarget(blockid, (struct sockaddr*)remoteInterface, MDB_GOTMULTICAST, 0);
    }
}

//! \fn StopMesh is the dtor:  Stop the mesh agent, this will cause the blocking mesh thread to cleanup and exit
void StopMesh()
{
    if (Chain == NULL) return;

    // Send exit code, notifies the local event subscribers that the agent is exiting
    {
        char exitcode = 4;
        ctrl_SendSubscriptionEvent(&exitcode, 1);
    }

    ILibStopChain(Chain);
    Chain = NULL;
}

int OnSslConnection(ILibWebClient_StateObject sender, STACK_OF(X509) *certs, struct sockaddr_in6 *remoteInterface, void *user)
{
    UNREFERENCED_PARAMETER( sender );
    UNREFERENCED_PARAMETER( user );

    //MSG("SSL Client Connection.\r\n");

    //char* ILibWebClient_GetCertificateHash(void* socketModule);
    //char* ILibWebClient_GetCertificateHash2(void* socketModule);

    // Get the node certificate and run a SHA256 hash on it.
    if (certs != NULL && sk_X509_num(certs) > 1)
    {
        // Compute the remote node's NodeID and store it in the ILibWebClient
        char* nodeid = ILibWebClient_GetCertificateHashEx(sender);
        if (util_keyhash2(sk_X509_value(certs, 1), nodeid) != 0) return 0;
        ILibWebClient_SetCertificateHash(sender, nodeid);

        // If we are connected to a computer that has our own identity, disconnect now.
        if (memcmp(g_selfid, nodeid, UTIL_HASHSIZE) == 0) return 0;

        // Update the remote node target information.
        mdb_updatetarget(nodeid, (struct sockaddr*)remoteInterface, MDB_AGENT, 1);
    }

    return 1; // Return 1 to accept, 0 to reject connection.
}
/*
static int verify_server_callback(int preverify_ok, X509_STORE_CTX *ctx)
{
    UNREFERENCED_PARAMETER( preverify_ok );
    UNREFERENCED_PARAMETER( ctx );

    // TODO: Check the certificate chain
    return 1;
}

static int verify_client_callback(int preverify_ok, X509_STORE_CTX *ctx)
{
    UNREFERENCED_PARAMETER( preverify_ok );
    UNREFERENCED_PARAMETER( ctx );

    // TODO: Check the certificate chain
    return 1;
}
*/
// Start the mesh agent, this call is blocking and will handle everything (Timer, Http, Udp...)
// This agent is single threaded and the thread calling this method will run everything.
/// \note this is the ctor for mesh action
int StartMesh(char* exefile)
{
    int l, err = 0;
//    SSL_CTX* ctx = NULL;
//    SSL_CTX* ctx2 = NULL;
#ifdef WINSOCK2
    WSADATA wsaData;
#endif
    struct sockaddr_in6 localUdpInterface;
    struct sockaddr_in multicastAddr4;
    struct sockaddr_in6 multicastAddr6;

    UNREFERENCED_PARAMETER( exefile );

    // We are going to be nice and drop the priority of this process
    // Because we want to remain the the background and have as little system impact as possible
#ifdef WIN32
    SetPriorityClass(GetCurrentProcess(), PROCESS_MODE_BACKGROUND_BEGIN);
#else
    nice(2);
#endif

    // Print the agent type & version
    MSG4("Starting Mesh Agent v%d.%d.%d\r\n", (int)(MESH_AGENT_VERSION>>16), (int)((MESH_AGENT_VERSION>>8)&0xFF), (int)((MESH_AGENT_VERSION)&0xFF));

    // Setup Chain. This will also setup Winsock is applicable
    Chain = ILibCreateChain();

    // IPv6 detection
    g_IPv6Support = ILibDetectIPv6Support();

    // Cleanup all addresses
    memset(&localUdpInterface, 0, sizeof(struct sockaddr_in6));
    memset(&multicastAddr4, 0, sizeof(struct sockaddr_in));
    memset(&multicastAddr6, 0, sizeof(struct sockaddr_in6));

    // Setup addresses
    if (g_IPv6Support)
    {
        // IPv6 support
        localUdpInterface.sin6_family = AF_INET6;
        localUdpInterface.sin6_port = htons(MESH_AGENT_PORT);
        multicastAddr6.sin6_family = AF_INET6;
        ILibInet_pton(AF_INET6, MESH_MCASTv6_GROUP, &(multicastAddr6.sin6_addr));
    }
    else
    {
        // IPv4 only
        localUdpInterface.sin6_family = AF_INET;
        ((struct sockaddr_in*)&localUdpInterface)->sin_port = htons(MESH_AGENT_PORT);
    }

    // Setup multicastAddr4
    multicastAddr4.sin_family = AF_INET;
    ILibInet_pton(AF_INET, MESH_MCASTv4_GROUP, &(multicastAddr4.sin_addr));

    // Fetch our own executable name
#ifdef WINSOCK2
    if (exefile != NULL) g_SelfExe = exefile;
    else
    {
        if ((g_SelfExeMem = malloc(4096)) == NULL) 
        {
            PRINTERROR();
            goto exit1;
        }
        l = GetModuleFileNameA(NULL, g_SelfExeMem, 4096);
        if (l != 0) 
        {
            g_SelfExeMem = realloc(g_SelfExeMem, l + 1);
            g_SelfExe = g_SelfExeMem;
        }
        else 
        {
            free(g_SelfExeMem);
            g_SelfExeMem = NULL;
        }
    }
#else
    g_SelfExe = exefile;
#endif

    // Setup the update filename
    if (g_SelfExe != NULL)
    {
        int len = strlen(g_SelfExe) + 1;
        if ((g_UpdateExe = malloc(len)) == NULL) 
        {
            PRINTERROR();
            goto exit1;
        }
        memcpy(g_UpdateExe, g_SelfExe, len);
#ifdef WIN32
        g_UpdateExe[len - 6] = '2';
#else
        g_UpdateExe[len - 2] = '2';
#endif
    }

    // Clean up the updater if present
#ifdef WIN32
    remove(g_UpdateExe);
#else
    remove(g_UpdateExe);
#endif

    // Hash our own executable file
    if (g_SelfExe != NULL) util_sha256file(g_SelfExe, g_SelfExeHash);

    // Setup Winsock
#ifdef WINSOCK2
    WSAStartup(MAKEWORD(1, 1), &wsaData);
#endif

//! \note commented out OpenSSL
    // OpenSSL and Mesh Controller Setup
	//util_openssl_init();
    if (ctrl_MeshInit() != 0) 
    {
        PRINTERROR();
        return 1;
    }

    // Setup random nonce & state
    memset(&Mesh, 0, sizeof(Mesh));
    util_randomtext(16, g_SessionNonce);
    g_SessionNonce[16] = 0;



    // Create TLS client context
//	ctx = SSL_CTX_new(SSLv23_client_method());
//	ctx2 = SSL_CTX_new(SSLv23_server_method());

//
///
//

    // Set the key and cert 
    ///if (SSL_CTX_use_certificate_chain_file(ctx, "cert.pem") <= 0) 
    //{
     //   ERR_print_errors_fp(stderr);
     //   exit(EXIT_FAILURE);
    //}
	//
    ///if (SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM) <= 0) 
    //{
    //    ERR_print_errors_fp(stderr);
    //    exit(EXIT_FAILURE);
    //}


//! \note commented out all secured comms
    // Server side settings
	/// CURRENT FCN       
    /// __owur int SSL_CTX_use_certificate 	( 	SSL_CTX *  	ctx, 	X509 *  	x  	) ;
    //l = SSL_CTX_use_certificate(ctx2, ctrl_GetTlsCert()->x509);
	/// CURRENT FCN        
    /// __owur int SSL_CTX_use_PrivateKey 	( 	SSL_CTX *  	ctx,  EVP_PKEY *  	pkey ) ;
	/// CURRENT FCN    
    //l = SSL_CTX_use_PrivateKey(ctx2, ctrl_GetTlsCert()->pkey);
	/// CURRENT FCN        
    //#define SSL_CTX_add_extra_chain_cert 	( ctx,  	x509  	)	    SSL_CTX_ctrl(ctx,SSL_CTRL_EXTRA_CHAIN_CERT,0,(char *)(x509))
	/// CURRENT FCN      
    //l = SSL_CTX_add_extra_chain_cert(ctx2, X509_dup(ctrl_GetCert()->x509));
	/// CURRENT FCN      
	/// void SSL_CTX_set_verify 	( 	SSL_CTX *  	ctx, int  	mode, int(*)(int, X509_STORE_CTX *)  	cb  ); 	    
    //SSL_CTX_set_verify(ctx2, SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE, verify_server_callback); // Ask for client authentication




 
    // Client side settings

    /// OpenSSL 3.0 client side call 
    ///
    
    // Configure the client to abort the handshake if certificate verification  fails
    /// SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    // In a real application you would probably just use the default system certificate trust store and call:
    ///     SSL_CTX_set_default_verify_paths(ctx);
    // In this demo though we are using a self-signed certificate, so the client must trust it directly.
    /// if (!SSL_CTX_load_verify_locations(ctx, "cert.pem", NULL)) 
    //{
    //    ERR_print_errors_fp(stderr);
    //    exit(EXIT_FAILURE);
    //}    
	/// CURRENT FCN       
    /// __owur int SSL_CTX_use_certificate 	( 	SSL_CTX *  	ctx, 	X509 *  	x  	) ;
    //l = SSL_CTX_use_certificate(ctx, ctrl_GetTlsClientCert()->x509);
	/// CURRENT FCN        
    /// __owur int SSL_CTX_use_PrivateKey 	( 	SSL_CTX *  	ctx,  EVP_PKEY *  	pkey ) ;    
    //l = SSL_CTX_use_PrivateKey(ctx, ctrl_GetTlsClientCert()->pkey);
	/// CURRENT FCN        
    //#define SSL_CTX_add_extra_chain_cert 	( ctx,  	x509  	)	    SSL_CTX_ctrl(ctx,SSL_CTRL_EXTRA_CHAIN_CERT,0,(char *)(x509))    
    //l = SSL_CTX_add_extra_chain_cert(ctx, X509_dup(ctrl_GetCert()->x509));
	/// CURRENT FCN      
	/// void SSL_CTX_set_verify 	( 	SSL_CTX *  	ctx, int  	mode, int(*)(int, X509_STORE_CTX *)  	cb  ); 	    
    //SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_client_callback); // Ask for server authentication


//
///  This is the code area that needs to be upgraded for the 3.0 OpenSSL calls
//

    // Create our chain & chain modules
    if (Chain == NULL) goto exit1; // Check that the chain is not already destroyed (this will leak, but it's not usual)
    Mesh.Timer = ILibGetBaseTimer(Chain);
    Mesh.MulticastSocket = ILibMulticastSocket_Create(Chain, 3000, 16990, &multicastAddr4, &multicastAddr6, UDPSocket_OnData, NULL);
    if (Mesh.MulticastSocket == NULL) 
    {
        PRINTERROR();
        goto exit1;
    }
    Mesh.HTTPServer = ILibWebServer_CreateEx(Chain, 10, MESH_AGENT_PORT, 0, &HttpServerSessionSink, NULL);
    if (Mesh.HTTPServer == NULL) 
    {
        PRINTERROR();
        goto exit1;
    }
    Mesh.HTTPClient = ILibCreateWebClient(5, Chain);
    if (Mesh.HTTPClient == NULL) 
    {
        PRINTERROR();
        goto exit1;
    }
    Mesh.HTTPCClient = ILibCreateWebClient(5, Chain);
    if (Mesh.HTTPCClient == NULL) 
    {
        PRINTERROR();
        goto exit1;
    }
//    ILibWebClient_SetTLS(Mesh.HTTPClient, ctx, &OnSslConnection);
//    ILibWebServer_SetTLS(Mesh.HTTPServer, ctx2);

    ILibLifeTime_Add(Mesh.Timer, (void*)1, 1, &TimerTriggered, &TimerDestroyed); // Start node update timer

#ifdef WINSOCK2
    NetworkMonitorSocket = socket(AF_INET, SOCK_DGRAM, 0);
    IPAddressMonitor(0, 0, 0, 0);
#else
    IPAddressMonitor(NULL);
#endif
    IPAddressMonitorUpdate(NULL);

    // Start the chain, this is the main blocking call, all of the mesh work is done right there.
    // This method only exits when the StopChain is called.
    ILibStartChain(Chain);

    goto exit2;

exit1:
    err = 1;
    printf("Failed to start mesh agent.\r\n");
    ILibChain_DestroyEx(Chain);
exit2:

    // Cleanup Mesh
    MSG("Cleaning up.\r\n");
//    if (ctx != NULL) SSL_CTX_free(ctx);
//    if (ctx2 != NULL) SSL_CTX_free(ctx2);

    // OpenSSL and Mesh Controller Cleanup
    ctrl_MeshUnInit();
//    util_openssl_uninit();

    // Check if we need to perform self-update
    if (g_UpdateOnExit)
    {
#ifdef WIN32
        // Windows version
        char temp[10000];
        STARTUPINFOA info = {sizeof(info)};
        PROCESS_INFORMATION processInfo;

        snprintf(temp, 10000, "%s -update:\"%s\"", g_UpdateExe, g_SelfExe);
        if (!CreateProcessA(NULL, temp, NULL, NULL, TRUE, 0, NULL, NULL, &info, &processInfo))
        {
            // TODO: Failed to run update.
        }
#else
        // Linux version
        char temp[10000];

        snprintf(temp, 10000, "./meshupdate.exe -update:\"%s\" &", g_SelfExe);
        system(temp);
#endif
    }

#ifdef WINSOCK2
    // Winsock cleanup
    WSACleanup();
    if (g_SelfExeMem != NULL) free(g_SelfExeMem);
#endif
    if (g_UpdateExe != NULL) free(g_UpdateExe);

#ifdef WIN32
    SetPriorityClass(GetCurrentProcess(), PROCESS_MODE_BACKGROUND_END);
#endif

    return err;
}

// Called then the master timer is triggered
void TimerTriggered(void *data)
{
    UNREFERENCED_PARAMETER( data );

    //MSG2("Timer triggered. Count = %d\r\n", (int)ILibLifeTime_Count(Mesh.Timer));

    switch ((int)data)
	{
		case 1: // General udpate timer
		{
			// Perform a syncronization - Here, the database does the work & calls the control module to perform sync.
			mdb_synctargets();

			// Reset the timer
			ILibLifeTime_Add(Mesh.Timer, (void*)1, MESH_CYCLETIME, &TimerTriggered, &TimerDestroyed);
		}
		break;
		case 2: // Broadcast timer
		{
			int NextMulticast;

			// Generate an updated push block
			ctrl_GetCurrentSignedNodeInfoBlock(NULL);

			// The interfaces have changed, lets make sure our multicase sockets are in order.
			ILibMulticastSocket_ResetMulticast(Mesh.MulticastSocket, 0);

			// Send our own nodeid data
			//MSG("Sending Broadcast.\r\n");
			ILibMulticastSocket_Broadcast(Mesh.MulticastSocket, g_selfid_mcast, 36, 1);

			// Select a next multicast timeout
			util_random(sizeof(int), (char*)(&NextMulticast));
			NextMulticast = ((NextMulticast % MESH_MCAST_TIMER_VAR) + MESH_MCAST_TIMER_MIN) * 60;
			// Reset the multicast timer
			ILibLifeTime_Add(Mesh.Timer, (void*)2, NextMulticast, &TimerTriggered, &TimerDestroyed);
		}
    break;
    }
}

// Called when a master timer is pending and the stack is exitting
void TimerDestroyed(void *data)
{
    UNREFERENCED_PARAMETER( data );
    //MSG("Timer destroyed.\r\n");
}

// This will handle a connection to the webserver created
void HttpServerSessionSink(struct ILibWebServer_Session *SessionToken, void *user)
{
    STACK_OF(X509) *certs;
    struct sockaddr_in6 remote;
#if defined(_DEBUG)
    struct sockaddr_in6 local;
    //char localstr[200];
    char remotestr[200];
#endif

    UNREFERENCED_PARAMETER( user );
    ILibWebServer_GetRemoteInterface(SessionToken, (struct sockaddr*)&remote);

#if defined(_DEBUG)
    ILibWebServer_GetLocalInterface(SessionToken, (struct sockaddr*)&local);
    if (remote.sin6_family == AF_INET) ILibInet_ntop(AF_INET, &(((struct sockaddr_in*)&remote)->sin_addr), remotestr, 200);
    if (remote.sin6_family == AF_INET6) ILibInet_ntop(AF_INET6, &(((struct sockaddr_in6*)&remote)->sin6_addr), remotestr, 200);
    //MSG2("HTTP Server connection from %s\r\n", remotestr);
#endif

    // A new inbound HTTP server session was connected, lets get remote NodeID & IP address and update the target state
    certs = ILibAsyncSocket_SslGetCerts(SessionToken->Reserved2); // Peer cert chains (without peer TLS client cert)
    if (certs != NULL && sk_X509_num(certs) > 0)
    {
        // Compute the hash and store it in the HttpSession
        if (util_keyhash2(sk_X509_value(certs, 0), SessionToken->CertificateHash) == 0)
        {
            SessionToken->CertificateHashPtr = SessionToken->CertificateHash;
            // If the nodeid of the client is not null and not outself, update this target.
            if (memcmp(g_selfid, SessionToken->CertificateHash, UTIL_HASHSIZE) != 0) mdb_updatetarget(SessionToken->CertificateHash, (struct sockaddr*)&remote, MDB_AGENT, 1);
        }
    }

    SessionToken->OnReceive = &HttpServerSessionReceiveSink;
    SessionToken->OnDisconnect = &HttpServerSessionDisconnect;
    SessionToken->User = NULL;
    SessionToken->User2 = NULL;
    SessionToken->User3 = NULL;
    SessionToken->User4 = 0;
}

// HTTP helpers
#define RESPONSE_HEADER_TEMPLATE_HTML "\r\nServer: MeshAgent\r\nContent-Type: text/html\r\nConnection: Keep-Alive"
#define RESPONSE_HEADER_TEMPLATE_TEXT "\r\nServer: MeshAgent\r\nContent-Type: text/plain\r\nConnection: Keep-Alive"
#define RESPONSE_HEADER_TEMPLATE_BIN "\r\nServer: MeshAgent\r\nContent-Type: application/octet-stream\r\nConnection: Keep-Alive"
#if defined(_DEBUG)
#define HTTP_DEBUG_MENU0 "<a href=\"/db\">Database Tables</a><br>"
#define HTTP_DEBUG_MENU1 "<a href=\"/cert\">Show node certificate</a><br>"
#define HTTP_DEBUG_MENU2 "<a href=\"/events\">Show Event Log</a><br>"
#define HTTP_DEBUG_MENU3 "<a href=\"/deleteevents\">Clear Event Log</a><br>"
#define HTTP_DEBUG_MENU4 "<a href=\"/buckets\">Distance Buckets</a><br>"
#define HTTP_DEBUG_AUTOHEADER "<html><meta http-equiv=\"refresh\" content=\"2\" /><META HTTP-EQUIV=\"CACHE-CONTROL\" CONTENT=\"NO-CACHE\"></html>"
#endif


void HttpWebServerSessionSendOK(struct ILibWebServer_Session *sender)
{
    UNREFERENCED_PARAMETER( sender );
    //MSG("SENDOK\r\n");
}

// Handles all of the HTTP server requests
void HttpServerSessionReceiveSink(struct ILibWebServer_Session *sender, int InterruptFlag, struct packetheader *header, char *bodyBuffer, int *beginPointer, int endPointer, int done)
{
    FILE* pfile;
#ifdef _DEBUG
    unsigned int l;
    char nodeid[UTIL_HASHSIZE];
    char* str;
    struct sockaddr_in6 addr;
#endif

    // Handle the more complex post queries.
    if (header != NULL && InterruptFlag == 0 && done == -1)
    {
        if(header->DirectiveObjLength == 19 && strncasecmp(header->DirectiveObj, "/mesh/statepush.bin", 19) == 0)
        {
            // Process all of the data
            *beginPointer = ctrl_ProcessDataBlocks(bodyBuffer, endPointer, NULL, sender->CertificateHashPtr, NULL, NULL);

            if (done != 0)
            {
                // Post is done, send ok and finish
                MSG3("HTTP Server Request: %s %s\r\n", header->Directive, header->DirectiveObj);
                ILibWebServer_StreamHeader_Raw(sender, 200, "200 - OK", RESPONSE_HEADER_TEMPLATE_TEXT, ILibAsyncSocket_MemoryOwnership_STATIC);
                ILibWebServer_StreamBody(sender, NULL, 0, ILibAsyncSocket_MemoryOwnership_STATIC,1);
                *beginPointer = endPointer;
            }

            return;
        }

        if(header->DirectiveObjLength == 19 && strncasecmp(header->DirectiveObj, "/mesh/quicksync.bin", 19) == 0)
        {
            int selfnodeflag = 0;

            if (done != 0)
            {
                // If this post includes the metadata for our own node, check it. If we have a better current push block, send it in the response.
                if (bodyBuffer != NULL && endPointer == 36 && g_serial > ntohl(((unsigned int*)bodyBuffer)[0]) && memcmp(bodyBuffer + 4, g_selfid, UTIL_HASHSIZE) == 0) selfnodeflag = MDB_SELFNODE;

                // Post is done, send ok and finish
                MSG3("HTTP Server Request: %s %s\r\n", header->Directive, header->DirectiveObj);
                ILibWebServer_StreamHeader_Raw(sender, 200, "200 - OK", RESPONSE_HEADER_TEMPLATE_TEXT, ILibAsyncSocket_MemoryOwnership_STATIC);

                // Send all blocks & close. This will send nodes & close the session when done.
                mdb_sendasync(sender, 0, sender->CertificateHashPtr, MDB_SESSIONKEY | MDB_AGENTID | selfnodeflag);
            }

            return;
        }

        if(header->DirectiveObjLength == 18 && strncasecmp(header->DirectiveObj, "/mesh/fullsync.bin", 18) == 0)
        {
            // Process the data
            *beginPointer = ctrl_ProcessDataBlocks(bodyBuffer, endPointer, NULL, sender->CertificateHashPtr, NULL, NULL);

            if (done != 0)
            {
                // Post is done, send ok and finish
                MSG3("HTTP Server Request: %s %s\r\n", header->Directive, header->DirectiveObj);
                ILibWebServer_StreamHeader_Raw(sender, 200, "200 - OK", RESPONSE_HEADER_TEMPLATE_TEXT, ILibAsyncSocket_MemoryOwnership_STATIC);

                // Send all blocks & close. This will send nodes & close the session when done.
                mdb_sendasync(sender, 0, sender->CertificateHashPtr, MDB_PUSHBLOCKS | MDB_SESSIONKEY | MDB_SELFNODE);
            }

            return;
        }
    }

    if (header != NULL && done !=0 && InterruptFlag == 0)
    {
        //MSG3("HTTP Server Request: %s %s\r\n", header->Directive, header->DirectiveObj);

        if(header->DirectiveObjLength == 17 && strncasecmp(header->DirectiveObj, "/mesh/selfexe.bin", 17) == 0 && g_SelfExe != NULL)
        {
#ifdef WIN32
            fopen_s(&pfile, g_SelfExe, "rb");
#else
            pfile = fopen(g_SelfExe, "rb");
#endif
            if (pfile == NULL)
            {
                // Unknown URL, 404 error
                ILibWebServer_StreamHeader_Raw(sender, 404, "404 - File not found", RESPONSE_HEADER_TEMPLATE_HTML, ILibAsyncSocket_MemoryOwnership_STATIC);
                ILibWebServer_StreamBody(sender, "404 - File not found", 20, ILibAsyncSocket_MemoryOwnership_STATIC,1);
            }
            else
            {
                // Send out our own exe file
                ILibWebServer_StreamHeader_Raw(sender, 200, "200 - OK", RESPONSE_HEADER_TEMPLATE_BIN, ILibAsyncSocket_MemoryOwnership_STATIC);
                ILibWebServer_StreamFile(sender, pfile); // This takes care of the async streaming.
            }
        }
        else if(header->DirectiveObjLength == 15 && strncasecmp(header->DirectiveObj, "/mesh/state.bin", 15) == 0)
        {
            // Get the state of the targets
            ILibWebServer_StreamHeader_Raw(sender, 200, "200 - OK", RESPONSE_HEADER_TEMPLATE_BIN, ILibAsyncSocket_MemoryOwnership_STATIC);
            mdb_sendasync(sender, 0, NULL, MDB_SELFNODE | MDB_PUSHBLOCKS | MDB_TARGETS);
        }
#if defined(_DEBUG)
        else if(header->DirectiveObjLength == 16 && strncasecmp(header->DirectiveObj, "/mesh/selfid.bin", 16) == 0 && g_SelfExe != NULL)
        {
            // Send out our own exe hash value
            ILibWebServer_StreamHeader_Raw(sender, 200, "200 - OK", RESPONSE_HEADER_TEMPLATE_BIN, ILibAsyncSocket_MemoryOwnership_STATIC);
            ILibWebServer_StreamBody(sender, g_selfid, UTIL_HASHSIZE, ILibAsyncSocket_MemoryOwnership_STATIC, 1);
        }
        else if(header->DirectiveObjLength == 1 && strncasecmp(header->DirectiveObj, "/", 1)==0)
        {
            // Send a small menu contining the nodeid and various html debug links
            ILibWebServer_StreamHeader_Raw(sender, 200, "200 - OK", RESPONSE_HEADER_TEMPLATE_HTML, ILibAsyncSocket_MemoryOwnership_STATIC);
            //spareDebugLen = sprintf(spareDebugMemory,"NodeID: %02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X",selfid[0],selfid[1],selfid[2],selfid[3],selfid[4],selfid[5],selfid[6],selfid[7],selfid[8],selfid[9],selfid[10],selfid[11],selfid[12],selfid[13],selfid[14],selfid[15],selfid[16],selfid[17],selfid[18],selfid[19]);
            ILibWebServer_StreamBody(sender, spareDebugMemory, spareDebugLen, ILibAsyncSocket_MemoryOwnership_USER,0);
            ILibWebServer_StreamBody(sender, "<br>", 4, ILibAsyncSocket_MemoryOwnership_STATIC,0);
            ILibWebServer_StreamBody(sender, HTTP_DEBUG_MENU0, (int)strlen(HTTP_DEBUG_MENU0), ILibAsyncSocket_MemoryOwnership_STATIC,0);
            ILibWebServer_StreamBody(sender, HTTP_DEBUG_MENU1, (int)strlen(HTTP_DEBUG_MENU1), ILibAsyncSocket_MemoryOwnership_STATIC,0);
            ILibWebServer_StreamBody(sender, HTTP_DEBUG_MENU2, (int)strlen(HTTP_DEBUG_MENU2), ILibAsyncSocket_MemoryOwnership_STATIC,0);
            ILibWebServer_StreamBody(sender, HTTP_DEBUG_MENU3, (int)strlen(HTTP_DEBUG_MENU3), ILibAsyncSocket_MemoryOwnership_STATIC,0);
            ILibWebServer_StreamBody(sender, HTTP_DEBUG_MENU4, (int)strlen(HTTP_DEBUG_MENU4), ILibAsyncSocket_MemoryOwnership_STATIC,0);
            ILibWebServer_StreamBody(sender, NULL, 0, ILibAsyncSocket_MemoryOwnership_STATIC,1);
        }
        else if(header->DirectiveObjLength == 7 && strncasecmp(header->DirectiveObj,"/events", 7) == 0)
        {
            // Send the current event log
            ILibWebServer_StreamHeader_Raw(sender, 200, "200 - OK", RESPONSE_HEADER_TEMPLATE_HTML, ILibAsyncSocket_MemoryOwnership_STATIC);
            mdb_sendevents(sender);
            ILibWebServer_StreamBody(sender, NULL, 0, ILibAsyncSocket_MemoryOwnership_STATIC,1);
        }
        else if(header->DirectiveObjLength == 3 && strncasecmp(header->DirectiveObj,"/db", 3) == 0)
        {
            // Send a nicely formatted dumb of the database targets table
            ILibWebServer_StreamHeader_Raw(sender, 200, "200 - OK", RESPONSE_HEADER_TEMPLATE_HTML, ILibAsyncSocket_MemoryOwnership_STATIC);
            ILibWebServer_StreamBody(sender, HTTP_DEBUG_AUTOHEADER, (int)strlen(HTTP_DEBUG_AUTOHEADER), ILibAsyncSocket_MemoryOwnership_STATIC, 0);
            mdb_sendalltargetsdebugasync(sender);
        }
        else if(header->DirectiveObjLength == 13 && strncasecmp(header->DirectiveObj,"/deleteevents", 13) == 0)
        {
            // Send clear the event log
            ILibWebServer_StreamHeader_Raw(sender, 200, "200 - OK", RESPONSE_HEADER_TEMPLATE_HTML, ILibAsyncSocket_MemoryOwnership_STATIC);
            mdb_deleteevents(sender);
            ILibWebServer_StreamBody(sender, "Cleared", 7, ILibAsyncSocket_MemoryOwnership_STATIC,1);
        }
        else if(header->DirectiveObjLength == 5 && strncasecmp(header->DirectiveObj,"/cert", 5) == 0)
        {
            // Send the current node certificate in plain text
            ILibWebServer_StreamHeader_Raw(sender, 200, "200 - OK", RESPONSE_HEADER_TEMPLATE_TEXT, ILibAsyncSocket_MemoryOwnership_STATIC);
            util_sendcert(sender, *ctrl_GetCert());
            ILibWebServer_StreamBody(sender, NULL, 0, ILibAsyncSocket_MemoryOwnership_STATIC, 1);
        }
        else if(header->DirectiveObjLength == 20 && strncasecmp(header->DirectiveObj,"/mesh/clearnodes.bin", 20) == 0)
        {
            // Send the current node certificate in plain text
            ILibWebServer_StreamHeader_Raw(sender, 200, "200 - OK", RESPONSE_HEADER_TEMPLATE_BIN, ILibAsyncSocket_MemoryOwnership_STATIC);
            mdb_clearall();
            ILibWebServer_StreamBody(sender, NULL, 0, ILibAsyncSocket_MemoryOwnership_STATIC, 1);
        }
        else if(header->DirectiveObjLength == 23 && strncasecmp(header->DirectiveObj,"/mesh/generatenodes.bin", 23) == 0)
        {
            // Send the current node certificate in plain text
            ILibWebServer_StreamHeader_Raw(sender, 200, "200 - OK", RESPONSE_HEADER_TEMPLATE_BIN, ILibAsyncSocket_MemoryOwnership_STATIC);
            //ut_GenerateTestNodes(50);

            // Test Intel AMT Sync
            memset(&addr, 0, sizeof(struct sockaddr_in6));
            addr.sin6_family = AF_INET;
            ((struct sockaddr_in*)&addr)->sin_port = htons(MESH_AGENT_PORT);
            ILibInet_pton(AF_INET, "192.168.2.100", &(((struct sockaddr_in*)&addr)->sin_addr));
            l = (int)mdb_gettargetstate((struct sockaddr*)&addr, nodeid, NULL, NULL, NULL);
            ctrl_SyncToIntelAmt(0, (struct sockaddr*)&addr, 16992, nodeid, "admin", "P@ssw0rd");

            ILibWebServer_StreamBody(sender, NULL, 0, ILibAsyncSocket_MemoryOwnership_STATIC, 1);
        }
        else if(header->DirectiveObjLength == 19 && strncasecmp(header->DirectiveObj,"/mesh/forcesync.bin", 19)==0)
        {
            // Force this node to sync to another IP address
            ILibWebServer_StreamHeader_Raw(sender, 200, "200 - OK", RESPONSE_HEADER_TEMPLATE_BIN, ILibAsyncSocket_MemoryOwnership_STATIC);

            // Setup the target address
            memset(&addr, 0, sizeof(struct sockaddr_in6));
            addr.sin6_family = AF_INET6;
            addr.sin6_port = htons(MESH_AGENT_PORT);
            ILibInet_pton(AF_INET6, bodyBuffer, &(addr.sin6_addr));

            // We put a high number in the lastcontact field to force a TLS connection
            //if ((l = (unsigned int)mdb_gettargetstate((struct sockaddr*)&addr, nodeid, NULL, NULL, NULL)) != 0) ctrl_SyncToNode((struct sockaddr*)&addr, nodeid, (int)l, NULL, NULL, 100000, 0);
            ILibWebServer_StreamBody(sender, NULL, 0, ILibAsyncSocket_MemoryOwnership_STATIC, 1);
        }
        else if(header->DirectiveObjLength == 23 && strncasecmp(header->DirectiveObj,"/mesh/allpushblocks.bin", 23)==0)
        {
            // Send the current node certificate in plain text
            ILibWebServer_StreamHeader_Raw(sender, 200, "200 - OK", RESPONSE_HEADER_TEMPLATE_BIN, ILibAsyncSocket_MemoryOwnership_STATIC);

            // Send out our own push block
            l = ctrl_GetCurrentSignedNodeInfoBlock(&str);
            ILibWebServer_StreamBody(sender, str, l, ILibAsyncSocket_MemoryOwnership_USER,0);

            // Send out all other push blocks in the database and close the session
            mdb_sendallpushblocksasync(sender, 0, NULL, 0);
        }
        else if(header->DirectiveObjLength == 21 && strncasecmp(header->DirectiveObj,"/mesh/setamtadmin.bin", 21)==0)
        {
            // Send the current node certificate in plain text
            ILibWebServer_StreamHeader_Raw(sender, 200, "200 - OK", RESPONSE_HEADER_TEMPLATE_BIN, ILibAsyncSocket_MemoryOwnership_STATIC);
            ctrl_SetLocalIntelAmtAdmin(bodyBuffer[0], bodyBuffer+1, bodyBuffer+33);
            ILibWebServer_StreamBody(sender, NULL, 0, ILibAsyncSocket_MemoryOwnership_STATIC,1);
        }
        else if(header->DirectiveObjLength == 8 && strncasecmp(header->DirectiveObj,"/buckets", 8) == 0)
        {
            char str[2000];
            char* ptr = str;
            int i;

            // Send the list of bucket values
            ILibWebServer_StreamHeader_Raw(sender, 200, "200 - OK", RESPONSE_HEADER_TEMPLATE_HTML, ILibAsyncSocket_MemoryOwnership_STATIC);
            for (i=31; i>=0; i--) 
            {
                ptr += snprintf(ptr, (str + 2000) - ptr, "Distance %d = %d<br>", i, g_distancebuckets[i]);
            }
            ILibWebServer_StreamBody(sender, str, (int)(ptr - str), ILibAsyncSocket_MemoryOwnership_STATIC, 1);
        }
        else if(header->DirectiveObjLength == 7 && strncasecmp(header->DirectiveObj,"/update", 7) == 0)
        {
            // Trigger a test update
            ILibWebServer_StreamHeader_Raw(sender, 200, "200 - OK", RESPONSE_HEADER_TEMPLATE_TEXT, ILibAsyncSocket_MemoryOwnership_STATIC);
            ILibWebServer_StreamBody(sender, NULL, 0, ILibAsyncSocket_MemoryOwnership_STATIC, 1);
            if (g_SelfExe != NULL)
            {
#ifdef WIN32
                remove(g_UpdateExe);
                CopyFileA(g_SelfExe, g_UpdateExe, FALSE);
#else
                char temp[6000];
                remove("meshupdate.exe");
                snprintf(temp, 6000, "cp %s meshupdate.exe", g_SelfExe);
                system(temp);
#endif
                g_UpdateOnExit = 1;
                StopMesh();
            }
        }
#endif
        else
        {
            // Unknown URL, 404 error
            MSG("HTTP Server sending 404 error\r\n");
            ILibWebServer_StreamHeader_Raw(sender, 404, "404 - File not found", RESPONSE_HEADER_TEMPLATE_HTML, ILibAsyncSocket_MemoryOwnership_STATIC);
            ILibWebServer_StreamBody(sender, "404 - File not found", 20, ILibAsyncSocket_MemoryOwnership_STATIC,1);
        }
    }
}

// Called when an HTTP session is disconnected.
void HttpServerSessionDisconnect(struct ILibWebServer_Session *session)
{
    UNREFERENCED_PARAMETER( session );
    //MSG("HTTP Server session disconnect.\r\n");
}

static const char *UPNPCP_SOAP_Header = "%s %s HTTP/1.1\r\nHost: %s:%d\r\nUser-Agent: %s, Mesh/1.1, MicroStack/1.0\r\nContent-Type: text/xml\r\nContent-Length: %d\r\n\r\n";
static const char *UPNPCP_SOAP_HeaderA = "%s %s HTTP/1.1\r\nHost: %s:%d\r\nUser-Agent: %s, Mesh/1.1, MicroStack/1.0\r\nContent-Type: text/xml\r\nContent-Length: %d\r\nAuthorization: %s\r\n\r\n";
char* PLATFORM = "Mesh/1.1, MicroStack/1.0";

void HttpResponseSink(
    void *WebReaderToken,
    int IsInterrupt,
    struct packetheader *header,
    char *bodyBuffer,
    int *beginPointer,
    int endPointer,
    int done,
    void *_service,
    void *state,
    int *PAUSE)
{
    int ptr;
    char* str;
    int headerLength;
    unsigned char powerstate;
    struct HttpRequestBlock* request = (struct HttpRequestBlock*)_service;
    struct sockaddr_in6 *remote;
    char tstr[200];
    NodeInfoBlock_t *nodeinfo;

    UNREFERENCED_PARAMETER( WebReaderToken );
    UNREFERENCED_PARAMETER( IsInterrupt );
    UNREFERENCED_PARAMETER( state );
    UNREFERENCED_PARAMETER( PAUSE );

    // Sanity Check
    if (request == NULL || request->addr == NULL) ILIBCRITICALEXIT(253);

    // If this request is finished, decrement the request counter, then cast the remote IP address
    if (done != 0) g_outstanding_outbound_requests--;
    remote = (struct sockaddr_in6*)(request->addr);

    // If this is a request error, we have to process it differently & exit.
    if (beginPointer == NULL)
    {
        // Debug
        if (remote->sin6_family == AF_INET) ILibInet_ntop(AF_INET, &(((struct sockaddr_in*)remote)->sin_addr), tstr, 200);
        if (remote->sin6_family == AF_INET6) ILibInet_ntop(AF_INET6, &(((struct sockaddr_in6*)remote)->sin6_addr), tstr, 200);
        MSG3("HTTP Request error - Target: %s, RequestType=%d\r\n", tstr, request->requesttype);

        if (request->requesttype == 1)
        {
            // We got a problem, the connection to the remote agent failed.
            // First, lets check to see if the expected node support Intel AMT.
            ptr = 0;

            if (request->nodeid != NULL)
            {
                nodeinfo = ctrl_GetNodeInfoBlock(request->nodeid);
                if (nodeinfo != NULL && nodeinfo->meinfo != NULL && nodeinfo->meinfo->guestuser[0] != 0 && nodeinfo->meinfo->guestpassword[0] != 0)
                {
                    // Seems like Intel AMT exists, if this is Intel AMT 5.0 or below and we are IPv6, don't use Intel AMT
                    if (nodeinfo->meinfo->version >= 0x00060000 || ((struct sockaddr*)request->addr)->sa_family == AF_INET)
                    {
                        // TODO: Check that "remote" is a managed interface

                        // Lets switch to Intel AMT mode
                        mdb_updatetarget(request->nodeid, (struct sockaddr*)remote, MDB_AMTONLY, 0);
                        ptr = 1;

                        // Launch a sync with Intel AMT
                        ctrl_SyncToIntelAmt(nodeinfo->meinfo->tlsenabled, request->addr, (nodeinfo->meinfo->tlsenabled==0?16992:16993), request->nodeid, (char*)(nodeinfo->meinfo->guestuser), (char*)(nodeinfo->meinfo->guestpassword));
                    }
                }
                info_FreeInfoBlock(nodeinfo);
            }

            // Intel AMT not supported, clean this target.
            if (ptr == 0) mdb_updatetarget(NullNodeId, (struct sockaddr*)remote, MDB_UNKNOWN, 0);
        }
        else if (request->requesttype == 2)
        {
            // We got a problem, the connection to Intel(R) AMT failed.
            mdb_updatetarget(NullNodeId, (struct sockaddr*)remote, MDB_UNKNOWN, 0);
        }
        else if (request->requesttype == 3)
        {
            // Problem occured, reset the self-update process
            if (request->pfile != NULL) fclose(request->pfile);
            remove(g_UpdateExe);
            g_PerformingSelfUpdate = 0;
        }

        if (request->ip       != NULL) free(request->ip);
        if (request->addr     != NULL) free(request->addr);
        if (request->realm    != NULL) free(request->realm);
        if (request->nonce    != NULL) free(request->nonce);
        if (request->qop      != NULL) free(request->qop);
        if (request->nodeid   != NULL) free(request->nodeid);
        if (request->username != NULL) free(request->username);
        if (request->password != NULL) free(request->password);
        free(request);
        return;
    }

    // Sync to a peer node. Only process 60k or more of data at a time to limit the number of commits to the database.
    // We pay a memcpy price for not handling as we go, but the commit time is much worst then memcpy.
    if (request->requesttype == 1 && (endPointer > 60000 || done != 0))
    {
        // We expect to be receiving raw blocks
        *beginPointer = ctrl_ProcessDataBlocks(bodyBuffer, endPointer, NULL, ILibWebClient_GetCertificateHash(WebReaderToken), remote, NULL);
        mdb_updatetarget(request->nodeid, (struct sockaddr*)remote, MDB_AGENT, 1);
    }

    // Sync to Intel AMT, authentication required
    if (request->requesttype == 2 && done != 0)
    {
        // We need to authenticate
        if (header->StatusCode == 401 && request->tryCount < 4 && (str = ILibGetHeaderLine(header, "WWW-Authenticate", 16)) != NULL)
        {
            // Parse the HTTP Digest challenge & generate response
            util_ExtractWwwAuthenticate(str, request);
            request->tryCount++;
            util_GenerateAuthorizationHeader(request, "GET", "/index.htm", ILibScratchPad, g_SessionNonce);

            // Build the header
            headerLength = snprintf(ILibScratchPad, sizeof(ILibScratchPad), UPNPCP_SOAP_HeaderA, "GET", "/index.htm", request->ip, request->port, PLATFORM, 0, ILibScratchPad);

            // Duplicate the request state
            request->refcount++;

            // Send the new request
            g_outstanding_outbound_requests++;
            ILibWebClient_PipelineRequestEx(
                request->requestmanager,
                (struct sockaddr*)request->addr,
                ILibScratchPad,	// Header
                headerLength,	// Header Size
                ILibAsyncSocket_MemoryOwnership_USER,
                NULL,			// Body
                0,				// Body Size
                ILibAsyncSocket_MemoryOwnership_USER,
                &HttpResponseSink,
                (void*)request,
                NULL
            );
        }
        else if (header->StatusCode == 401 && request->tryCount >= 4 && (str = ILibGetHeaderLine(header, "WWW-Authenticate", 16)) != NULL)
        {
            // The Intel(R) AMT authentication failed 5 times, change the state to unknown
            mdb_updatetarget(NullNodeId, (struct sockaddr*)remote, MDB_UNKNOWN, 0);
        }
        else if (header->StatusCode == 200 && done == -1)
        {
            // We got the web page. Process it and update the power state
            if (request->nodeid != NULL)
            {
                info_ProcessAmtWebPage(bodyBuffer, endPointer, &powerstate, &str);
                mdb_updatetarget(request->nodeid, (struct sockaddr*)remote, MDB_AMTONLY, powerstate);
                MSG3("Got Intel(R) AMT web page. Power=%d, ID=%s.\r\n", powerstate, str);
            }
            *beginPointer = endPointer;
        }
    }

    // We are fetching a remote agent update
    if (request->requesttype == 3)
    {
        if (bodyBuffer != NULL && endPointer > 0)
        {
            // We are fetching a remote agent update
            if (request->pfile == NULL)
            {
                remove(g_UpdateExe);
#ifdef WIN32
                fopen_s(&(request->pfile), g_UpdateExe, "wb");
#else
                request->pfile = fopen(g_UpdateExe, "wb");
#endif
            }
            fwrite(bodyBuffer, 1, endPointer, request->pfile);
            *beginPointer = endPointer;
        }
        if (done != 0)
        {
            if (request->pfile != NULL)
            {
                char updatehash[32];

                // Close the file and hash it
                fclose(request->pfile);
                if (util_sha256file(g_UpdateExe, updatehash) == 0)
                {
                    // Check the hash
                    // TODO

                    // Perform the update
#ifndef WIN32
                    char cmd[4096];
                    snprintf(cmd, 4096, "chmod 700 %s", g_UpdateExe);
                    system(cmd);
#endif
                    g_UpdateOnExit = 1;
                    StopMesh();
                }
                if (g_UpdateOnExit == 0) remove(g_UpdateExe);
            }
        }
    }

    // Cleanup if the request completed
    if (done != 0)
    {
        if (header == NULL)
        {
            // Connection Failed
            MSG("HTTP Request Failed.\r\n");
        }
        else if (header->StatusCode != 200)
        {
            // HTTP Error
            if (header->StatusCode != 401) MSG2("HTTP error (%d).\r\n", header->StatusCode);
        }
        else
        {
            // Post is done, send ok and finish
            //MSG("HTTP Response Completed.\r\n");
        }
        *beginPointer = endPointer;

        // Free the request structure
        if (request != NULL)
        {
            if (request->refcount == 0)
            {
                if (request->ip       != NULL) free(request->ip);
                if (request->addr     != NULL) free(request->addr);
                if (request->realm    != NULL) free(request->realm);
                if (request->nonce    != NULL) free(request->nonce);
                if (request->qop      != NULL) free(request->qop);
                if (request->nodeid   != NULL) free(request->nodeid);
                if (request->username != NULL) free(request->username);
                if (request->password != NULL) free(request->password);
                free(request);
            }
            else request->refcount--;
        }
    }
}

// Send a unicast packet using the same sockets used for multicast.
void UnicastUdpPacket(struct sockaddr* target, char* data, int datalen)
{
    ILibMulticastSocket_Unicast(Mesh.MulticastSocket, target, data, datalen);
}

void PerformHttpRequest(int tls, struct sockaddr *addr, char* path, struct HttpRequestBlock* user, char* post, int postlen)
{
    char* str;
    int headerLength;
    char *headerBuffer;
    struct sockaddr_in6 addr6;
#ifdef _DEBUG
    char tstr[400];
    char https[2];
#endif

    // Convert the IPv4 to IPv6 address if needed, then, create the HTTP HOST entry.
    ILibMakeIPv6Addr(addr, &addr6);
    ILibMakeHttpHeaderAddr(addr, &str);

    // Create the HTTP header. Care must be taken to format IPv6 address with brakets.
    if ((headerBuffer = (char*)malloc(400 + strlen(path))) == NULL) return;
    headerLength = snprintf(headerBuffer, 400 + strlen(path), UPNPCP_SOAP_Header, (postlen == 0)?"GET":"POST", path, str, INET_SOCKADDR_PORT(addr), PLATFORM, postlen);
    free(str);

    // Launch the HTTP request, should work on both IPv4 and IPv6. If post is empty, this is a GET, otherwise POST.
    g_outstanding_outbound_requests++;

#ifdef _DEBUG
    https[1]=0;
    if (tls != 0) 
    {
        https[0]='S';
    }
    else 
    {
        https[0]=0;
    }
    if (addr6.sin6_family == AF_INET) ILibInet_ntop(AF_INET, &(((struct sockaddr_in*)&addr6)->sin_addr), tstr, 400);
    if (addr6.sin6_family == AF_INET6) ILibInet_ntop(AF_INET6, &(((struct sockaddr_in6*)&addr6)->sin6_addr), tstr, 400);
    if (addr6.sin6_family == AF_INET) MSG4("Launching HTTP%s://[%s]:%d/.\r\n", https, tstr, ntohs(((struct sockaddr_in*)&addr6)->sin_port));
    if (addr6.sin6_family == AF_INET6) MSG4("Launching HTTP%s://[%s]:%d/.\r\n", https, tstr, ntohs(((struct sockaddr_in6*)&addr6)->sin6_port));
#endif

    user->requestmanager = tls?Mesh.HTTPClient:Mesh.HTTPCClient;

    ILibWebClient_PipelineRequestEx(
        user->requestmanager,
        (struct sockaddr*)&addr6,
        headerBuffer,	// Header
        headerLength,	// Header Size
        ILibAsyncSocket_MemoryOwnership_CHAIN,
        post,			// Body
        postlen,		// Body Size
        ILibAsyncSocket_MemoryOwnership_CHAIN,
        &HttpResponseSink,
        (void*)user,
        NULL
    );
}



#define AUTHORIZATION_FIELDDATA_TEMPLATE "Digest username=\"%s\", realm=\"%s\", nonce=\"%s\", uri=\"%s\", response=\"%s\", qop=%s, nc=%08x, cnonce=\"%s\""




// Starts dropping packets is rate is too high
long util_af_time = 0;
long util_af_count = 0;

//! \fn CreateRSA creates memory and fills it for use elsewhere
RSA_t * CreateRSA()
{
/*
	RSA_t * ret = malloc ( sizeof( RSA_t ));
	ret->primes = 3;
	ret->bits = 4096;
	ret->pctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
	EVP_PKEY_keygen_init(ret->pctx);
	ret->params[0] = OSSL_PARAM_construct_uint("bits", &(ret->bits));
	ret->params[1] = OSSL_PARAM_construct_uint("primes", &(ret->primes));
	ret->params[2] = OSSL_PARAM_construct_end();
	EVP_PKEY_CTX_set_params(pctx, &(ret->params));
	EVP_PKEY_generate(pctx, &(ret->pkey));
	EVP_PKEY_print_private(bio_out, ret->pkey, 0, NULL);
	EVP_PKEY_CTX_free(ret->pctx);	
	
	return ret;
*/
}



int util_antiflood(int rate, int interval)
{
/*
    long seconds;
    struct timeval clock;
    gettimeofday(&clock,NULL);
    seconds = clock.tv_sec;

    if ((seconds - util_af_time) > interval)
    {
        util_af_time = seconds;
        util_af_count = 0;
        return 1;
    }
    util_af_count++;
    return util_af_count < rate;
*/
}


// Extract data from an HTTP Digest authentication request
int util_ExtractWwwAuthenticate(char *wwwAuthenticate, void *request)
{
/*
    struct HttpRequestBlock *hostData = (struct HttpRequestBlock *)request;
    struct parser_result *r = ILibParseString(wwwAuthenticate,0,(int)strlen(wwwAuthenticate), ", ", 2);
    if (hostData == NULL) return -1;

    if (r != NULL)
    {
        struct parser_result *r1;
        struct parser_result_field *prf = NULL;

        char *keyValue = NULL;
        char *key = NULL;

        prf = r->FirstResult;
        while(prf!=NULL)
        {
            keyValue = prf->data;

            r1 = ILibParseString(keyValue,0,prf->datalength,"=\"",2);

            if (r1->NumResults == 1)
            {
                ILibDestructParserResults(r1);
                r1 = ILibParseString(keyValue,0,prf->datalength,"=",1);
            }

            key = r1->FirstResult->data;

            if(strncasecmp(key, "Digest realm", (int)strlen("Digest realm")) == 0)
            {
                hostData->realm = malloc(r1->LastResult->datalength);
                if (hostData->realm == NULL) goto error;
                strncpy(hostData->realm, r1->LastResult->data, r1->LastResult->datalength);
                hostData->realm[r1->LastResult->datalength - 1] = '\0';
            }
            else if(strncasecmp(key, "nonce", (int)strlen("nonce")) == 0)
            {
                hostData->nonce = malloc(r1->LastResult->datalength);
                if (hostData->nonce == NULL) goto error;
                strncpy(hostData->nonce, r1->LastResult->data, r1->LastResult->datalength);
                hostData->nonce[r1->LastResult->datalength - 1] = '\0';
            }
            else if(strncasecmp(key, "qop", (int)strlen("qop")) == 0)
            {
                hostData->qop = malloc(r1->LastResult->datalength + 1);
                if (hostData->qop == NULL) goto error;
                strncpy(hostData->qop, r1->LastResult->data, r1->LastResult->datalength);
                if (hostData->qop[r1->LastResult->datalength - 1] == '\"')
                {
                    hostData->qop[r1->LastResult->datalength - 1] = '\0';
                }
                else
                {
                    hostData->qop[r1->LastResult->datalength] = '\0';
                }
            }

            ILibDestructParserResults(r1);
            prf = prf->NextResult;
        }
        ILibDestructParserResults(r);
    }

    return 0;

error:
    if (hostData->realm != NULL) 
    {
        free(hostData->realm);
        hostData->realm = NULL;
    }
    if (hostData->nonce != NULL) 
    {
        free(hostData->nonce);
        hostData->nonce = NULL;
    }
    if (hostData->qop != NULL) 
    {
        free(hostData->qop);
        hostData->qop = NULL;
    }

    return -1;
*/
}


// Convert a private key into a usage specific key
void util_genusagekey(char* inkey, char* outkey, char usage)
{
/*
    SHA256_CTX c;
    SHA256_Init(&c);
    SHA256_Update(&c, &usage, 1);
    SHA256_Update(&c, inkey, 32);
    SHA256_Update(&c, &usage, 1);
    SHA256_Final((unsigned char*)outkey, &c);
*/
}


void util_GenerateAuthorizationHeader(void *request, char *requestType, char *uri, char *authorization, char* cnonce)
{
 /*
    char a1[MAX_TOKEN_SIZE];
    char a1Digest[MAX_TOKEN_SIZE];
    char a2[MAX_TOKEN_SIZE];
    char a2Digest[MAX_TOKEN_SIZE];
    char a3[MAX_TOKEN_SIZE];
    char a3Digest[MAX_TOKEN_SIZE];
    int tempLen = 0;
    struct HttpRequestBlock *mappingData = (struct HttpRequestBlock *)request;

    // username:realm:password
    tempLen = snprintf(a1, MAX_TOKEN_SIZE, "%s:%s:%s", mappingData->username, mappingData->realm, mappingData->password);
    util_md5hex(a1, tempLen, a1Digest);

    // GET:uri
    tempLen = snprintf(a2, MAX_TOKEN_SIZE, "%s:%s", requestType, uri);
    util_md5hex(a2, tempLen, a2Digest);

    // a1Digest:nonce:nc:cnonce:qop:a2Digest
    tempLen = snprintf(a3, MAX_TOKEN_SIZE, "%s:%s:%08x:%s:%s:%s", a1Digest, mappingData->nonce, ++mappingData->nc, cnonce, mappingData->qop, a2Digest);
    util_md5hex(a3, tempLen, a3Digest);

    snprintf(authorization, 1024, AUTHORIZATION_FIELDDATA_TEMPLATE, mappingData->username, mappingData->realm, mappingData->nonce, uri, a3Digest, mappingData->qop, mappingData->nc, cnonce);
*/
}



// Get the private session key for a given nodeid.
// Nodeid is 32 bytes, key must point to 36 bytes of free space.
void util_nodesessionkey(char* nodeid, char* key)
{
/*
    SHA256_CTX c;
    SHA256_Init(&c);
    SHA256_Update(&c, nodeid, 32);
    SHA256_Update(&c, g_SessionRandom, 32);
    SHA256_Final((unsigned char*)(key + 4), &c);
    ((unsigned int*)key)[0] = g_SessionRandomId; // Here, endianness does not matter, leave as-is for speed.
*/
}


void util_freecert(struct util_cert* cert)
{
/*
    if (cert->x509 != NULL) X509_free(cert->x509);
    if (cert->pkey != NULL) EVP_PKEY_free(cert->pkey);
    cert->x509 = NULL;
    cert->pkey = NULL;
 */   
}

int util_to_cer(struct util_cert cert, char** data)
{
/*
    *data = NULL;
    return i2d_X509(cert.x509, (unsigned char**)data);
*/
}

int util_from_cer(char* data, int datalen, struct util_cert* cert)
{
/*
    cert->x509 = NULL;
    cert->pkey = NULL;
    cert->x509 = d2i_X509(&(cert->x509), (const unsigned char**)&data, datalen);
    cert->pkey = NULL;
    return ((cert->x509) == NULL);
*/
}

int util_to_p12(struct util_cert cert, char *password, char** data)
{
/*
    PKCS12 *p12;
    int len;
    p12 = PKCS12_create(password, "Certificate", cert.pkey, cert.x509, NULL, 0,0,0,0,0);
    *data = NULL;
    len = i2d_PKCS12(p12, (unsigned char**)data);
    PKCS12_free(p12);
    return len;
*/
}

int util_from_p12(char* data, int datalen, char* password, struct util_cert* cert)
{
 /*   
    int r = 0;
    PKCS12 *p12 = NULL;
    if (data == NULL || datalen ==0) return 0;
    cert->x509 = NULL;
    cert->pkey = NULL;
    p12 = d2i_PKCS12(&p12, (const unsigned char**)&data, datalen);
    r = PKCS12_parse(p12, password, &(cert->pkey), &(cert->x509), NULL);
    PKCS12_free(p12);
    return r;
  */
}

// Add extension using V3 code: we can set the config file as NULL because we wont reference any other sections.
int util_add_ext(X509 *cert, int nid, char *value)
{
/*
    X509_EXTENSION *ex;
    X509V3_CTX ctx;
    // This sets the 'context' of the extensions. No configuration database
    X509V3_set_ctx_nodb(&ctx);
    // Issuer and subject certs: both the target since it is self signed, no request and no CRL
    X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);
    ex = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);
    if (!ex) return 0;

    X509_add_ext(cert,ex,-1);
    X509_EXTENSION_free(ex);
    return 1;
*/
}

void util_printcert(struct util_cert cert)
{
/*
    if (cert.x509 == NULL) return;
    X509_print_fp(stdout,cert.x509);
*/
}

void util_printcert_pk(struct util_cert cert)
{
/*
    if (cert.pkey == NULL) return;
    RSA_print_fp(stdout,cert.pkey->pkey.rsa,0);
*/
}

void util_sendcert(struct ILibWebServer_Session *sender, struct util_cert cert)
{
/*
    int l = 0;
    BIO *out = NULL;
    char *data;
    if (cert.x509 == NULL) return;
    out = BIO_new(BIO_s_mem());
    l = X509_print(out,cert.x509);
    l = BIO_get_mem_data(out, &data);
    ILibWebServer_StreamBody(sender, data, l, ILibAsyncSocket_MemoryOwnership_USER,0);
    BIO_free(out);
*/
}


// Creates a X509 certificate, if rootcert is NULL this creates a root (self-signed) certificate.
// Is the name parameter is NULL, the hex value of the hash of the public key will be the subject name.
int util_mkCert(struct util_cert *rootcert, struct util_cert* cert, int bits, int days, char* name, enum CERTIFICATE_TYPES certtype)
{
/*
    X509 *x = NULL;
    X509_EXTENSION *ex = NULL;
    EVP_PKEY *pk = NULL;
    RSA *rsa = NULL;
    X509_NAME *cname=NULL;
    X509 **x509p = NULL;
    EVP_PKEY **pkeyp = NULL;
    char hash[UTIL_HASHSIZE];
    char serial[8];
    char nameStr[(UTIL_HASHSIZE * 2) + 2];

    CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);

    if ((pkeyp == NULL) || (*pkeyp == NULL))
    {
    	if ((pk=EVP_PKEY_new()) == NULL)
    	{
    		abort();
    		return(0);
    	}
    }
    else
    	pk = *pkeyp;

    if ((x509p == NULL) || (*x509p == NULL))
    {
    	if ((x=X509_new()) == NULL) goto err;
    }
    else x = *x509p;

    rsa=RSA_generate_key(bits, RSA_F4, NULL, NULL);
    if (!EVP_PKEY_assign_RSA(pk, rsa))
    {
    	abort();
    	goto err;
    }
    rsa = NULL;

    util_randomtext(8, serial);
    X509_set_version(x,2);
    ASN1_STRING_set(X509_get_serialNumber(x), serial, 8);
    X509_gmtime_adj(X509_get_notBefore(x),0);
    X509_gmtime_adj(X509_get_notAfter(x),(long)60*60*24*days);
    X509_set_pubkey(x,pk);

    // Set the subject name
    cname = X509_get_subject_name(x);

    if (name == NULL)
    {
    	// Computer the hash of the public key
    	util_sha256((char*)x->cert_info->key->public_key->data, x->cert_info->key->public_key->length, hash);
    	util_tohex(hash, UTIL_HASHSIZE, nameStr);
    	X509_NAME_add_entry_by_txt(cname,"CN", MBSTRING_ASC, (unsigned char*)nameStr, -1, -1, 0);
    }
    else
    {
    	// This function creates and adds the entry, working out the correct string type and performing checks on its length. Normally we'd check the return value for errors...
    	X509_NAME_add_entry_by_txt(cname,"CN", MBSTRING_ASC, (unsigned char*)name, -1, -1, 0);
    }

    if (rootcert == NULL)
    {
    	// Its self signed so set the issuer name to be the same as the subject.
    	X509_set_issuer_name(x,cname);

    	// Add various extensions: standard extensions
    	util_add_ext(x, NID_basic_constraints, "critical,CA:TRUE");
    	util_add_ext(x, NID_key_usage, "critical,keyCertSign,cRLSign");

    	util_add_ext(x, NID_subject_key_identifier, "hash");
    	//util_add_ext(x, NID_netscape_cert_type, "sslCA");
    	//util_add_ext(x, NID_netscape_comment, "example comment extension");

    	if (!X509_sign(x,pk,EVP_sha256())) goto err;
    }
    else
    {
    	// This is a sub-certificate
    	cname=X509_get_subject_name(rootcert->x509);
    	X509_set_issuer_name(x,cname);

    	// Add usual cert stuff
    	ex = X509V3_EXT_conf_nid(NULL, NULL, NID_key_usage, "digitalSignature, keyEncipherment, keyAgreement");
    	X509_add_ext(x, ex, -1);
    	X509_EXTENSION_free(ex);

    	// Add usages: TLS server, TLS client, Intel(R) AMT Console
    	//ex = X509V3_EXT_conf_nid(NULL, NULL, NID_ext_key_usage, "TLS Web Server Authentication, TLS Web Client Authentication, 2.16.840.1.113741.1.2.1, 2.16.840.1.113741.1.2.2");
    	if (certtype == CERTIFICATE_TLS_SERVER)
    	{
    		// TLS server
    		ex = X509V3_EXT_conf_nid(NULL, NULL, NID_ext_key_usage, "TLS Web Server Authentication");
    		X509_add_ext(x, ex, -1);
    		X509_EXTENSION_free(ex);
    	}
    	else if (certtype == CERTIFICATE_TLS_CLIENT)
    	{
    		// TLS client
    		ex = X509V3_EXT_conf_nid(NULL, NULL, NID_ext_key_usage, "TLS Web Client Authentication");
    		X509_add_ext(x, ex, -1);
    		X509_EXTENSION_free(ex);
    	}

    	if (!X509_sign(x,rootcert->pkey,EVP_sha256())) goto err;
    }

    cert->x509 = x;
    cert->pkey = pk;

    return(1);
    err:
    return(0);
*/
}

int util_keyhash(struct util_cert cert, char* result)
{
/*
    if (cert.x509 == NULL) return -1;
    util_sha256((char*)(cert.x509->cert_info->key->public_key->data), cert.x509->cert_info->key->public_key->length, result);
    return 0;
*/
}

int util_keyhash2(X509* cert, char* result)
{
/*
    if (cert == NULL) return -1;
    util_sha256((char*)(cert->cert_info->key->public_key->data), cert->cert_info->key->public_key->length, result);
    return 0;
*/
}

// Perform a MD5 hash on the data
void util_md5(char* data, int datalen, char* result)
{
/*
    MD5_CTX c;
    MD5_Init(&c);
    MD5_Update(&c, data, datalen);
    MD5_Final((unsigned char*)result, &c);
*/
}

// Perform a MD5 hash on the data and convert result to HEX and store in output
// This is useful for HTTP Digest
void util_md5hex(char* data, int datalen, char *out)
{
/*
    int i = 0;
    unsigned char *temp = (unsigned char*)out;
    MD5_CTX mdContext;
    unsigned char digest[16];

    MD5_Init(&mdContext);
    MD5_Update(&mdContext, (unsigned char *)data, datalen);
    MD5_Final(digest, &mdContext);

    for(i = 0; i < HALF_NONCE_SIZE; i++)
    {
    	*(temp++) = utils_HexTable[(unsigned char)data[i] >> 4];
    	*(temp++) = utils_HexTable[(unsigned char)data[i] & 0x0F];
    }

    *temp = '\0';
*/
}

// Sign this block of data, the first 32 bytes of the block must be avaialble to add the certificate hash.
int util_sign(struct util_cert cert, char* data, int datalen, char** signature)
{
/*
    int size = 0;
    unsigned int hashsize = UTIL_HASHSIZE;
    BIO *in = NULL;
    PKCS7 *message = NULL;
    *signature = NULL;
    if (datalen <= UTIL_HASHSIZE) return 0;

    // Add hash to start of data
    X509_digest(cert.x509, EVP_sha256(), (unsigned char*)data, &hashsize);

    // Sign the block
    in = BIO_new_mem_buf(data, datalen);
    message = PKCS7_sign(cert.x509, cert.pkey, NULL, in, PKCS7_BINARY);
    if (message == NULL) return 0;
    size = i2d_PKCS7(message, (unsigned char**)signature);
    BIO_free(in);
    PKCS7_free(message);
    return size;
*/
}

// Verify the signed block, the first 32 bytes of the data must be the certificate hash to work.
int util_verify(char* signature, int signlen, struct util_cert* cert, char** data)
{
/*
    unsigned int size, r;
    BIO *out = NULL;
    PKCS7 *message = NULL;
    char* data2 = NULL;
    char hash[UTIL_HASHSIZE];
    STACK_OF(X509) *st = NULL;

    cert->x509 = NULL;
    cert->pkey = NULL;
    *data = NULL;
    message = d2i_PKCS7(NULL, (const unsigned char**)&signature, signlen);
    if (message == NULL) goto error;
    out = BIO_new(BIO_s_mem());

    // Lets rebuild the original message and check the size
    size = i2d_PKCS7(message, NULL);
    if (size < (unsigned int)signlen) goto error;

    // Check the PKCS7 signature, but not the certificate chain.
    r = PKCS7_verify(message, NULL, NULL, NULL, out, PKCS7_NOVERIFY);
    if (r == 0) goto error;

    // If data block contains less than 32 bytes, fail.
    size = BIO_get_mem_data(out, &data2);
    if (size <= UTIL_HASHSIZE) goto error;

    // Copy the data block
    *data = malloc(size+1);
    if (*data == NULL) goto error;
    memcpy(*data, data2, size);
    (*data)[size] = 0;

    // Get the certificate signer
    st = PKCS7_get0_signers(message, NULL, PKCS7_NOVERIFY);
    cert->x509 = X509_dup(sk_X509_value(st, 0));
    sk_X509_free(st);

    // Get a full certificate hash of the signer
    r = UTIL_HASHSIZE;
    X509_digest(cert->x509, EVP_sha256(), (unsigned char*)hash, &r);

    // Check certificate hash with first 32 bytes of data.
    if (memcmp(hash, *data, UTIL_HASHSIZE) != 0) goto error;

    // Approved, cleanup and return.
    BIO_free(out);
    PKCS7_free(message);

    return size;

    error:
    if (out != NULL) BIO_free(out);
    if (message != NULL) PKCS7_free(message);
    if (*data != NULL) free(*data);
    if (cert->x509 != NULL) { X509_free(cert->x509); cert->x509 = NULL; }

    return 0;
*/
}

// Encrypt a block of data for a target certificate
int util_encrypt(struct util_cert cert, char* data, int datalen, char** encdata)
{
/*
    int size = 0;
    BIO *in = NULL;
    PKCS7 *message = NULL;
    STACK_OF(X509) *encerts = NULL;
    *encdata = NULL;
    if (datalen == 0) return 0;

    // Setup certificates
    encerts = sk_X509_new_null();
    sk_X509_push(encerts,cert.x509);

    // Encrypt the block
    *encdata = NULL;
    in = BIO_new_mem_buf(data, datalen);
    message = PKCS7_encrypt(encerts, in, EVP_aes_128_cbc(), PKCS7_BINARY);
    if (message == NULL) return 0;
    size = i2d_PKCS7(message, (unsigned char**)encdata);
    BIO_free(in);
    PKCS7_free(message);
    sk_X509_free(encerts);
    return size;
*/
}

// Encrypt a block of data using multiple target certificates
int util_encrypt2( STACK_OF(X509) *certs, char* data, int datalen, char** encdata)
{
 /*
    int size = 0;
    BIO *in = NULL;
    PKCS7 *message = NULL;
    *encdata = NULL;
    if (datalen == 0) return 0;

    // Encrypt the block
    *encdata = NULL;
    in = BIO_new_mem_buf(data, datalen);
    message = PKCS7_encrypt(certs, in, EVP_aes_128_cbc(), PKCS7_BINARY);
    if (message == NULL) return 0;
    size = i2d_PKCS7(message, (unsigned char**)encdata);
    BIO_free(in);
    PKCS7_free(message);
    return size;
*/
}

// Decrypt a block of data using the specified certificate. The certificate must have a private key.
int util_decrypt(char* encdata, int encdatalen, struct util_cert cert, char** data)
{
/*
    unsigned int size, r;
    BIO *out = NULL;
    PKCS7 *message = NULL;
    char* data2 = NULL;

    *data = NULL;
    if (cert.pkey == NULL) return 0;

    message = d2i_PKCS7(NULL, (const unsigned char**)&encdata, encdatalen);
    if (message == NULL) goto error;
    out = BIO_new(BIO_s_mem());

    // Lets rebuild the original message and check the size
    size = i2d_PKCS7(message, NULL);
    if (size < (unsigned int)encdatalen) goto error;

    // Decrypt the PKCS7
    r = PKCS7_decrypt(message, cert.pkey, cert.x509, out, 0);
    if (r == 0) goto error;

    // If data block contains 0 bytes, fail.
    size = BIO_get_mem_data(out, &data2);
    if (size == 0) goto error;

    // Copy the data block
    *data = malloc(size+1);
    if (*data == NULL) goto error;
    memcpy(*data, data2, size);
    (*data)[size] = 0;

    // Cleanup and return.
    BIO_free(out);
    PKCS7_free(message);

    return size;

    error:
    if (out != NULL) BIO_free(out);
    if (message != NULL) PKCS7_free(message);
    if (*data != NULL) free(*data);
    if (data2 != NULL) free(data2);
    return 0;
*/
}




// Take a block of data and cipher it for a given key.
// The key is expected to be 36 bytes (including key identifier as for 4 bytes).
int util_cipher(char* key, char* nodeid, char* data, int datalen, char** result, int sendresponsekey)
{
/*
    	char* out;
    	int tmplen = 16;
    	int outlen = datalen + 40 + 16; // Worst case, we have to encode they session key (40) and padding (16)
    	int ptr = 44;
    	EVP_CIPHER_CTX ctx;
    	HMAC_CTX hmac;
    	unsigned int iv[4];
    	unsigned int hmaclen = 32;
    	char selfkey[40];
    	char tempkey[32];

    	// Incerement the IV and check for roll over.
    	if (g_nextiv++ == 0xFFFFFFFF)
    	{
    		// In the really rare case this roll over, lets reset our crypto keys.
    		// This may cause packets to be unreadable for a while, but things move back towards being normal.
    		util_random(UTIL_HASHSIZE, g_SessionRandom);
    		g_SessionRandomId++;
    		g_nextiv = 1;
    	}

    	// Allocate header + data + padding and fill in the header
    	if ((*result = out = malloc(44 + datalen + 40 + 16 + 32)) == NULL) return 0;
    	memcpy(out + 4, g_selfid, 32);				// 32 byte NodeID of the source
    	memcpy(out + 36, key, 4);					// 4 byte target session key identifier
    	memcpy(out + 40, &g_nextiv, 4);				// 4 byte IV salt

    	// Setup the IV
    	iv[0] = g_nextiv;
    	iv[1] = ((unsigned int*)nodeid)[0];
    	iv[2] = ((unsigned int*)nodeid)[1];
    	iv[3] = ((unsigned int*)nodeid)[2];

    	// Perform AES-128 crypto
    	EVP_CIPHER_CTX_init(&ctx);
    	util_genusagekey(key + 4, tempkey, 1); // Convert the private key into an encryption key
    	if (!EVP_EncryptInit_ex(&ctx, EVP_aes_128_cbc(), NULL, (const unsigned char *)tempkey, (const unsigned char*)iv)) goto error;

    	// Check if we need to encode the return key, if so, avoid copies and insert it into the crypto stream
    	if (sendresponsekey != 0)
    	{
    		// Computer our own return key for this now.
    		util_nodesessionkey(nodeid, selfkey + 4);
    		((unsigned short*)selfkey)[0] = PB_SESSIONKEY;
    		((unsigned short*)selfkey)[1] = 40;

    		// Encrypt the session key
    		if (!EVP_EncryptUpdate(&ctx, ((unsigned char*)out) + ptr, &outlen, (const unsigned char *)selfkey, 40)) goto error;
    		ptr += outlen;
    		outlen = datalen + 16;
    	}

    	// Finish the crypto operation
    	if (!EVP_EncryptUpdate(&ctx, (unsigned char*)(out + ptr), &outlen, (const unsigned char *)data, (int)datalen)) goto error;
    	if (!EVP_EncryptFinal_ex(&ctx, ((unsigned char*)out) + ptr + outlen, &tmplen)) goto error;
    	if (!EVP_CIPHER_CTX_cleanup(&ctx)) goto error;

    	// Setup the header
    	((unsigned short*)out)[0] = PB_AESCRYPTO;				// AES-128 block type
    	((unsigned short*)out)[1] = ptr + outlen + tmplen + 32;	// block length

    	// Perform HMAC-SHA256
    	util_genusagekey(key + 4, tempkey, 2); // Convert the private key into an integrity checking key
    	HMAC_CTX_init(&hmac);
    	HMAC_Init_ex(&hmac, tempkey, 32, EVP_sha256(), NULL);
    	HMAC_Update(&hmac, (unsigned char*)out, ptr + outlen + tmplen);
    	HMAC_Final(&hmac, (unsigned char*)(out + ptr + outlen + tmplen), &hmaclen);
    	HMAC_CTX_cleanup(&hmac);

    	// Return the total size: header + data + padding + HMAC.
    	return ptr + outlen + tmplen + 32;

    error:
    	EVP_CIPHER_CTX_cleanup(&ctx);
    	free(out);
    	*result = NULL;

    return 0;
*/
}

// Decrypt an incoming block of data
// If this packet is not encrypted correctly or uses an old key, we return zero.
int util_decipher(char* data, int datalen, char** result, char* nodeid)
{
/*
    	char* out = NULL;
    	int outlen = datalen - 44 + 16;
    	int tmplen = 16;
    	EVP_CIPHER_CTX ctx;
    	char key[36];
    	unsigned int iv[4];
    	HMAC_CTX hmac;
    	unsigned int hmaclen = 32;
    	char hmac_result[32];
    	char tempkey[32];

    	// Check pre-conditions
    	*result = NULL;
    	if (datalen < 44 + 16) return 0;									// If the data length is too short, exit.
    	if (((unsigned short*)data)[0] != 8) return 0;						// If this is not the right type, exit
    	if (((unsigned short*)data)[1] != datalen) return 0;				// If this is not the right size, exit
    	if (((unsigned int*)(data + 36))[0] != g_SessionRandomId) return 0;	// If this is not the correct key id, exit

    	// Compute the decryption key & IV
    	util_nodesessionkey(data + 4, key);
    	iv[0] = ((unsigned int*)(data + 40))[0];
    	iv[1] = ((unsigned int*)g_selfid)[0];
    	iv[2] = ((unsigned int*)g_selfid)[1];
    	iv[3] = ((unsigned int*)g_selfid)[2];

    	// Perform HMAC-SHA256 and check
    	util_genusagekey(key + 4, tempkey, 2); // Convert the private key into an integrity checking key
    	HMAC_CTX_init(&hmac);
    	HMAC_Init_ex(&hmac, tempkey, 32, EVP_sha256(), NULL);
    	HMAC_Update(&hmac, (unsigned char*)data, datalen - 32);
    	HMAC_Final(&hmac, (unsigned char*)hmac_result, &hmaclen);
    	HMAC_CTX_cleanup(&hmac);
    	if (memcmp(hmac_result, data + datalen - 32, 32) != 0) goto error;

    	// Allocate the output data buffer
    	if ((*result = out = malloc(datalen - 44 + 16 + 1000)) == NULL) return 0;

    	// Perform AES-128 decrypt
    	util_genusagekey(key + 4, tempkey, 1); // Convert the private key into an encryption key
    	EVP_CIPHER_CTX_init(&ctx);
    	if (!EVP_DecryptInit_ex(&ctx, EVP_aes_128_cbc(), NULL, (const unsigned char*)tempkey, (const unsigned char*)iv)) { EVP_CIPHER_CTX_cleanup(&ctx); goto error; }
    	if (!EVP_DecryptUpdate(&ctx, (unsigned char*)out, &outlen, (unsigned char*)(data + 44), (int)datalen - 44 - 32)) { EVP_CIPHER_CTX_cleanup(&ctx); goto error; }
    	if (!EVP_DecryptFinal_ex(&ctx, ((unsigned char *)out) + outlen, &tmplen)) { EVP_CIPHER_CTX_cleanup(&ctx); goto error; }
    	if (!EVP_CIPHER_CTX_cleanup(&ctx)) goto error;

    	// We know the source of this block
    	if (nodeid != NULL) memcpy(nodeid, data + 4, 32);

    	// Return the total size
    	return outlen + tmplen;

    error:
    	if (out != NULL) free(out);
    	*result = NULL;

    return 0;
*/
}


// Setup OpenSSL
void util_openssl_init()
{
/*
    char* tbuf[64];
#ifdef WIN32
    HMODULE g_hAdvLib = NULL;
    BOOLEAN (APIENTRY *g_CryptGenRandomPtr)(void*, ULONG) = NULL;
#endif
#ifdef _POSIX
    int l;
#endif

//	SSLeay_add_all_algorithms();
//	SSL_library_init(); // TWO LEAKS COMING FROM THIS LINE. Seems to be a well known OpenSSL problem.
//	SSL_load_error_strings();
//	ERR_load_crypto_strings(); // ONE LEAK IN LINUX

    // Add more random seeding in Windows (This is probably useful since OpenSSL in Windows has weaker seeding)
#ifdef WIN32
    RAND_screen(); // On Windows, add more random seeding using a screen dump
    if (g_hAdvLib = LoadLibrary(TEXT("ADVAPI32.DLL"))) g_CryptGenRandomPtr = (BOOLEAN (APIENTRY *)(void*,ULONG))GetProcAddress(g_hAdvLib,"SystemFunction036");
    if (g_CryptGenRandomPtr != 0 && g_CryptGenRandomPtr(tbuf, 64) != 0) RAND_add(tbuf, 64, 64); // Use this high quality random as added seeding
    if (g_hAdvLib != NULL) FreeLibrary(g_hAdvLib);
#endif

    // Add more random seeding in Linux (May be overkill since OpenSSL already uses /dev/urandom)
#ifdef _POSIX
    // Under Linux we use "/dev/urandom" if available. This is the best source of random on Linux & variants
    FILE *pFile = fopen("/dev/urandom","rb");
    if (pFile != NULL)
    {
        l = fread(tbuf, 1, 64, pFile);
        fclose(pFile);
        if (l > 0) RAND_add(tbuf, l, l);
    }
#endif
*/
}

// Cleanup OpenSSL
void util_openssl_uninit()
{
//	RAND_cleanup();
//	CRYPTO_set_dynlock_create_callback(NULL);
//	CRYPTO_set_dynlock_destroy_callback(NULL);
//	CRYPTO_set_dynlock_lock_callback(NULL);
//	CRYPTO_set_locking_callback(NULL);
//	CRYPTO_set_id_callback(NULL);
//	ERR_remove_state(0);
//	CONF_modules_unload(1);
//	ERR_free_strings();
//	EVP_cleanup();
//	CRYPTO_cleanup_all_ex_data();
//	ENGINE_cleanup();
}



