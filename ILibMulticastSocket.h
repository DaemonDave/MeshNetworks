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


/*! \file MulticastSocket.h 
	\brief MicroStack APIs for UDP multicasting functionality
*/

#ifndef __ILibMulticastSocket__
#define __ILibMulticastSocket__

#if defined(WIN32)
	#define _CRTDBG_MAP_ALLOC
#endif

#if defined(WIN32) && !defined(_WIN32_WCE)
	#include <crtdbg.h>
#endif

#if defined(WINSOCK2)
	#include <winsock2.h>
	#include <ws2tcpip.h>
#elif defined(WINSOCK1)
	#include <winsock.h>
	#include <wininet.h>
#endif

#ifndef ___ILibAsyncUDPSocket___
#include "ILibAsyncUDPSocket.h"
#endif

#ifndef ___ILibAsyncSocket___
#include "ILibAsyncSocket.h"
#endif

#ifndef __ILibParsers__
#include "ILibParsers.h"
#endif

#ifndef ___ILibAsyncServerSocket___
#include "ILibAsyncServerSocket.h"
#endif


#define INET_SOCKADDR_LENGTH(x) ((x==AF_INET6?sizeof(struct sockaddr_in6):sizeof(struct sockaddr_in)))

typedef struct ILibMulticastSocket_StateModule
{
    void (*PreSelect)(void* object,fd_set *readset, fd_set *writeset, fd_set *errorset, int* blocktime);
    void (*PostSelect)(void* object,int slct, fd_set *readset, fd_set *writeset, fd_set *errorset);
    void (*Destroy)(void* object);

    void *Chain;
    void *UDPServer;
    void *UDPServer6;
    void *User;
    void *Tag;
    unsigned char TTL;
    unsigned short LocalPort;
    ILibAsyncUDPSocket_OnData OnData;
    unsigned int EchoCancel;

    // The IPv4 and IPv6 multicast addresses.
    struct sockaddr_in MulticastAddr;
    struct sockaddr_in6 MulticastAddr6;

    // Lists of local IPv4 and IPv6 interfaces
    struct sockaddr_in *AddressListV4;
    int AddressListLengthV4;
    int* IndexListV6;
    int IndexListLenV6;

    // Sockets used to sent and receive messages
#if defined(WIN32) || defined(_WIN32_WCE)
    SOCKET NOTIFY_SEND_socks;
    SOCKET NOTIFY_SEND_socks6;
#else
    int NOTIFY_SEND_socks;
    int NOTIFY_SEND_socks6;
#endif
}ILibMulticastSocket_StateModule_t;


ILibMulticastSocket_StateModule_t *ILibMulticastSocket_Create(void *Chain, int BufferSize, unsigned short LocalPort, struct sockaddr_in *MulticastAddr, struct sockaddr_in6 *MulticastAddr6, ILibAsyncUDPSocket_OnData OnData, void *user);
void ILibMulticastSocket_Unicast(ILibMulticastSocket_StateModule_t *module, struct sockaddr* target, char* data, int datalen);
void ILibMulticastSocket_Broadcast(ILibMulticastSocket_StateModule_t *module, char* data, int datalen, int count);
void ILibMulticastSocket_ResetMulticast(ILibMulticastSocket_StateModule_t *module, int cleanuponly);

#endif

