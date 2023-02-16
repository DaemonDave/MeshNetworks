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




#ifndef ___ILibAsyncUDPSocket___
#include "ILibAsyncUDPSocket.h"
#endif

#define INET_SOCKADDR_LENGTH(x) ((x==AF_INET6?sizeof(struct sockaddr_in6):sizeof(struct sockaddr_in)))
#define INET_SOCKADDR_PORT(x) (x->sa_family==AF_INET6?(unsigned short)(((struct sockaddr_in6*)x)->sin6_port):(unsigned short)(((struct sockaddr_in*)x)->sin_port))

struct ILibAsyncUDPSocket_Data
{
    void *user1;
    void *user2;

    ILibAsyncSocket_SocketModule UDPSocket;
    unsigned short BoundPortNumber;

    ILibAsyncUDPSocket_OnData OnData;
    ILibAsyncUDPSocket_OnSendOK OnSendOK;
};

void ILibAsyncUDPSocket_OnDataSink(ILibAsyncSocket_SocketModule socketModule, char* buffer, int *p_beginPointer, int endPointer,ILibAsyncSocket_OnInterrupt* OnInterrupt, void **user, int *PAUSE)
{
    struct ILibAsyncUDPSocket_Data *data = (struct ILibAsyncUDPSocket_Data*)*user;

    struct sockaddr_in6 RemoteAddress;
    int RemoteAddressSize;

    UNREFERENCED_PARAMETER( OnInterrupt );

    RemoteAddressSize = ILibAsyncSocket_GetRemoteInterface(socketModule, (struct sockaddr*)&RemoteAddress);

    if (data->OnData!=NULL)
    {
        data->OnData(
            socketModule,
            buffer,
            endPointer,
            &RemoteAddress,
            data->user1,
            data->user2,
            PAUSE);
    }
    *p_beginPointer = endPointer;
}
void ILibAsyncUDPSocket_OnSendOKSink(ILibAsyncSocket_SocketModule socketModule, void *user)
{
    struct ILibAsyncUDPSocket_Data *data = (struct ILibAsyncUDPSocket_Data*)user;
    if (data->OnSendOK!=NULL)
    {
        data->OnSendOK(socketModule, data->user1, data->user2);
    }
}

void ILibAsyncUDPSocket_OnDisconnect(ILibAsyncSocket_SocketModule socketModule, void *user)
{
    UNREFERENCED_PARAMETER( socketModule );
    free(user);
}
/*! \fn ILibAsyncUDPSocket_SocketModule ILibAsyncUDPSocket_CreateEx(void *Chain, int BufferSize, int localInterface, unsigned short localPortStartRange, unsigned short localPortEndRange, enum ILibAsyncUDPSocket_Reuse reuse, ILibAsyncUDPSocket_OnData OnData, ILibAsyncUDPSocket_OnSendOK OnSendOK, void *user)
	\brief Creates a new instance of an ILibAsyncUDPSocket module, using a random port number between \a localPortStartRange and \a localPortEndRange inclusive.
	\param Chain The chain to add this object to. (Chain must <B>not</B> not be running)
	\param BufferSize The size of the buffer to use
	\param localInterface The IP address to bind this socket to, in network order
	\param localPortStartRange The begin range to select a port number from (host order)
	\param localPortEndRange The end range to select a port number from (host order)
	\param reuse Reuse type
	\param OnData The handler to receive data
	\param OnSendOK The handler to receive notification that pending sends have completed
	\param user User object to associate with this object
	\returns The ILibAsyncUDPSocket_SocketModule handle that was created
*/
ILibAsyncUDPSocket_SocketModule ILibAsyncUDPSocket_CreateEx(void *Chain, int BufferSize, struct sockaddr *localInterface, enum ILibAsyncUDPSocket_Reuse reuse, ILibAsyncUDPSocket_OnData OnData, ILibAsyncUDPSocket_OnSendOK OnSendOK, void *user)
{
    int rv;
    int off = 0;
    SOCKET sock;
    int ra = (int)reuse;
    void *RetVal = NULL;
    struct ILibAsyncUDPSocket_Data *data;

    // Initialize the UDP socket data structure
    data = (struct ILibAsyncUDPSocket_Data*)malloc(sizeof(struct ILibAsyncUDPSocket_Data));
    if (data == NULL) return NULL;
    memset(data, 0, sizeof(struct ILibAsyncUDPSocket_Data));
    data->OnData = OnData;
    data->OnSendOK = OnSendOK;
    data->user1 = user;

    // Create a new socket & set REUSE if needed. If it's IPv6, use the same socket for both IPv4 and IPv6.
    if ((sock = socket(localInterface->sa_family, SOCK_DGRAM, IPPROTO_UDP)) == -1) 
    {
        return 0;
    }
    if (reuse == ILibAsyncUDPSocket_Reuse_SHARED) rv = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char*)&ra, sizeof(ra));
    if (localInterface->sa_family == AF_INET6) rv = setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&off, sizeof(off));

    // Attempt to bind the UDP socket
#ifdef WIN32
    if ( bind(sock, localInterface, INET_SOCKADDR_LENGTH(localInterface->sa_family)) != 0 ) 
    {
        closesocket(sock);
        return NULL;
    }
#else
    if ( bind(sock, localInterface, INET_SOCKADDR_LENGTH(localInterface->sa_family)) != 0 ) 
    {
        close(sock);
        return NULL;
    }
#endif

    // Set the BoundPortNumber
    if (localInterface->sa_family == AF_INET6) 
    {
        data->BoundPortNumber = ntohs(((struct sockaddr_in6*)localInterface)->sin6_port);
    }
    else 
    {
        data->BoundPortNumber = ntohs(((struct sockaddr_in*)localInterface)->sin_port);
    }

    // Create an Async Socket to handle the data
    RetVal = ILibCreateAsyncSocketModule(Chain, BufferSize, &ILibAsyncUDPSocket_OnDataSink, NULL, &ILibAsyncUDPSocket_OnDisconnect, &ILibAsyncUDPSocket_OnSendOKSink);
    if (RetVal == NULL)
    {
#if defined(WIN32) || defined(_WIN32_WCE)
        closesocket(sock);
#else
        close(sock);
#endif
        free(data);
        return NULL;
    }
    ILibAsyncSocket_UseThisSocket(RetVal, &sock, &ILibAsyncUDPSocket_OnDisconnect, data);
    return RetVal;
}

SOCKET ILibAsyncUDPSocket_GetSocket(ILibAsyncUDPSocket_SocketModule module)
{
    return *((SOCKET*)ILibAsyncSocket_GetSocket(module));
}

/*! \fn int ILibAsyncUDPSocket_JoinMulticastGroup(ILibAsyncUDPSocket_SocketModule module, int localInterface, int remoteInterface)
	\brief Joins a multicast group
	\param module The ILibAsyncUDPSocket_SocketModule to join the multicast group
	\param localInterface The local IP address in network order, to join the multicast group
	\param remoteInterface The multicast ip address in network order, to join
	\returns 0 = Success, Nonzero = Failure
*/
int ILibAsyncUDPSocket_JoinMulticastGroupV4(ILibAsyncUDPSocket_SocketModule module, struct sockaddr_in *multicastAddr, struct sockaddr *localAddr)
{
    struct ip_mreq mreq;
#if defined(WIN32) || defined(_WIN32_WCE)
    SOCKET s = *((SOCKET*)ILibAsyncSocket_GetSocket(module));
#else
    int s = *((int*)ILibAsyncSocket_GetSocket(module));
#endif

    // We start with the multicast structure
    memcpy(&mreq.imr_multiaddr, &(((struct sockaddr_in*)multicastAddr)->sin_addr), sizeof(mreq.imr_multiaddr));
#ifdef WIN32
    mreq.imr_interface.s_addr = ((struct sockaddr_in*)localAddr)->sin_addr.S_un.S_addr;
#else
    mreq.imr_interface.s_addr = ((struct sockaddr_in*)localAddr)->sin_addr.s_addr;
#endif
    return setsockopt(s, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char*)&mreq, sizeof(mreq));
}

int ILibAsyncUDPSocket_JoinMulticastGroupV6(ILibAsyncUDPSocket_SocketModule module, struct sockaddr_in6 *multicastAddr, int ifIndex)
{
    struct ipv6_mreq mreq6;
#if defined(WIN32) || defined(_WIN32_WCE)
    SOCKET s = *((SOCKET*)ILibAsyncSocket_GetSocket(module));
#else
    int s = *((int*)ILibAsyncSocket_GetSocket(module));
#endif

    memcpy(&mreq6.ipv6mr_multiaddr, &(((struct sockaddr_in6*)multicastAddr)->sin6_addr), sizeof(mreq6.ipv6mr_multiaddr));
    mreq6.ipv6mr_interface = ifIndex;
    return setsockopt(s, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, (char*)&mreq6, sizeof(mreq6));
}

/*! \fn int ILibAsyncUDPSocket_SetMulticastInterface(ILibAsyncUDPSocket_SocketModule module, int localInterface)
	\brief Sets the local interface to use, when multicasting
	\param module The ILibAsyncUDPSocket_SocketModule handle to set the interface on
	\param localInterface The local IP address in network order, to use when multicasting
	\returns 0 = Success, Nonzero = Failure
*/
int ILibAsyncUDPSocket_SetMulticastInterface(ILibAsyncUDPSocket_SocketModule module, struct sockaddr *localInterface)
{
#if defined(__SYMBIAN32__)
    return(0);
#else
#if !defined(_WIN32_WCE) || (defined(_WIN32_WCE) && _WIN32_WCE>=400)
#if defined(WIN32) || defined(_WIN32_WCE)
    SOCKET s = *((SOCKET*)ILibAsyncSocket_GetSocket(module));
#else
    int s = *((int*)ILibAsyncSocket_GetSocket(module));
#endif
    return(setsockopt(s, localInterface->sa_family == AF_INET6 ? IPPROTO_IPV6 : IPPROTO_IP, localInterface->sa_family == AF_INET6 ? IPV6_MULTICAST_IF : IP_MULTICAST_IF, (void*)localInterface, INET_SOCKADDR_LENGTH(localInterface->sa_family)));
#else
    return(1);
#endif
#endif
}
/*! \fn int ILibAsyncUDPSocket_SetMulticastTTL(ILibAsyncUDPSocket_SocketModule module, unsigned char TTL)
	\brief Sets the Multicast TTL value
	\param module The ILibAsyncUDPSocket_SocketModule handle to set the Multicast TTL value
	\param TTL The Multicast-TTL value to use
	\returns 0 = Success, Nonzero = Failure
*/
int ILibAsyncUDPSocket_SetMulticastTTL(ILibAsyncUDPSocket_SocketModule module, unsigned char TTL)
{
    struct sockaddr_in6 localAddress;
#if defined(__SYMBIAN32__)
    return(0);
#else
#if defined(WIN32) || defined(_WIN32_WCE)
    SOCKET s = *((SOCKET*)ILibAsyncSocket_GetSocket(module));
#else
    int s = *((int*)ILibAsyncSocket_GetSocket(module));
#endif
    ILibAsyncSocket_GetLocalInterface(module, (struct sockaddr*)&localAddress);
    return(setsockopt(s, localAddress.sin6_family == PF_INET6 ? IPPROTO_IPV6 : IPPROTO_IP, localAddress.sin6_family == PF_INET6 ? IPV6_MULTICAST_HOPS : IP_MULTICAST_TTL, (void*)&TTL, sizeof(TTL) < 0));
#endif
}

