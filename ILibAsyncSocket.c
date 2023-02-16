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

#ifndef ___ILibAsyncSocket___
#include "ILibAsyncSocket.h"
#endif

//#ifndef WINSOCK2
//#define SOCKET unsigned int
//#endif

#define INET_SOCKADDR_LENGTH(x) ((x==AF_INET6?sizeof(struct sockaddr_in6):sizeof(struct sockaddr_in)))

#ifdef SEMAPHORE_TRACKING
#define SEM_TRACK(x) x
void AsyncSocket_TrackLock(const char* MethodName, int Occurance, void *data)
{
    char v[100];
    wchar_t wv[100];
    size_t l;

    snprintf(v, 100, "  LOCK[%s, %d] (%x)\r\n",MethodName,Occurance,data);
#ifdef WIN32
    mbstowcs_s(&l, wv, 100, v, 100);
    OutputDebugString(wv);
#else
    printf(v);
#endif
}
void AsyncSocket_TrackUnLock(const char* MethodName, int Occurance, void *data)
{
    char v[100];
    wchar_t wv[100];
    size_t l;

    snprintf(v, 100, "UNLOCK[%s, %d] (%x)\r\n",MethodName,Occurance,data);
#ifdef WIN32
    mbstowcs_s(&l, wv, 100, v, 100);
    OutputDebugString(wv);
#else
    printf(v);
#endif
}
#else
#define SEM_TRACK(x)
#endif

struct ILibAsyncSocket_SendData
{
    char* buffer;
    int bufferSize;
    int bytesSent;

    struct sockaddr_in6 remoteAddress;

    int UserFree;
    struct ILibAsyncSocket_SendData *Next;
};

struct ILibAsyncSocketModule
{
    void (*PreSelect)(void* object,fd_set *readset, fd_set *writeset, fd_set *errorset, int* blocktime);
    void (*PostSelect)(void* object,int slct, fd_set *readset, fd_set *writeset, fd_set *errorset);
    void (*Destroy)(void* object);
    void *Chain;

    unsigned int PendingBytesToSend;
    unsigned int TotalBytesSent;

#if defined(_WIN32_WCE) || defined(WIN32)
    SOCKET internalSocket;
#elif defined(_POSIX)
    int internalSocket;
#endif

    // The IPv4/IPv6 compliant address of the remote endpoint. We are not going to be using IPv6 all the time,
    // but we use the IPv6 structure to allocate the meximum space we need.
    struct sockaddr_in6 RemoteAddress;

    // Local interface of a given socket. This module will bind to any interface, but the actual interface used
    // is stored here.
    struct sockaddr_in6 LocalAddress;

    // Apparently used to store the multicast address when using a UDP multicast socket.
    struct sockaddr_in6 LocalAddress2;

    // Source address. Here is stored the actual source of a packet, usualy used with UDP where the source
    // of the traffic changes.
    struct sockaddr_in6 SourceAddress;

    ILibAsyncSocket_OnData OnData;
    ILibAsyncSocket_OnConnect OnConnect;
    ILibAsyncSocket_OnDisconnect OnDisconnect;
    ILibAsyncSocket_OnSendOK OnSendOK;
    ILibAsyncSocket_OnInterrupt OnInterrupt;

    ILibAsyncSocket_OnBufferSizeExceeded OnBufferSizeExceeded;
    ILibAsyncSocket_OnBufferReAllocated OnBufferReAllocated;

    void *LifeTime;
    void *user;
    int PAUSE;
    int FinConnect;
    int SSLConnect;
    int BeginPointer;
    int EndPointer;
    char* buffer;
    int MallocSize;
    int InitialSize;

    struct ILibAsyncSocket_SendData *PendingSend_Head;
    struct ILibAsyncSocket_SendData *PendingSend_Tail;
    sem_t SendLock;

    int MaxBufferSize;
    int MaxBufferSizeExceeded;
    void *MaxBufferSizeUserObject;

    // Added for TLS support
    SSL* ssl;
    int  sslstate;
    BIO* sslbio;
    SSL_CTX *ssl_ctx;
};

void ILibAsyncSocket_PostSelect(void* object,int slct, fd_set *readset, fd_set *writeset, fd_set *errorset);
void ILibAsyncSocket_PreSelect(void* object,fd_set *readset, fd_set *writeset, fd_set *errorset, int* blocktime);

//
// An internal method called by Chain as Destroy, to cleanup AsyncSocket
//
// <param name="socketModule">The AsyncSocketModule</param>
void ILibAsyncSocket_Destroy(void *socketModule)
{
    struct ILibAsyncSocketModule* module = (struct ILibAsyncSocketModule*)socketModule;
    struct ILibAsyncSocket_SendData *temp, *current;

    // Call the interrupt event if necessary
    if (!ILibAsyncSocket_IsFree(module))
    {
        if (module->OnInterrupt != NULL) module->OnInterrupt(module, module->user);
    }

    // If this is an SSL socket, free the SSL state
    if (module->ssl != NULL)
    {
        SSL_free(module->ssl); // Frees SSL session and BIO buffer at the same time
        module->ssl = NULL;
        module->sslstate = 0;
        module->sslbio = NULL;
    }

    // Close socket if necessary
    if (module->internalSocket != ~0)
    {
#if defined(_WIN32_WCE) || defined(WIN32)
#if defined(WINSOCK2)
        shutdown(module->internalSocket, SD_BOTH);
#endif
        closesocket(module->internalSocket);
#elif defined(_POSIX)
        shutdown(module->internalSocket,SHUT_RDWR);
        close(module->internalSocket);
#endif
        module->internalSocket = (SOCKET)~0;
    }

    // Free the buffer if necessary
    if (module->buffer != NULL)
    {
        free(module->buffer);
        module->buffer = NULL;
        module->MallocSize = 0;
    }

    // Clear all the data that is pending to be sent
    temp = current = module->PendingSend_Head;
    while (current != NULL)
    {
        temp = current->Next;
        if (current->UserFree == 0) free(current->buffer);
        free(current);
        current = temp;
    }

    module->FinConnect = 0;
    module->SSLConnect = 0;
    module->sslstate = 0;
    sem_destroy(&(module->SendLock));
}
/*! \fn ILibAsyncSocket_SetReAllocateNotificationCallback(ILibAsyncSocket_SocketModule AsyncSocketToken, ILibAsyncSocket_OnBufferReAllocated Callback)
\brief Set the callback handler for when the internal data buffer has been resized
\param AsyncSocketToken The specific connection to set the callback with
\param Callback The callback handler to set
*/
void ILibAsyncSocket_SetReAllocateNotificationCallback(ILibAsyncSocket_SocketModule AsyncSocketToken, ILibAsyncSocket_OnBufferReAllocated Callback)
{
    if (AsyncSocketToken != NULL) 
    {
        ((struct ILibAsyncSocketModule*)AsyncSocketToken)->OnBufferReAllocated = Callback;
    }
}

/*! \fn ILibCreateAsyncSocketModule(void *Chain, int initialBufferSize, ILibAsyncSocket_OnData OnData, ILibAsyncSocket_OnConnect OnConnect, ILibAsyncSocket_OnDisconnect OnDisconnect,ILibAsyncSocket_OnSendOK OnSendOK)
\brief Creates a new AsyncSocketModule
\param Chain The chain to add this module to. (Chain must <B>not</B> be running)
\param initialBufferSize The initial size of the receive buffer
\param OnData Function Pointer that triggers when Data is received
\param OnConnect Function Pointer that triggers upon successfull connection establishment
\param OnDisconnect Function Pointer that triggers upon disconnect
\param OnSendOK Function Pointer that triggers when pending sends are complete
\returns An ILibAsyncSocket token
*/
ILibAsyncSocket_SocketModule ILibCreateAsyncSocketModule(void *Chain, int initialBufferSize, ILibAsyncSocket_OnData OnData, ILibAsyncSocket_OnConnect OnConnect, ILibAsyncSocket_OnDisconnect OnDisconnect, ILibAsyncSocket_OnSendOK OnSendOK)
{
    struct ILibAsyncSocketModule *RetVal = (struct ILibAsyncSocketModule*)malloc(sizeof(struct ILibAsyncSocketModule));
    if (RetVal == NULL) return NULL;
    memset(RetVal, 0, sizeof(struct ILibAsyncSocketModule));
    if ((RetVal->buffer = (char*)malloc(initialBufferSize)) == NULL) ILIBCRITICALEXIT(254);
    RetVal->PreSelect = &ILibAsyncSocket_PreSelect;
    RetVal->PostSelect = &ILibAsyncSocket_PostSelect;
    RetVal->Destroy = &ILibAsyncSocket_Destroy;
    RetVal->internalSocket = (SOCKET)~0;
    RetVal->OnData = OnData;
    RetVal->OnConnect = OnConnect;
    RetVal->OnDisconnect = OnDisconnect;
    RetVal->OnSendOK = OnSendOK;
    RetVal->InitialSize = initialBufferSize;
    RetVal->MallocSize = initialBufferSize;
    RetVal->LifeTime = ILibGetBaseTimer(Chain); //ILibCreateLifeTime(Chain);

    sem_init(&(RetVal->SendLock),0,1);

    RetVal->Chain = Chain;
    ILibAddToChain(Chain, RetVal);

    return((void*)RetVal);
}

/*! \fn ILibAsyncSocket_ClearPendingSend(ILibAsyncSocket_SocketModule socketModule)
\brief Clears all the pending data to be sent for an AsyncSocket
\param socketModule The ILibAsyncSocket to clear
*/
void ILibAsyncSocket_ClearPendingSend(ILibAsyncSocket_SocketModule socketModule)
{
    struct ILibAsyncSocketModule *module = (struct ILibAsyncSocketModule*)socketModule;
    struct ILibAsyncSocket_SendData *data, *temp;

    data = module->PendingSend_Head;
    module->PendingSend_Tail = NULL;
    while (data != NULL)
    {
        temp = data->Next;
        // We only need to free this if we have ownership of this memory
        if (data->UserFree == 0) free(data->buffer);
        free(data);
        data = temp;
    }
    module->PendingSend_Head = NULL;
    module->PendingBytesToSend = 0;
}

/*! \fn ILibAsyncSocket_SendTo(ILibAsyncSocket_SocketModule socketModule, char* buffer, int length, int remoteAddress, unsigned short remotePort, enum ILibAsyncSocket_MemoryOwnership UserFree)
\brief Sends data on an AsyncSocket module to a specific destination. (Valid only for <B>UDP</B>)
\param socketModule The ILibAsyncSocket module to send data on
\param buffer The buffer to send
\param length The length of the buffer to send
\param remoteAddress The IPAddress of the destination
\param remotePort The Port number of the destination
\param UserFree Flag indicating memory ownership.
\returns \a ILibAsyncSocket_SendStatus indicating the send status
*/
enum ILibAsyncSocket_SendStatus ILibAsyncSocket_SendTo(ILibAsyncSocket_SocketModule socketModule, char* buffer, int length, struct sockaddr *remoteAddress, enum ILibAsyncSocket_MemoryOwnership UserFree)
{
    struct ILibAsyncSocketModule *module = (struct ILibAsyncSocketModule*)socketModule;
    struct ILibAsyncSocket_SendData *data;
    int unblock = 0;
    int bytesSent;

    // If the socket is empty, return now.
    if (socketModule == NULL) return(ILibAsyncSocket_SEND_ON_CLOSED_SOCKET_ERROR);

    // Setup a new send data structure
    if ((data = (struct ILibAsyncSocket_SendData*)malloc(sizeof(struct ILibAsyncSocket_SendData))) == NULL) ILIBCRITICALEXIT(254);
    memset(data,0,sizeof(struct ILibAsyncSocket_SendData));
    data->buffer = buffer;
    data->bufferSize = length;
    data->bytesSent = 0;
    data->UserFree = UserFree;
    data->Next = NULL;

    // Copy the address to the send data structure
    memset(&(data->remoteAddress), 0, sizeof(struct sockaddr_in6));
    if (remoteAddress != NULL) memcpy(&(data->remoteAddress), remoteAddress, INET_SOCKADDR_LENGTH(remoteAddress->sa_family));

    SEM_TRACK(AsyncSocket_TrackLock("ILibAsyncSocket_Send", 1, module);)
    sem_wait(&(module->SendLock));

    if (module->internalSocket == ~0)
    {
        // Too Bad, the socket closed
        if (UserFree == 0) 
        {
            free(buffer);
        }
        free(data);
        SEM_TRACK(AsyncSocket_TrackUnLock("ILibAsyncSocket_Send", 2, module);)
        sem_post(&(module->SendLock));
        return(ILibAsyncSocket_SEND_ON_CLOSED_SOCKET_ERROR);
    }

    module->PendingBytesToSend += length;
    if (module->PendingSend_Tail!=NULL)
    {
        // There are still bytes that are pending to be sent, so we need to queue this up
        module->PendingSend_Tail->Next = data;
        module->PendingSend_Tail = data;
        unblock = 1;
        if (UserFree == ILibAsyncSocket_MemoryOwnership_USER)
        {
            // If we don't own this memory, we need to copy the buffer,
            // because the user may free this memory before we have a chance to send it
            if ((data->buffer = (char*)malloc(data->bufferSize)) == NULL) ILIBCRITICALEXIT(254);
            memcpy(data->buffer, buffer, length);
            MEMCHECK(assert(length <= data->bufferSize);)
            data->UserFree = ILibAsyncSocket_MemoryOwnership_CHAIN;
        }
    }
    else
    {
        // There is no data pending to be sent, so lets go ahead and try to send it
        module->PendingSend_Tail = data;
        module->PendingSend_Head = data;

        if (module->ssl != NULL || remoteAddress == NULL)
        {
            if (module->ssl == NULL)
            {
                // Send on non-SSL socket, set MSG_NOSIGNAL since we don't want to get Broken Pipe signals in Linux, ignored if Windows.
                bytesSent = send(module->internalSocket, module->PendingSend_Head->buffer+module->PendingSend_Head->bytesSent, module->PendingSend_Head->bufferSize-module->PendingSend_Head->bytesSent, MSG_NOSIGNAL);
            }
            else
            {
                // Send on SSL socket, set MSG_NOSIGNAL since we don't want to get Broken Pipe signals in Linux, ignored if Windows.
                bytesSent = SSL_write(module->ssl, module->PendingSend_Head->buffer+module->PendingSend_Head->bytesSent, module->PendingSend_Head->bufferSize-module->PendingSend_Head->bytesSent);
            }
        }
        else
        {
            bytesSent = sendto(module->internalSocket, module->PendingSend_Head->buffer+module->PendingSend_Head->bytesSent, module->PendingSend_Head->bufferSize-module->PendingSend_Head->bytesSent, MSG_NOSIGNAL, (struct sockaddr*)remoteAddress, INET_SOCKADDR_LENGTH(remoteAddress->sa_family));
        }
        if (bytesSent != -1 && bytesSent != module->PendingSend_Head->bufferSize-module->PendingSend_Head->bytesSent)
        {
            // Partial send
            bytesSent = SSL_get_error(module->ssl, bytesSent);
        }

        if (bytesSent > 0)
        {
            // We were able to send something, so lets increment the counters
            module->PendingSend_Head->bytesSent += bytesSent;
            module->PendingBytesToSend -= bytesSent;
            module->TotalBytesSent += bytesSent;
        }

        if (bytesSent == -1 && module->ssl != NULL)
        {
            // OpenSSL returned an error
            bytesSent = SSL_get_error(module->ssl, bytesSent);
            if (bytesSent != SSL_ERROR_WANT_WRITE && bytesSent != SSL_ERROR_SSL) // "bytesSent != SSL_ERROR_SSL" portion is weird, but if not present, flowcontrol fails.
            {
                // Most likely the socket closed while we tried to send
                if (UserFree == 0) 
                {
                    free(buffer);
                }
                module->PendingSend_Head = module->PendingSend_Tail = NULL;
                free(data);
                SEM_TRACK(AsyncSocket_TrackUnLock("ILibAsyncSocket_Send",3,module);)
                sem_post(&(module->SendLock));

                // Ensure Calling On_Disconnect with MicroStackThread
                ILibLifeTime_Add(module->LifeTime, socketModule, 0, &ILibAsyncSocket_Disconnect, NULL);

                return(ILibAsyncSocket_SEND_ON_CLOSED_SOCKET_ERROR);
            }
        }
        if (bytesSent == -1 && module->ssl == NULL)
        {
            // Send returned an error, so lets figure out what it was, as it could be normal
#if defined(_WIN32_WCE) || defined(WIN32)
            bytesSent = WSAGetLastError();
            if (bytesSent != WSAEWOULDBLOCK)
#elif defined(_POSIX)
            if (errno!=EWOULDBLOCK)
#endif
            {
                // Most likely the socket closed while we tried to send
                if (UserFree == 0) 
                {
                    free(buffer);
                }
                module->PendingSend_Head = module->PendingSend_Tail = NULL;
                free(data);
                SEM_TRACK(AsyncSocket_TrackUnLock("ILibAsyncSocket_Send", 3, module);)
                sem_post(&(module->SendLock));

                // Ensure Calling On_Disconnect with MicroStackThread
                ILibLifeTime_Add(module->LifeTime, socketModule, 0, &ILibAsyncSocket_Disconnect, NULL);

                return(ILibAsyncSocket_SEND_ON_CLOSED_SOCKET_ERROR);
            }
        }
        if (module->PendingSend_Head->bytesSent == module->PendingSend_Head->bufferSize)
        {
            // All of the data has been sent
            if (UserFree == 0) 
            {
                free(module->PendingSend_Head->buffer);
            }
            module->PendingSend_Tail = NULL;
            free(module->PendingSend_Head);
            module->PendingSend_Head = NULL;
        }
        else
        {
            // All of the data wasn't sent, so we need to copy the buffer
            // if we don't own the memory, because the user may free the
            // memory, before we have a chance to complete sending it.
            if (UserFree == ILibAsyncSocket_MemoryOwnership_USER)
            {
                if ((data->buffer = (char*)malloc(data->bufferSize)) == NULL) ILIBCRITICALEXIT(254);
                memcpy(data->buffer,buffer,length);
                MEMCHECK(assert(length <= data->bufferSize);)
                data->UserFree = ILibAsyncSocket_MemoryOwnership_CHAIN;
            }
            unblock = 1;
        }

    }
    SEM_TRACK(AsyncSocket_TrackUnLock("ILibAsyncSocket_Send", 4, module);)
    sem_post(&(module->SendLock));
    if (unblock!=0) 
    {
        ILibForceUnBlockChain(module->Chain);
    }
    return(unblock);
}

/*! \fn ILibAsyncSocket_Disconnect(ILibAsyncSocket_SocketModule socketModule)
\brief Disconnects an ILibAsyncSocket
\param socketModule The ILibAsyncSocket to disconnect
*/
void ILibAsyncSocket_Disconnect(ILibAsyncSocket_SocketModule socketModule)
{
#if defined(_WIN32_WCE) || defined(WIN32)
    SOCKET s;
#else
    int s;
#endif
    SSL *wasssl;

    struct ILibAsyncSocketModule *module = (struct ILibAsyncSocketModule*)socketModule;

    SEM_TRACK(AsyncSocket_TrackLock("ILibAsyncSocket_Disconnect", 1, module);)
    sem_wait(&(module->SendLock));

    wasssl = module->ssl;
    if (module->ssl != NULL)
    {
        sem_post(&(module->SendLock));
        SSL_free(module->ssl); // Frees SSL session and both BIO buffers at the same time
        sem_wait(&(module->SendLock));
        module->ssl = NULL;
        module->sslstate = 0;
        module->sslbio = NULL;
    }

    if (module->internalSocket != ~0)
    {
        // There is an associated socket that is still valid, so we need to close it
        module->PAUSE = 1;
        s = module->internalSocket;
        module->internalSocket = (SOCKET)~0;
        if (s != -1)
        {
#if defined(_WIN32_WCE) || defined(WIN32)
#if defined(WINSOCK2)
            shutdown(s,SD_BOTH);
#endif
            closesocket(s);
#elif defined(_POSIX)
            shutdown(s,SHUT_RDWR);
            close(s);
#endif
        }

        // Since the socket is closing, we need to clear the data that is pending to be sent
        ILibAsyncSocket_ClearPendingSend(socketModule);
        SEM_TRACK(AsyncSocket_TrackUnLock("ILibAsyncSocket_Disconnect", 2, module);)
        sem_post(&(module->SendLock));

        if (wasssl == NULL)
        {
            // This was a normal socket, fire the event notifying the user. Depending on connection state, we event differently
            if (module->FinConnect == 0 && module->OnConnect != NULL) 
            {
                module->OnConnect(module, 0, module->user);    // Connection Failed
            }
            if (module->FinConnect != 0 && module->OnDisconnect != NULL) 
            {
                module->OnDisconnect(module, module->user);    // Socket Disconnected
            }
        }
        else
        {
            // This was a SSL socket, fire the event notifying the user. Depending on connection state, we event differently
            if (module->SSLConnect == 0 && module->OnConnect != NULL) 
            {
                module->OnConnect(module, 0, module->user);    // Connection Failed
            }
            if (module->SSLConnect != 0 && module->OnDisconnect != NULL) 
            {
                module->OnDisconnect(module, module->user);    // Socket Disconnected
            }
        }
        module->FinConnect = 0;
        module->SSLConnect = 0;
        module->sslstate = 0;
    }
    else
    {
        SEM_TRACK(AsyncSocket_TrackUnLock("ILibAsyncSocket_Disconnect", 3, module);)
        sem_post(&(module->SendLock));
    }
}

void ILibProcessAsyncSocket(struct ILibAsyncSocketModule *Reader, int pendingRead);
//void ILibAsyncSocket_HandleDelayedCiraWrite(struct ILibAsyncSocketModule *module);
void ILibAsyncSocket_Callback(ILibAsyncSocket_SocketModule socketModule, int connectDisconnectReadWrite)
{
    if (socketModule != NULL)
    {
        struct ILibAsyncSocketModule *module = (struct ILibAsyncSocketModule*)socketModule;
        if (connectDisconnectReadWrite == 0) // Connected
        {
            memset(&(module->LocalAddress), 0, sizeof(struct sockaddr_in6));

            module->FinConnect = 1;
            module->PAUSE = 0;

            if (module->ssl != NULL)
            {
                // If SSL enabled, we need to complete the SSL handshake before we tell the application we are connected.
                SSL_connect(module->ssl);
            }
            else
            {
                // No SSL, tell application we are connected.
                module->OnConnect(module, -1, module->user);
            }
        }
        else if (connectDisconnectReadWrite == 1) // Disconnected
            ILibAsyncSocket_Disconnect(module);
        else if (connectDisconnectReadWrite == 2) // Data read
            ILibProcessAsyncSocket(module, 1);
    }
}


/*! \fn ILibAsyncSocket_ConnectTo(ILibAsyncSocket_SocketModule socketModule, int localInterface, int remoteInterface, int remotePortNumber, ILibAsyncSocket_OnInterrupt InterruptPtr,void *user)
\brief Attempts to establish a TCP connection
\param socketModule The ILibAsyncSocket to initiate the connection
\param localInterface The interface to use to establish the connection
\param remoteInterface The remote interface to connect to
\param remotePortNumber The remote port to connect to
\param InterruptPtr Function Pointer that triggers if connection attempt is interrupted
\param user User object that will be passed to the \a OnConnect method
*/
void ILibAsyncSocket_ConnectTo(void* socketModule, struct sockaddr *localInterface, struct sockaddr *remoteAddress, ILibAsyncSocket_OnInterrupt InterruptPtr, void *user)
{
    int flags = 1;
    char *tmp;
    struct ILibAsyncSocketModule *module = (struct ILibAsyncSocketModule*)socketModule;

    // If there is something going on and we try to connect using this socket, fail! This is not supposed to happen.
    if (module->internalSocket != -1) 
    {
        PRINTERROR();
        ILIBCRITICALEXIT2(253, module->internalSocket);
    }

    // Clean up
    memset(&(module->RemoteAddress), 0, sizeof(struct sockaddr_in6));
    memset(&(module->LocalAddress), 0, sizeof(struct sockaddr_in6));
    memset(&(module->LocalAddress2), 0, sizeof(struct sockaddr_in6));
    memset(&(module->SourceAddress), 0, sizeof(struct sockaddr_in6));

    // Setup
    memcpy(&(module->RemoteAddress), remoteAddress, INET_SOCKADDR_LENGTH(remoteAddress->sa_family));
    module->PendingBytesToSend = 0;
    module->TotalBytesSent = 0;
    module->PAUSE = 0;
    module->user = user;
    module->OnInterrupt = InterruptPtr;
    if ((tmp = (char*)realloc(module->buffer, module->InitialSize)) == NULL) ILIBCRITICALEXIT(254);
    module->buffer = tmp;
    module->MallocSize = module->InitialSize;

    // The local port should always be zero
#ifdef _DEBUG
    if (localInterface->sa_family == AF_INET && ((struct sockaddr_in*)localInterface)->sin_port != 0) 
    {
        PRINTERROR();
        ILIBCRITICALEXIT(253);
    }
    if (localInterface->sa_family == AF_INET6 && ((struct sockaddr_in*)localInterface)->sin_port != 0) 
    {
        PRINTERROR();
        ILIBCRITICALEXIT(253);
    }
#endif

    // Allocate a new socket
    if ((module->internalSocket = ILibGetSocket(localInterface, SOCK_STREAM, IPPROTO_TCP)) == 0) 
    {
        PRINTERROR();
        ILIBCRITICALEXIT(253);
    }

    // Initialise the buffer pointers, since no data is in them yet.
    module->FinConnect = 0;
    module->SSLConnect = 0;
    module->sslstate = 0;
    module->BeginPointer = 0;
    module->EndPointer = 0;

    // Set the socket to non-blocking mode, because we need to play nice and share the MicroStack thread
#if defined(_WIN32_WCE) || defined(WIN32)
    ioctlsocket(module->internalSocket, FIONBIO, (u_long *)(&flags));
#elif defined(_POSIX)
    flags = fcntl(module->internalSocket, F_GETFL,0);
    fcntl(module->internalSocket, F_SETFL, O_NONBLOCK | flags);
#endif

    // Turn on keep-alives for the socket
    setsockopt(module->internalSocket, SOL_SOCKET, SO_KEEPALIVE, (char*)&flags, sizeof(flags));

    // Connect the socket, and force the chain to unblock, since the select statement doesn't have us in the fdset yet.
    if (connect(module->internalSocket, (struct sockaddr*)remoteAddress, INET_SOCKADDR_LENGTH(remoteAddress->sa_family)) != -1) 
    {
        PRINTERROR();
        ILIBCRITICALEXIT(253);
    }

#ifdef _DEBUG
#ifdef _POSIX
    if (errno != EINPROGRESS) 
    {
        PRINTERROR();    // The result of the connect should always be "WOULD BLOCK" on Linux. (TODO: This was triggered in Linux!)
        ILIBCRITICALEXIT2(253, errno);
    }
#endif
#ifdef WIN32
    if (GetLastError() != WSAEWOULDBLOCK)
    {
        PRINTERROR();
        ILIBCRITICALEXIT2(253, GetLastError());  // The result of the connect should always be "WOULD BLOCK" on Windows.
    }
#endif
#endif

    ILibForceUnBlockChain(module->Chain);
}

//
// Internal method called when data is ready to be processed on an ILibAsyncSocket
//
// <param name="Reader">The ILibAsyncSocket with pending data</param>
void ILibProcessAsyncSocket(struct ILibAsyncSocketModule *Reader, int pendingRead)
{
    int ssllen;
    int sslstate;
    int sslerror;
    int iBeginPointer = 0;
    int iEndPointer = 0;
    int iPointer = 0;
    int bytesReceived = 0;
    int len;
    SSL *wasssl;
    char *temp;

    //
    // If the thing isn't paused, and the user set the pointers such that we still have data
    // in our buffers, we need to call the user back with that data, before we attempt to read
    // more data off the network
    //
    if (!pendingRead)
    {
        if (Reader->internalSocket != ~0 && Reader->PAUSE <= 0 && Reader->BeginPointer != Reader->EndPointer)
        {
            iBeginPointer = Reader->BeginPointer;
            iEndPointer = Reader->EndPointer;
            iPointer = 0;

            while (Reader->internalSocket != ~0 && Reader->PAUSE <= 0 && Reader->BeginPointer != Reader->EndPointer && Reader->EndPointer != 0)
            {
                Reader->EndPointer = Reader->EndPointer-Reader->BeginPointer;
                Reader->BeginPointer = 0;
                if (Reader->OnData != NULL)
                {
                    Reader->OnData(Reader, Reader->buffer + iBeginPointer, &(iPointer), Reader->EndPointer, &(Reader->OnInterrupt), &(Reader->user), &(Reader->PAUSE));
                }
                iBeginPointer += iPointer;
                Reader->EndPointer -= iPointer;
                if (iPointer == 0) break;
                iPointer = 0;
            }
            Reader->BeginPointer = iBeginPointer;
            Reader->EndPointer = iEndPointer;
        }
    }

    // Reading Body Only
    if (Reader->BeginPointer == Reader->EndPointer)
    {
        Reader->BeginPointer = 0;
        Reader->EndPointer = 0;
    }
    if (!pendingRead || Reader->PAUSE > 0) return;

    //
    // If we need to grow the buffer, do it now
    //
    if (bytesReceived > (Reader->MallocSize - Reader->EndPointer) || 1024 > (Reader->MallocSize - Reader->EndPointer))// the 1st portion is for ssl & cd
    {
        //
        // This memory reallocation sometimes causes Insure++
        // to incorrectly report a READ_DANGLING (usually in
        // a call to ILibWebServer_StreamHeader_Raw.)
        //
        // We verified that the problem is with Insure++ by
        // noting the value of 'temp' (0x008fa8e8),
        // 'Reader->buffer' (0x00c55e80), and
        // 'MEMORYCHUNKSIZE' (0x00001800).
        //
        // When Insure++ reported the error, it (incorrectly)
        // claimed that a pointer to memory address 0x00c55ea4
        // was invalid, while (correctly) citing the old memory
        // (0x008fa8e8-0x008fb0e7) as freed memory.
        // Normally Insure++ reports that the invalid pointer
        // is pointing to someplace in the deallocated block,
        // but that wasn't the case.
        //
        if (Reader->MaxBufferSize == 0 || Reader->MallocSize < Reader->MaxBufferSize)
        {
            if (Reader->MaxBufferSize > 0 && (Reader->MaxBufferSize - Reader->MallocSize < MEMORYCHUNKSIZE))
            {
                Reader->MallocSize = Reader->MaxBufferSize;
            }
            else if (bytesReceived > 0)
            {
                Reader->MallocSize += bytesReceived - (Reader->MallocSize - Reader->EndPointer);
            }
            else
            {
                Reader->MallocSize += MEMORYCHUNKSIZE;
            }

            temp = Reader->buffer;
            Reader->buffer = (char*)realloc(Reader->buffer, Reader->MallocSize);
            //
            // If this realloc moved the buffer somewhere, we need to inform people of it
            //
            if (Reader->buffer != temp && Reader->OnBufferReAllocated != NULL) Reader->OnBufferReAllocated(Reader, Reader->user, Reader->buffer-temp);
        }
        else
        {
            //
            // If we grow the buffer anymore, it will exceed the maximum allowed buffer size
            //
            Reader->MaxBufferSizeExceeded = 1;
            if (Reader->OnBufferSizeExceeded != NULL) Reader->OnBufferSizeExceeded(Reader, Reader->MaxBufferSizeUserObject);
            ILibAsyncSocket_Disconnect(Reader);
            return;
        }
    }
    else if (Reader->BeginPointer != 0 && bytesReceived == 0)
    {
        //
        // We can save some cycles by moving the data back to the top
        // of the buffer, instead of just allocating more memory.
        //
        temp = Reader->buffer + Reader->BeginPointer;;
        memmove(Reader->buffer, temp, Reader->EndPointer-Reader->BeginPointer);
        Reader->EndPointer -= Reader->BeginPointer;
        Reader->BeginPointer = 0;

        //
        // Even though we didn't allocate new memory, we still moved data in the buffer,
        // so we need to inform people of that, because it might be important
        //
        if (Reader->OnBufferReAllocated != NULL) Reader->OnBufferReAllocated(Reader, Reader->user, temp-Reader->buffer);
    }

    if (Reader->ssl != NULL)
    {
        // Read data off the SSL socket.

        // Now we will tell OpenSSL to process that data in the steam. This read may return nothing, but OpenSSL may
        // put data in the output buffer to be sent back out.
        bytesReceived = 0;
        do
        {
            // Read data from the SSL socket, this will read one SSL record at a time.
            ssllen = SSL_read(Reader->ssl, Reader->buffer+Reader->EndPointer+bytesReceived, Reader->MallocSize-Reader->EndPointer-bytesReceived);
            if (ssllen > 0) bytesReceived += ssllen;
        }
        while (ssllen > 0);

        //printf("SSL READ: LastLen = %d, Total = %d, State = %d, Error = %d\r\n", ssllen, bytesReceived, sslstate, sslerror);

        // Read the current SSL error
        sslerror = SSL_get_error(Reader->ssl, ssllen);
        if (sslerror != SSL_ERROR_WANT_READ)
        {
#ifdef WIN32
            if (sslerror == SSL_ERROR_SYSCALL && GetLastError() == 0) return; // This is a special Windows case, bit of a mistery, but it happens.
#endif

            // There is no more data on the socket, shut it down.
            Reader->sslstate = 0;
            bytesReceived = -1;
        }
        //! \note this is the SSLeay OpenSSL function call that is incompatible with V3.0 OpenSSL 
        //! I didn't figure out which are the state variables with mystery "3"
        //! If mystery "3" crashes this is the \fn call that caused it.
        // old code
        //sslstate = SSL_state(Reader->ssl);
        /// new code
        // Reader->state; ?? Alternative variable ?? SSL_get_state(Reader->ssl) from  OpenSSL 3.0  new ssl.h
        sslstate = SSL_get_state(Reader->ssl); // ?? Alternative variable ??
        if (Reader->sslstate != 3 && sslstate == 3) //! \note SSL_ST_OK			0x03 from old OpenSSLeay mismatches new  OpenSSL 3.0   SSL_ST_CONNECT	0x1000  && SSL_ST_ACCEPT	0x2000
        {
            // If the SSL state changed to connected, we need to tell the application about the connection.
            Reader->sslstate = 3;
            if (Reader->SSLConnect == 0) // This is still a mistery, but if this check is not present, it's possible to signal connect more than once.
            {
                Reader->SSLConnect = 1;
                if (Reader->OnConnect != NULL) Reader->OnConnect(Reader, -1, Reader->user);
            }
        }
        if (bytesReceived == 0)
        {
            // We received no data, lets investigate why
            if (ssllen == 0 && bytesReceived == 0)
            {
                // There is no more data on the socket, shut it down.
                Reader->sslstate = 0;
                bytesReceived = -1;
            }
            else if (ssllen == -1 && sslstate == 0x2112)
            {
                // There is no more data on the socket, shut it down.
                Reader->sslstate = 0;
                bytesReceived = -1;
            }
            else return;
        }
    }
    else
    {
        // Read data off the non-SSL, generic socket.

        // Set the receive address buffer size and read from the socket.
        len = sizeof(struct sockaddr_in6);
#if defined(WINSOCK2)
        bytesReceived = recvfrom(Reader->internalSocket, Reader->buffer+Reader->EndPointer, Reader->MallocSize-Reader->EndPointer, 0, (struct sockaddr*)&(Reader->SourceAddress), (int*)&len);
#else
        bytesReceived = recvfrom(Reader->internalSocket, Reader->buffer+Reader->EndPointer, Reader->MallocSize-Reader->EndPointer, 0, (struct sockaddr*)&(Reader->SourceAddress), (unsigned int*)&len);
#endif
    }

    sem_wait(&(Reader->SendLock));

    if (bytesReceived <= 0)
    {
        //
        // This means the socket was gracefully closed by the remote endpoint
        //
        SEM_TRACK(AsyncSocket_TrackLock("ILibProcessAsyncSocket", 1, Reader);)
        ILibAsyncSocket_ClearPendingSend(Reader);
        SEM_TRACK(AsyncSocket_TrackUnLock("ILibProcessAsyncSocket", 2, Reader);)

#if defined(_WIN32_WCE) || defined(WIN32)
#if defined(WINSOCK2)
        shutdown(Reader->internalSocket, SD_BOTH);
#endif
        closesocket(Reader->internalSocket);
#elif defined(_POSIX)
        shutdown(Reader->internalSocket,SHUT_RDWR);
        close(Reader->internalSocket);
#endif
        Reader->internalSocket = (SOCKET)~0;

        ILibAsyncSocket_ClearPendingSend(Reader);
        wasssl = Reader->ssl;
        if (Reader->ssl != NULL)
        {
            sem_post(&(Reader->SendLock));
            SSL_free(Reader->ssl); // Frees SSL session and BIO buffer at the same time
            sem_wait(&(Reader->SendLock));
            Reader->ssl = NULL;
            Reader->sslstate = 0;
            Reader->sslbio = NULL;
        }
        sem_post(&(Reader->SendLock));

        //
        // Inform the user the socket has closed
        //
        if (wasssl == NULL)
        {
            // This was a normal socket, fire the event notifying the user. Depending on connection state, we event differently
            if (Reader->FinConnect == 0 && Reader->OnConnect != NULL) 
            {
                Reader->OnConnect(Reader, 0, Reader->user);    // Connection Failed
            }
            if (Reader->FinConnect != 0 && Reader->OnDisconnect != NULL) 
            {
                Reader->OnDisconnect(Reader, Reader->user);    // Socket Disconnected
            }
        }
        else
        {
            // This was a SSL socket, fire the event notifying the user. Depending on connection state, we event differently
            if (Reader->SSLConnect == 0 && Reader->OnConnect != NULL) 
            {
                Reader->OnConnect(Reader, 0, Reader->user);    // Connection Failed
            }
            if (Reader->SSLConnect != 0 && Reader->OnDisconnect != NULL) 
            {
                Reader->OnDisconnect(Reader, Reader->user);    // Socket Disconnected
            }
        }
        Reader->FinConnect = 0;
        Reader->SSLConnect = 0;
        Reader->sslstate = 0;

        //
        // If we need to free the buffer, do so
        //
        if (Reader->buffer != NULL)
        {
            free(Reader->buffer);
            Reader->buffer = NULL;
            Reader->MallocSize = 0;
        }
    }
    else
    {
        sem_post(&(Reader->SendLock));

        //
        // Data was read, so increment our counters
        //
        Reader->EndPointer += bytesReceived;

        //
        // Tell the user we have some data
        //
        if (Reader->OnData != NULL)
        {
            iBeginPointer = Reader->BeginPointer;
            iPointer = 0;
            Reader->OnData(Reader, Reader->buffer + Reader->BeginPointer, &(iPointer), Reader->EndPointer - Reader->BeginPointer, &(Reader->OnInterrupt), &(Reader->user),&(Reader->PAUSE));
            Reader->BeginPointer += iPointer;
        }
        //
        // If the user set the pointers, and we still have data, call them back with the data
        //
        if (Reader->internalSocket != ~0 && Reader->PAUSE <= 0 && Reader->BeginPointer!=Reader->EndPointer && Reader->BeginPointer != 0)
        {
            iBeginPointer = Reader->BeginPointer;
            iEndPointer = Reader->EndPointer;
            iPointer = 0;

            while (Reader->internalSocket != ~0 && Reader->PAUSE <= 0 && Reader->BeginPointer != Reader->EndPointer && Reader->EndPointer != 0)
            {
                Reader->EndPointer = Reader->EndPointer-Reader->BeginPointer;
                Reader->BeginPointer = 0;
                if (Reader->OnData != NULL)
                {
                    Reader->OnData(Reader,Reader->buffer + iBeginPointer, &(iPointer), Reader->EndPointer, &(Reader->OnInterrupt), &(Reader->user), &(Reader->PAUSE));
                }
                iBeginPointer += iPointer;
                Reader->EndPointer -= iPointer;
                if (iPointer == 0) break;
                iPointer = 0;
            }
            Reader->BeginPointer = iBeginPointer;
            Reader->EndPointer = iEndPointer;
        }

        //
        // If the user consumed all of the buffer, we can recycle it
        //
        if (Reader->BeginPointer == Reader->EndPointer)
        {
            Reader->BeginPointer = 0;
            Reader->EndPointer = 0;
        }
    }
}

/*! \fn ILibAsyncSocket_GetUser(ILibAsyncSocket_SocketModule socketModule)
\brief Returns the user object
\param socketModule The ILibAsyncSocket token to fetch the user object from
\returns The user object
*/
void *ILibAsyncSocket_GetUser(ILibAsyncSocket_SocketModule socketModule)
{
    return(socketModule == NULL?NULL:((struct ILibAsyncSocketModule*)socketModule)->user);
}
//
// Chained PreSelect handler for ILibAsyncSocket
//
// <param name="readset"></param>
// <param name="writeset"></param>
// <param name="errorset"></param>
// <param name="blocktime"></param>
void ILibAsyncSocket_PreSelect(void* socketModule,fd_set *readset, fd_set *writeset, fd_set *errorset, int* blocktime)
{
    struct ILibAsyncSocketModule *module = (struct ILibAsyncSocketModule*)socketModule;
    if (module->internalSocket == -1) return; // If there is not internal socket, just return now.

    SEM_TRACK(AsyncSocket_TrackLock("ILibAsyncSocket_PreSelect", 1, module);)
    sem_wait(&(module->SendLock));

    if (module->internalSocket != -1)
    {
        if (module->PAUSE < 0) *blocktime = 0;
        if (module->FinConnect == 0)
        {
            // Not Connected Yet
            FD_SET(module->internalSocket,writeset);
            FD_SET(module->internalSocket,errorset);
        }
        else
        {
            if (module->PAUSE == 0) // Only if this is zero. <0 is resume, so we want to process first
            {
                // Already Connected, just needs reading
                FD_SET(module->internalSocket,readset);
                FD_SET(module->internalSocket,errorset);
            }
        }

        if (module->PendingSend_Head != NULL)
        {
            // If there is pending data to be sent, then we need to check when the socket is writable
            FD_SET(module->internalSocket,writeset);
        }
    }
    SEM_TRACK(AsyncSocket_TrackUnLock("ILibAsyncSocket_PreSelect",2,module);)
    sem_post(&(module->SendLock));
}

//
// Chained PostSelect handler for ILibAsyncSocket
//
// <param name="socketModule"></param>
// <param name="slct"></param>
// <param name="readset"></param>
// <param name="writeset"></param>
// <param name="errorset"></param>
void ILibAsyncSocket_PostSelect(void* socketModule, int slct, fd_set *readset, fd_set *writeset, fd_set *errorset)
{
    struct ILibAsyncSocketModule *module = (struct ILibAsyncSocketModule*)socketModule;
    int TriggerSendOK = 0;
    struct ILibAsyncSocket_SendData *temp;
    int bytesSent = 0;
    int flags, len;
    int TRY_TO_SEND = 1;
    int triggerReadSet = 0;
    int triggerResume = 0;
    int triggerWriteSet = 0;
    int serr = 0, serrlen = sizeof(serr);
    SSL *wasssl;

    UNREFERENCED_PARAMETER( slct );

    if (module->internalSocket == -1) {
        return;    // If there is not internal socket, just return now.
    }
    SEM_TRACK(AsyncSocket_TrackLock("ILibAsyncSocket_PostSelect", 1, module);)
    sem_wait(&(module->SendLock));

    // Write Handling
    if (module->FinConnect != 0 && module->internalSocket != ~0 && FD_ISSET(module->internalSocket,writeset) != 0)
    {
        //
        // Keep trying to send data, until we are told we can't
        //
        while (TRY_TO_SEND != 0)
        {
            if (module->ssl != NULL)
            {
                // Send on SSL socket
                bytesSent = SSL_write(module->ssl, module->PendingSend_Head->buffer+module->PendingSend_Head->bytesSent, module->PendingSend_Head->bufferSize-module->PendingSend_Head->bytesSent);
            }
            else if (module->PendingSend_Head->remoteAddress.sin6_family == 0)
            {
                bytesSent = send(module->internalSocket,module->PendingSend_Head->buffer+module->PendingSend_Head->bytesSent,module->PendingSend_Head->bufferSize-module->PendingSend_Head->bytesSent,MSG_NOSIGNAL);
            }
            else
            {
                bytesSent = sendto(module->internalSocket,module->PendingSend_Head->buffer+module->PendingSend_Head->bytesSent,module->PendingSend_Head->bufferSize-module->PendingSend_Head->bytesSent,MSG_NOSIGNAL,(struct sockaddr*)&module->PendingSend_Head->remoteAddress,INET_SOCKADDR_LENGTH(module->PendingSend_Head->remoteAddress.sin6_family));
            }

            if (bytesSent > 0)
            {
                module->PendingBytesToSend -= bytesSent;
                module->TotalBytesSent += bytesSent;
                module->PendingSend_Head->bytesSent += bytesSent;
                if (module->PendingSend_Head->bytesSent == module->PendingSend_Head->bufferSize)
                {
                    // Finished Sending this block
                    if (module->PendingSend_Head == module->PendingSend_Tail)
                    {
                        module->PendingSend_Tail = NULL;
                    }
                    if (module->PendingSend_Head->UserFree == 0)
                    {
                        free(module->PendingSend_Head->buffer);
                    }
                    temp = module->PendingSend_Head->Next;
                    free(module->PendingSend_Head);
                    module->PendingSend_Head = temp;
                    if (module->PendingSend_Head==NULL) 
                    {
                        TRY_TO_SEND = 0;
                    }
                }
                else
                {
                    //
                    // We sent data, but not everything that needs to get sent was sent, try again
                    //
                    TRY_TO_SEND = 1;
                }
            }
            if (bytesSent == -1 || module->ssl == NULL)
            {
                // Error, clean up everything
                TRY_TO_SEND = 0;
#if defined(_WIN32_WCE) || defined(WIN32)
                if (WSAGetLastError() != WSAEWOULDBLOCK)
#elif defined(_POSIX)
                if (errno != EWOULDBLOCK)
#endif
                {
                    //
                    // There was an error sending
                    //
                    ILibAsyncSocket_ClearPendingSend(socketModule);
                    ILibLifeTime_Add(module->LifeTime, socketModule, 0, &ILibAsyncSocket_Disconnect, NULL);
                }
            }
            else if (bytesSent == -1 && module->ssl != NULL)
            {
                // OpenSSL returned an error
                bytesSent = SSL_get_error(module->ssl, bytesSent);
                if (bytesSent != SSL_ERROR_WANT_WRITE)
                {
                    //
                    // There was an error sending
                    //
                    ILibAsyncSocket_ClearPendingSend(socketModule);
                    ILibLifeTime_Add(module->LifeTime, socketModule, 0, &ILibAsyncSocket_Disconnect, NULL);
                }
            }
        }
        //
        // This triggers OnSendOK, if all the pending data has been sent.
        //
        if (module->PendingSend_Head == NULL && bytesSent != -1) 
        {
            TriggerSendOK = 1;
        }
        SEM_TRACK(AsyncSocket_TrackUnLock("ILibAsyncSocket_PostSelect", 2, module);)
        sem_post(&(module->SendLock));
        if (TriggerSendOK != 0) module->OnSendOK(module, module->user);
    }
    else
    {
        SEM_TRACK(AsyncSocket_TrackUnLock("ILibAsyncSocket_PostSelect", 2, module);)
        sem_post(&(module->SendLock));
    }


    SEM_TRACK(AsyncSocket_TrackLock("ILibAsyncSocket_PostSelect", 1, module);)
    sem_wait(&(module->SendLock)); // Lock!

    //
    // Error Handling. If the ERROR flag is set we have a problem. If not, we must check the socket status for an error.
    // Yes, this is odd, but it's possible for a socket to report a read set and still have an error, in this past this
    // was not handled and caused a lot of problems.
    //
    if (FD_ISSET(module->internalSocket, errorset) != 0)
    {
        serr = 1;
    }
    else
    {
        // Fetch the socket error code
#if defined(WINSOCK2)
        getsockopt(module->internalSocket, SOL_SOCKET, SO_ERROR, (char*)&serr, (int*)&serrlen);
#else
        getsockopt(module->internalSocket, SOL_SOCKET, SO_ERROR, (char*)&serr, (unsigned int*)&serrlen);
#endif
    }

    // If there are any errors, shutdown this socket
    if (serr != 0)
    {
        // If this is an SSL socket, close down the SSL state
        if ((wasssl = module->ssl) != NULL)
        {
            sem_post(&(module->SendLock));
            SSL_free(module->ssl); // Frees SSL session and BIO buffer at the same time
            sem_wait(&(module->SendLock));
            module->ssl = NULL;
            module->sslstate = 0;
            module->sslbio = NULL;
        }

        // Now shutdown the socket and set it to zero
#if defined(_WIN32_WCE) || defined(WIN32)
#if defined(WINSOCK2)
        shutdown(module->internalSocket, SD_BOTH);
#endif
        closesocket(module->internalSocket);
#elif defined(_POSIX)
        shutdown(module->internalSocket, SHUT_RDWR);
        close(module->internalSocket);
#endif
        module->internalSocket = (SOCKET)~0;

        // Unlock before fireing the event
        SEM_TRACK(AsyncSocket_TrackUnLock("ILibAsyncSocket_PostSelect", 4, module);)
        sem_post(&(module->SendLock));

        if (wasssl == NULL)
        {
            // This was a normal socket, fire the event notifying the user. Depending on connection state, we event differently
            if (module->FinConnect == 0 && module->OnConnect != NULL) 
            {
                module->OnConnect(module, 0, module->user);    // Connection Failed
            }
            if (module->FinConnect != 0 && module->OnDisconnect != NULL) 
            {
                module->OnDisconnect(module, module->user);    // Socket Disconnected
            }
        }
        else
        {
            // This was a SSL socket, fire the event notifying the user. Depending on connection state, we event differently
            if (module->SSLConnect == 0 && module->OnConnect != NULL) 
            {
                module->OnConnect(module, 0, module->user);    // Connection Failed
            }
            if (module->SSLConnect != 0 && module->OnDisconnect != NULL) 
            {
                module->OnDisconnect(module, module->user);    // Socket Disconnected
            }
        }
        module->FinConnect = 0;
        module->SSLConnect = 0;
        module->sslstate = 0;
    }
    else
    {
        // There are no errors, lets keep processing the socket normally
        if (module->FinConnect == 0)
        {
            // Check to see if the socket is connected
            if (FD_ISSET(module->internalSocket, writeset) != 0)
            {
                // Connected
                len = sizeof(struct sockaddr_in6);
#if defined(WINSOCK2)
                getsockname(module->internalSocket, (struct sockaddr*)(&module->LocalAddress), (int*)&len);
#else
                getsockname(module->internalSocket, (struct sockaddr*)(&module->LocalAddress), (unsigned int*)&len);
#endif
                module->FinConnect = 1;
                module->PAUSE = 0;

                // Set the socket to non-blocking mode, so we can play nice and share the thread
#if defined(_WIN32_WCE) || defined(WIN32)
                flags = 1;
                ioctlsocket(module->internalSocket, FIONBIO, (u_long *)(&flags));
#elif defined(_POSIX)
                flags = fcntl(module->internalSocket, F_GETFL,0);
                fcntl(module->internalSocket, F_SETFL, O_NONBLOCK|flags);
#endif

                // Connection Complete
                triggerWriteSet = 1;
            }

            // Unlock before fireing the event
            SEM_TRACK(AsyncSocket_TrackUnLock("ILibAsyncSocket_PostSelect", 4, module);)
            sem_post(&(module->SendLock));

            // If we did connect, we got more things to do
            if (triggerWriteSet != 0)
            {
                if (module->ssl != NULL)
                {
                    // If this is an SSL socket, launch the SSL connection process
                    if (SSL_connect(module->ssl) == 0) {
                        PRINTERROR();
                        ILIBCRITICALEXIT(253);
                    }
                }
                else
                {
                    // If this is a normal socket, event the connection now.
                    if (module->OnConnect != NULL) module->OnConnect(module, -1, module->user);
                }
            }
        }
        else
        {
            // Connected socket, we need to read data
            if (FD_ISSET(module->internalSocket, readset) != 0)
            {
                triggerReadSet = 1; // Data Available
            }
            else if (module->PAUSE < 0)
            {
                // Someone resumed a paused connection, but the FD_SET was not triggered because there is no new data on the socket.
                triggerResume = 1;
                ++module->PAUSE;
            }

            // Unlock before fireing the event
            SEM_TRACK(AsyncSocket_TrackUnLock("ILibAsyncSocket_PostSelect", 4, module);)
            sem_post(&(module->SendLock));

            if (triggerReadSet != 0 || triggerResume != 0) ILibProcessAsyncSocket(module, triggerReadSet);
        }
    }
    SEM_TRACK(AsyncSocket_TrackUnLock("ILibAsyncSocket_PostSelect",4,module);)
}

/*! \fn ILibAsyncSocket_IsFree(ILibAsyncSocket_SocketModule socketModule)
\brief Determines if an ILibAsyncSocket is in use
\param socketModule The ILibAsyncSocket to query
\returns 0 if in use, nonzero otherwise
*/
int ILibAsyncSocket_IsFree(ILibAsyncSocket_SocketModule socketModule)
{
    struct ILibAsyncSocketModule *module = (struct ILibAsyncSocketModule*)socketModule;
    return(module->internalSocket==~0?1:0);
}

/*! \fn ILibAsyncSocket_GetPendingBytesToSend(ILibAsyncSocket_SocketModule socketModule)
\brief Returns the number of bytes that are pending to be sent
\param socketModule The ILibAsyncSocket to query
\returns Number of pending bytes
*/
unsigned int ILibAsyncSocket_GetPendingBytesToSend(ILibAsyncSocket_SocketModule socketModule)
{
    struct ILibAsyncSocketModule *module = (struct ILibAsyncSocketModule*)socketModule;
    return(module->PendingBytesToSend);
}

/*! \fn ILibAsyncSocket_GetTotalBytesSent(ILibAsyncSocket_SocketModule socketModule)
\brief Returns the total number of bytes that have been sent, since the last reset
\param socketModule The ILibAsyncSocket to query
\returns Number of bytes sent
*/
unsigned int ILibAsyncSocket_GetTotalBytesSent(ILibAsyncSocket_SocketModule socketModule)
{
    struct ILibAsyncSocketModule *module = (struct ILibAsyncSocketModule*)socketModule;
    return(module->TotalBytesSent);
}

/*! \fn ILibAsyncSocket_ResetTotalBytesSent(ILibAsyncSocket_SocketModule socketModule)
\brief Resets the total bytes sent counter
\param socketModule The ILibAsyncSocket to reset
*/
void ILibAsyncSocket_ResetTotalBytesSent(ILibAsyncSocket_SocketModule socketModule)
{
    struct ILibAsyncSocketModule *module = (struct ILibAsyncSocketModule*)socketModule;
    module->TotalBytesSent = 0;
}

/*! \fn ILibAsyncSocket_GetBuffer(ILibAsyncSocket_SocketModule socketModule, char **buffer, int *BeginPointer, int *EndPointer)
\brief Returns the buffer associated with an ILibAsyncSocket
\param socketModule The ILibAsyncSocket to obtain the buffer from
\param[out] buffer The buffer
\param[out] BeginPointer Stating offset of the buffer
\param[out] EndPointer Length of buffer
*/
void ILibAsyncSocket_GetBuffer(ILibAsyncSocket_SocketModule socketModule, char **buffer, int *BeginPointer, int *EndPointer)
{
    struct ILibAsyncSocketModule* module = (struct ILibAsyncSocketModule*)socketModule;

    *buffer = module->buffer;
    *BeginPointer = module->BeginPointer;
    *EndPointer = module->EndPointer;
}

void ILibAsyncSocket_ModuleOnConnect(ILibAsyncSocket_SocketModule socketModule)
{
    struct ILibAsyncSocketModule* module = (struct ILibAsyncSocketModule*)socketModule;
    if (module != NULL && module->OnConnect != NULL) module->OnConnect(module, -1, module->user);
}

// Set the SSL client context used by all connections done by this socket module. The SSL context must
// be set before using this module. If left to NULL, all connections are in the clear using TCP.
//
// This is utilized by the ILibAsyncServerSocket module
// <param name="socketModule">The ILibAsyncSocket to modify</param>
// <param name="ssl_ctx">The ssl_ctx structure</param>
void ILibAsyncSocket_SetSSLContext(ILibAsyncSocket_SocketModule socketModule, SSL_CTX *ssl_ctx, int server)
{
    if (socketModule != NULL)
    {
        struct ILibAsyncSocketModule* module = (struct ILibAsyncSocketModule*)socketModule;
        if (ssl_ctx == NULL) return;

        if (module->ssl_ctx == NULL)
        {
            module->ssl_ctx = ssl_ctx;
            SSL_CTX_set_mode(ssl_ctx,SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
        }

        if (module->internalSocket > 0 && module->ssl == NULL)
        {
            module->ssl = SSL_new(ssl_ctx);
            module->sslstate = 0;
            module->sslbio = BIO_new_socket((int)(module->internalSocket), BIO_NOCLOSE);	// This is an odd conversion from SOCKET (possible 64bit) to 32 bit integer, but has to be done.
            SSL_set_bio(module->ssl, module->sslbio, module->sslbio);

            if (server != 0) SSL_set_accept_state(module->ssl); // Setup server SSL state
            else SSL_set_connect_state(module->ssl); // Setup client SSL state
        }
    }
}

//
// Sets the remote address field
//
// This is utilized by the ILibAsyncServerSocket module
// <param name="socketModule">The ILibAsyncSocket to modify</param>
// <param name="RemoteAddress">The remote interface</param>
void ILibAsyncSocket_SetRemoteAddress(ILibAsyncSocket_SocketModule socketModule, struct sockaddr *remoteAddress)
{
    if (socketModule != NULL)
    {
        struct ILibAsyncSocketModule* module = (struct ILibAsyncSocketModule*)socketModule;
        memcpy(&(module->RemoteAddress), remoteAddress, INET_SOCKADDR_LENGTH(remoteAddress->sa_family));
    }
}

/*! \fn ILibAsyncSocket_UseThisSocket(ILibAsyncSocket_SocketModule socketModule,void* UseThisSocket,ILibAsyncSocket_OnInterrupt InterruptPtr,void *user)
\brief Associates an actual socket with ILibAsyncSocket
\par
Instead of calling \a ConnectTo, you can call this method to associate with an already
connected socket.
\param socketModule The ILibAsyncSocket to associate
\param UseThisSocket The socket to associate
\param InterruptPtr Function Pointer that triggers when the TCP connection is interrupted
\param user User object to associate with this session
*/
void ILibAsyncSocket_UseThisSocket(ILibAsyncSocket_SocketModule socketModule, void* UseThisSocket, ILibAsyncSocket_OnInterrupt InterruptPtr, void *user)
{
#if defined(_WIN32_WCE) || defined(WIN32)
    SOCKET TheSocket = *((SOCKET*)UseThisSocket);
#elif defined(_POSIX)
    int TheSocket = *((int*)UseThisSocket);
#endif
    int flags;
    char *tmp;
    struct ILibAsyncSocketModule* module = (struct ILibAsyncSocketModule*)socketModule;

    module->PendingBytesToSend = 0;
    module->TotalBytesSent = 0;
    module->internalSocket = TheSocket;
    module->OnInterrupt = InterruptPtr;
    module->user = user;
    module->FinConnect = 1;
    module->SSLConnect = 0;
    module->PAUSE = 0;

    //
    // If the buffer is too small/big, we need to realloc it to the minimum specified size
    //
    if ((tmp = (char*)realloc(module->buffer, module->InitialSize)) == NULL) ILIBCRITICALEXIT(254);
    module->buffer = tmp;
    module->MallocSize = module->InitialSize;
    module->BeginPointer = 0;
    module->EndPointer = 0;

    if (module->ssl_ctx != NULL)
    {
        module->ssl = SSL_new(module->ssl_ctx);
        module->sslstate = 0;
        module->sslbio = BIO_new_socket((int)(module->internalSocket), BIO_NOCLOSE);	// This is an odd conversion from SOCKET (possible 64bit) to 32 bit integer, but has to be done.
        SSL_set_bio(module->ssl, module->sslbio, module->sslbio);
        SSL_set_accept_state(module->ssl); // Setup server SSL state
    }

    //
    // Make sure the socket is non-blocking, so we can play nice and share the thread
    //
#if defined(_WIN32_WCE) || defined(WIN32)
    flags = 1;
    ioctlsocket(module->internalSocket, FIONBIO,(u_long *)(&flags));
#elif defined(_POSIX)
    flags = fcntl(module->internalSocket,F_GETFL,0);
    fcntl(module->internalSocket,F_SETFL,O_NONBLOCK|flags);
#endif
}

/*! \fn ILibAsyncSocket_GetRemoteInterface(ILibAsyncSocket_SocketModule socketModule)
\brief Returns the Remote Interface of a connected session
\param socketModule The ILibAsyncSocket to query
\returns The remote interface
*/
int ILibAsyncSocket_GetRemoteInterface(ILibAsyncSocket_SocketModule socketModule, struct sockaddr *remoteAddress)
{
    struct ILibAsyncSocketModule *module = (struct ILibAsyncSocketModule*)socketModule;
    if (module->RemoteAddress.sin6_family != 0)
    {
        memcpy(remoteAddress, &(module->RemoteAddress), INET_SOCKADDR_LENGTH(module->RemoteAddress.sin6_family));
        return INET_SOCKADDR_LENGTH(module->RemoteAddress.sin6_family);
    }
    memcpy(remoteAddress, &(module->SourceAddress), INET_SOCKADDR_LENGTH(module->SourceAddress.sin6_family));
    return INET_SOCKADDR_LENGTH(module->SourceAddress.sin6_family);
}

/*! \fn ILibAsyncSocket_GetLocalInterface(ILibAsyncSocket_SocketModule socketModule)
\brief Returns the Local Interface of a connected session, in network order
\param socketModule The ILibAsyncSocket to query
\returns The local interface
*/
int ILibAsyncSocket_GetLocalInterface(ILibAsyncSocket_SocketModule socketModule, struct sockaddr *localAddress)
{
    struct ILibAsyncSocketModule *module = (struct ILibAsyncSocketModule*)socketModule;
    int receivingAddressLength = sizeof(struct sockaddr_in6);

    if (module->LocalAddress.sin6_family !=0)
    {
        memcpy(localAddress, &(module->LocalAddress2), INET_SOCKADDR_LENGTH(module->LocalAddress2.sin6_family));
        return INET_SOCKADDR_LENGTH(module->LocalAddress2.sin6_family);
    }
    else
    {
#if defined(WINSOCK2)
        getsockname(module->internalSocket, localAddress, (int*)&receivingAddressLength);
#else
        getsockname(module->internalSocket, localAddress, (unsigned int*)&receivingAddressLength);
#endif
        return receivingAddressLength;
    }
}

/*! \fn ILibAsyncSocket_Resume(ILibAsyncSocket_SocketModule socketModule)
\brief Resumes a paused session
\par
Sessions can be paused, such that further data is not read from the socket until resumed
\param socketModule The ILibAsyncSocket to resume
*/
void ILibAsyncSocket_Resume(ILibAsyncSocket_SocketModule socketModule)
{
    struct ILibAsyncSocketModule *sm = (struct ILibAsyncSocketModule*)socketModule;
    if (sm!=NULL)
    {
        sm->PAUSE = -1;
        ILibForceUnBlockChain(sm->Chain);
    }
}

/*! \fn ILibAsyncSocket_GetSocket(ILibAsyncSocket_SocketModule module)
\brief Obtain the underlying raw socket
\param module The ILibAsyncSocket to query
\returns The raw socket
*/
void* ILibAsyncSocket_GetSocket(ILibAsyncSocket_SocketModule module)
{
    struct ILibAsyncSocketModule *sm = (struct ILibAsyncSocketModule*)module;
    return(&(sm->internalSocket));
}

void ILibAsyncSocket_SetLocalInterface2(ILibAsyncSocket_SocketModule module, struct sockaddr *LocalAddress)
{
    struct ILibAsyncSocketModule *sm = (struct ILibAsyncSocketModule*)module;
    memcpy(&(sm->LocalAddress2), LocalAddress, INET_SOCKADDR_LENGTH(LocalAddress->sa_family));
}

void ILibAsyncSocket_SetMaximumBufferSize(ILibAsyncSocket_SocketModule module, int maxSize, ILibAsyncSocket_OnBufferSizeExceeded OnBufferSizeExceededCallback, void *user)
{
    struct ILibAsyncSocketModule *sm = (struct ILibAsyncSocketModule*)module;
    sm->MaxBufferSize = maxSize;
    sm->OnBufferSizeExceeded = OnBufferSizeExceededCallback;
    sm->MaxBufferSizeUserObject = user;
}

int ILibAsyncSocket_WasClosedBecauseBufferSizeExceeded(ILibAsyncSocket_SocketModule socketModule)
{
    struct ILibAsyncSocketModule *sm = (struct ILibAsyncSocketModule*)socketModule;
    return(sm->MaxBufferSizeExceeded);
}

X509 *ILibAsyncSocket_SslGetCert(ILibAsyncSocket_SocketModule socketModule)
{
    struct ILibAsyncSocketModule *sm = (struct ILibAsyncSocketModule*)socketModule;
    //! \note original 
    //return SSL_get_peer_certificate(sm->ssl);
    //! \note new define to make minor fix and I don't know why it works? locally compiled has this symbol but not other one...
    return SSL_get1_peer_certificate(sm->ssl);
}

STACK_OF(X509) *ILibAsyncSocket_SslGetCerts(ILibAsyncSocket_SocketModule socketModule)
{
    struct ILibAsyncSocketModule *sm = (struct ILibAsyncSocketModule*)socketModule;
    return SSL_get_peer_cert_chain(sm->ssl);
}

