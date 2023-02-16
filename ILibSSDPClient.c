/*
 * INTEL CONFIDENTIAL
 * Copyright (c) 2002, 2003 Intel Corporation.  All rights reserved.
 *
 * The source code contained or described herein and all documents
 * related to the source code ("Material") are owned by Intel
 * Corporation or its suppliers or licensors.  Title to the
 * Material remains with Intel Corporation or its suppliers and
 * licensors.  The Material contains trade secrets and proprietary
 * and confidential information of Intel or its suppliers and
 * licensors. The Material is protected by worldwide copyright and
 * trade secret laws and treaty provisions.  No part of the Material
 * may be used, copied, reproduced, modified, published, uploaded,
 * posted, transmitted, distributed, or disclosed in any way without
 * Intel's prior express written permission.

 * No license under any patent, copyright, trade secret or other
 * intellectual property right is granted to or conferred upon you
 * by disclosure or delivery of the Materials, either expressly, by
 * implication, inducement, estoppel or otherwise. Any license
 * under such intellectual property rights must be express and
 * approved by Intel in writing.
 *
 * $Workfile: ILibSSDPClient.c
 * $Revision: #1.0.1775.28223
 * $Author:   Intel Corporation, Intel Device Builder
 * $Date:     Thursday, November 11, 2004
 *
 *
 *
 */

#ifndef __ILibSSDPClient__
#include "ILibSSDPClient.h"
#endif


#define UPNP_PORT 1900
#define UPNP_GROUP "239.255.255.250"


struct SSDPClientModule
{
    void (*PreSelect)(void* object,fd_set *readset, fd_set *writeset, fd_set *errorset, int* blocktime);
    void (*PostSelect)(void* object,int slct, fd_set *readset, fd_set *writeset, fd_set *errorset);
    void (*Destroy)(void* object);
    void (*FunctionCallback)(void *sender, char* UDN, int Alive, char* LocationURL, int Timeout, UPnPSSDP_MESSAGE m, void *user);
    char* DeviceURN;
    int DeviceURNLength;

    char* DeviceURN_Prefix;
    int DeviceURN_PrefixLength;
    int BaseDeviceVersionNumber;

    int *IPAddress;
    int NumIPAddress;

#ifdef UPNP_1_1
    void *HashTable;
    void *TIMER;
#	if defined(WIN32) || defined(_WIN32_WCE)
    SOCKET UNICAST_Socket;
#	else
    int UNICAST_Socket;
#	endif
#endif

#if defined(WIN32) || defined(_WIN32_WCE)
    SOCKET SSDPListenSocket;
    SOCKET MSEARCH_Response_Socket;
#else
    int SSDPListenSocket;
    int MSEARCH_Response_Socket;
#endif

    int Terminate;
    void *Reserved;
};

#ifdef UPNP_1_1
struct LocationInfo
{
    int BootID;
    int ConfigID;
    char* LocationURL;
    unsigned short SearchPort;
    int IsInteresting;
    int Timeout;
    char *UDN;
    struct SSDPClientModule* parent;
};

void ILibSSDP_UnicastSearch(void *SSDPToken, char *IP, unsigned short Port)
{
    struct SSDPClientModule *module = (struct SSDPClientModule*)SSDPToken;
    char *buffer;
    int bufferlength;
    struct sockaddr_in dest_addr;

    memset((char *)&(dest_addr),0,sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr.s_addr = inet_addr(IP);
    dest_addr.sin_port = htons(Port);

    buffer = (char*)malloc(105+module->DeviceURNLength);
    bufferlength = sprintf(buffer,"M-SEARCH * HTTP/1.1\r\nMX: 3\r\nST: %s\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\n\r\n",module->DeviceURN);

    printf("UNICASTING to %s:%u...\r\n",IP,Port);
    sendto(module->UNICAST_Socket, buffer, bufferlength, 0, (struct sockaddr *) &dest_addr, sizeof(dest_addr));
    free(buffer);
}

void ILibSSDP_LocationSink(void *obj)
{
    struct LocationInfo* LI = (struct LocationInfo*)obj;
    char *IP;
    unsigned short Port;
    char *Path;

    struct sockaddr_in addr;

    ILibParseUri(LI->LocationURL,&IP,&Port,&Path);

    memset((char *)&addr, 0,sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(IP);
    addr.sin_port = htons(Port);

    //Send UNICAST M-SEARCH to the device
    ILibSSDP_UnicastSearch(LI->parent,IP,LI->SearchPort);

    free(IP);
    free(Path);
}
//void ILibSSDP_LocationSink_Destroy(void *obj)
//{
//	struct LocationInfo* LI = (struct LocationInfo*)obj;
//	free(LI->LocationURL);
//	free(LI);
//}
#endif

#if defined(WIN32) || defined(_WIN32_WCE)
void ILibReadSSDP(SOCKET ReadSocket, struct SSDPClientModule *module)
#else
void ILibReadSSDP(int ReadSocket, struct SSDPClientModule *module)
#endif
{
    int bytesRead = 0;
    char* buffer = (char*)malloc(4096);
    struct sockaddr_in addr;
    int addrlen = sizeof(struct sockaddr_in);
    struct packetheader *packet;
    struct packetheader_field_node *node;
    struct parser_result *pnode,*pnode2;
    struct parser_result_field *prf;

    char* Location = NULL;
    char* UDN = NULL;
    int Timeout = 0;
    int Alive = 0;
    int OK;
    int rt;

#ifdef UPNP_1_1
    int BootID=0;
    int ConfigID=0;
    int MaxVersion=1;
    unsigned short SearchPort = 1900;
#endif

    char *IP;
    unsigned short PORT;
    char *PATH;
    int MATCH=0;
#ifdef UPNP_1_1
    struct LocationInfo *LI;
#endif

    do
    {
        bytesRead = recvfrom(ReadSocket, buffer, 4096, 0, (struct sockaddr *) &addr, &addrlen);
        if(bytesRead<=0)
        {
            break;
        }
        packet = ILibParsePacketHeader(buffer,0,bytesRead);
        if(packet==NULL) {
            continue;
        }

        if(packet->Directive==NULL)
        {
            /* M-SEARCH Response */
            if(packet->StatusCode==200)
            {
                node = packet->FirstField;
                while(node!=NULL)
                {
#ifdef UPNP_1_1
                    if(strncasecmp(node->Field,"BOOTID.UPNP.ORG",15)==0)
                    {
                        node->FieldData[node->FieldDataLength] = '\0';
                        BootID = atoi(node->FieldData);
                    }
                    if(strncasecmp(node->Field,"CONFIGID.UPNP.ORG",17)==0)
                    {
                        node->FieldData[node->FieldDataLength] = '\0';
                        ConfigID = atoi(node->FieldData);
                    }
                    if(strncasecmp(node->Field,"SEARCHPORT.UPNP.ORG",19)==0)
                    {
                        node->FieldData[node->FieldDataLength] = '\0';
                        SearchPort = (unsigned short)atoi(node->FieldData);
                    }
#endif
                    if(strncasecmp(node->Field,"LOCATION",8)==0)
                    {
                        Location = node->FieldData;
                        Location[node->FieldDataLength] = 0;
                        //Location = (char*)malloc(node->FieldDataLength+1);
                        //memcpy(Location,node->FieldData,node->FieldDataLength);
                        //Location[node->FieldDataLength] = '\0';
                    }
                    if(strncasecmp(node->Field,"CACHE-CONTROL",13)==0)
                    {
                        pnode = ILibParseString(node->FieldData, 0, node->FieldDataLength, ",", 1);
                        prf = pnode->FirstResult;
                        while(prf!=NULL)
                        {
                            pnode2 = ILibParseString(prf->data, 0, prf->datalength, "=", 1);
                            pnode2->FirstResult->datalength = ILibTrimString(&(pnode2->FirstResult->data),pnode2->FirstResult->datalength);
                            pnode2->FirstResult->data[pnode2->FirstResult->datalength]=0;
                            if(strcasecmp(pnode2->FirstResult->data,"max-age")==0)
                            {
                                pnode2->LastResult->datalength = ILibTrimString(&(pnode2->LastResult->data),pnode2->LastResult->datalength);
                                pnode2->LastResult->data[pnode2->LastResult->datalength]=0;
                                Timeout = atoi(pnode2->LastResult->data);
                                ILibDestructParserResults(pnode2);
                                break;
                            }
                            prf = prf->NextResult;
                            ILibDestructParserResults(pnode2);
                        }
                        ILibDestructParserResults(pnode);
                    }
                    if(strncasecmp(node->Field,"USN",3)==0)
                    {
                        pnode = ILibParseString(node->FieldData, 0, node->FieldDataLength, "::", 2);
                        pnode->FirstResult->data[pnode->FirstResult->datalength] = '\0';
                        UDN = pnode->FirstResult->data+5;
                        ILibDestructParserResults(pnode);
                    }
                    node = node->NextField;
                }
                ILibParseUri(Location,&IP,&PORT,&PATH);
                if(addr.sin_addr.s_addr==inet_addr(IP))
                {
#ifdef UPNP_1_1
                    LI = (struct LocationInfo*)ILibGetEntry(module->HashTable,Location,(int)strlen(Location));
                    if(LI!=NULL)
                    {
                        LI->IsInteresting = 1;
                        LI->Timeout = Timeout;
                    }
                    else
                    {
                        LI = (struct LocationInfo*)malloc(sizeof(struct LocationInfo));
                        memset(LI,0,sizeof(struct LocationInfo));
                        LI->ConfigID = ConfigID;
                        LI->LocationURL = (char*)malloc((int)strlen(Location)+1);
                        strcpy(LI->LocationURL,Location);
                        LI->SearchPort = SearchPort;
                        LI->parent = module;
                        LI->IsInteresting = 1;
                        LI->Timeout = Timeout;
                        LI->UDN = (char*)malloc(strlen(UDN)+1);
                        strcpy(LI->UDN,UDN);
                        ILibAddEntry(module->HashTable,Location,(int)strlen(Location),LI);
                    }
#endif
                    if(module->FunctionCallback!=NULL)
                    {
                        module->FunctionCallback(module,UDN,-1,Location,Timeout,UPnPSSDP_MSEARCH,module->Reserved);
                    }
                }
                free(IP);
                free(PATH);
            }
        }
        else
        {
            /* Notify Packet */
            if(strncasecmp(packet->Directive,"NOTIFY",6)==0)
            {
                OK = 0;
                rt = 0;
                node = packet->FirstField;
#ifdef UPNP_1_1
                // Find MaxVersion first
                while(node!=NULL)
                {
                    node->Field[node->FieldLength] = '\0';
                    if(strncasecmp(node->Field,"MAXVERSION.UPNP.ORG",19)==0)
                    {
                        node->FieldData[node->FieldDataLength] = '\0';
                        MaxVersion = atoi(node->FieldData);
                    }
                    node = node->NextField;
                }
                node = packet->FirstField;
#endif
                while(node!=NULL)
                {
                    node->Field[node->FieldLength] = '\0';
                    if(strncasecmp(node->Field,"NT",2)==0 && node->FieldLength==2)
                    {
                        node->FieldData[node->FieldDataLength] = '\0';
                        if(strncasecmp(node->FieldData,module->DeviceURN_Prefix,module->DeviceURN_PrefixLength)==0)
                        {
#ifdef UPNP_1_1
                            if(atoi(node->FieldData+module->DeviceURN_PrefixLength)>=module->BaseDeviceVersionNumber || MaxVersion >= module->BaseDeviceVersionNumber)
                            {
                                OK = -1;
                            }
#else
                            if(atoi(node->FieldData+module->DeviceURN_PrefixLength)>=module->BaseDeviceVersionNumber)
                            {
                                OK = -1;
                            }
#endif
                        }
#ifndef UPNP_1_1
                        else if(strncasecmp(node->FieldData,"upnp:rootdevice",15)==0)
                        {
                            rt = -1;
                        }
                        else
                        {
                            break;
                        }
#endif
                    }
                    if(strncasecmp(node->Field,"NTS",3)==0)
                    {
                        if(strncasecmp(node->FieldData,"ssdp:alive",10)==0)
                        {
                            Alive = -1;
                            rt = 0;
                        }
                        else
                        {
                            Alive = 0;
                            OK = 0;
                        }
                    }
                    if(strncasecmp(node->Field,"USN",3)==0)
                    {
                        pnode = ILibParseString(node->FieldData, 0, node->FieldDataLength, "::", 2);
                        pnode->FirstResult->data[pnode->FirstResult->datalength] = '\0';
                        UDN = pnode->FirstResult->data+5;
                        ILibDestructParserResults(pnode);
                    }
                    if(strncasecmp(node->Field,"LOCATION",8)==0)
                    {
                        Location = node->FieldData;
                        Location[node->FieldDataLength] = 0;
                        //Location = (char*)malloc(node->FieldDataLength+1);
                        //memcpy(Location,node->FieldData,node->FieldDataLength);
                        //Location[node->FieldDataLength] = '\0';
                    }
#ifdef UPNP_1_1
                    if(strncasecmp(node->Field,"BOOTID.UPNP.ORG",15)==0)
                    {
                        node->FieldData[node->FieldDataLength] = '\0';
                        BootID = atoi(node->FieldData);
                    }
                    if(strncasecmp(node->Field,"CONFIGID.UPNP.ORG",17)==0)
                    {
                        node->FieldData[node->FieldDataLength] = '\0';
                        ConfigID = atoi(node->FieldData);
                    }
                    if(strncasecmp(node->Field,"SEARCHPORT.UPNP.ORG",19)==0)
                    {
                        node->FieldData[node->FieldDataLength] = '\0';
                        SearchPort = (unsigned short)atoi(node->FieldData);
                    }
#endif
                    if(strncasecmp(node->Field,"CACHE-CONTROL",13)==0)
                    {
                        pnode = ILibParseString(node->FieldData, 0, node->FieldDataLength, ",", 1);
                        prf = pnode->FirstResult;
                        while(prf!=NULL)
                        {
                            pnode2 = ILibParseString(prf->data, 0, prf->datalength, "=", 1);
                            pnode2->FirstResult->datalength = ILibTrimString(&(pnode2->FirstResult->data),pnode2->FirstResult->datalength);
                            pnode2->FirstResult->data[pnode2->FirstResult->datalength]=0;
                            if(strcasecmp(pnode2->FirstResult->data,"max-age")==0)
                            {
                                pnode2->LastResult->datalength = ILibTrimString(&(pnode2->LastResult->data),pnode2->LastResult->datalength);
                                pnode2->LastResult->data[pnode2->LastResult->datalength]=0;
                                Timeout = atoi(pnode2->LastResult->data);
                                ILibDestructParserResults(pnode2);
                                break;
                            }
                            prf = prf->NextResult;
                            ILibDestructParserResults(pnode2);
                        }
                        ILibDestructParserResults(pnode);
                    }
                    node = node->NextField;
                }
#ifdef UPNP_1_1
                if((OK!=0 && Alive!=0) || (Alive==0)) // UPnP/1.1 is very tolerant
#else
                if((OK!=0 && Alive!=0) || (rt!=0 && Alive==0)) // UPnP/1.0 is not tolerant
#endif
                {
                    if(Location!=NULL)
                    {
                        ILibParseUri(Location,&IP,&PORT,&PATH);
                        if(addr.sin_addr.s_addr==inet_addr(IP))
                        {
                            MATCH=1;
                        }
                        else
                        {
                            MATCH=0;
                        }
                        free(IP);
                        free(PATH);
#ifdef UPNP_1_1
                        if(ILibHasEntry(module->HashTable,Location,(int)strlen(Location))==0)
                        {
                            LI = (struct LocationInfo*)malloc(sizeof(struct LocationInfo));
                            memset(LI,0,sizeof(struct LocationInfo));
                            LI->ConfigID = ConfigID;
                            LI->LocationURL = (char*)malloc((int)strlen(Location)+1);
                            strcpy(LI->LocationURL,Location);
                            LI->SearchPort = SearchPort;
                            LI->parent = module;
                            LI->IsInteresting = 1;
                            LI->Timeout = Timeout;
                            LI->UDN = (char*)malloc(strlen(UDN)+1);
                            strcpy(LI->UDN,UDN);
                            ILibAddEntry(module->HashTable,Location,(int)strlen(Location),LI);
                        }
                        else
                        {
                            LI = (struct LocationInfo*)ILibGetEntry(module->HashTable,Location,(int)strlen(Location));
                            if(LI!=NULL)
                            {
                                LI->IsInteresting = 1;
                                LI->Timeout = Timeout;
                                ILibLifeTime_Remove(module->TIMER, LI);
                            }
                        }
#endif
                    }
                    if(Alive==0 || MATCH!=0)
                    {
                        if(module->FunctionCallback!=NULL)
                        {
                            module->FunctionCallback(module,UDN,Alive,Location,Timeout,UPnPSSDP_NOTIFY,module->Reserved);
                        }
                    }
                }
#ifdef UPNP_1_1
                else if(Location!=NULL)
                {
                    // Didn't match, lets Unicast search to make sure (1.1)
                    if(ILibHasEntry(module->HashTable,Location,(int)strlen(Location))==0)
                    {
                        LI = (struct LocationInfo*)malloc(sizeof(struct LocationInfo));
                        memset(LI,0,sizeof(struct LocationInfo));
                        LI->ConfigID = ConfigID;
                        LI->LocationURL = (char*)malloc((int)strlen(Location)+1);
                        strcpy(LI->LocationURL,Location);
                        LI->parent = module;
                        LI->IsInteresting = 0;
                        LI->Timeout = Timeout;
                        LI->SearchPort = SearchPort;

                        ILibAddEntry(module->HashTable,Location,(int)strlen(Location),LI);
                        ILibLifeTime_Add(module->TIMER,LI,10,&ILibSSDP_LocationSink,NULL);
                    }
                    else
                    {
                        // There is a match, is this an interesting device?
                        LI = (struct LocationInfo*)ILibGetEntry(module->HashTable,Location,(int)strlen(Location));
                        if(LI!=NULL)
                        {
                            if(LI->IsInteresting!=0)
                            {
                                if(module->FunctionCallback!=NULL)
                                {
                                    module->FunctionCallback(module,UDN,Alive,Location,Timeout,UPnPSSDP_MSEARCH,module->Reserved);
                                }
                            }
                        }
                    }
                }
#endif
            }
        }
        ILibDestructPacket(packet);
    } while(bytesRead>0);
    free(buffer);
}

void ILibSSDPClientModule_PreSelect(void* object,fd_set *readset, fd_set *writeset, fd_set *errorset, int* blocktime)
{
    struct SSDPClientModule *module = (struct SSDPClientModule*)object;
    FD_SET(module->SSDPListenSocket,readset);
    FD_SET(module->MSEARCH_Response_Socket, readset);
#ifdef UPNP_1_1
    FD_SET(module->UNICAST_Socket,readset);
#endif
}
void ILibSSDPClientModule_PostSelect(void* object,int slct, fd_set *readset, fd_set *writeset, fd_set *errorset)
{
    struct SSDPClientModule *module = (struct SSDPClientModule*)object;
    if(slct>0)
    {
        if(FD_ISSET(module->SSDPListenSocket,readset)!=0)
        {
            ILibReadSSDP(module->SSDPListenSocket,module);
        }
        if(FD_ISSET(module->MSEARCH_Response_Socket,readset)!=0)
        {
            ILibReadSSDP(module->MSEARCH_Response_Socket,module);
        }
#ifdef UPNP_1_1
        if(FD_ISSET(module->UNICAST_Socket,readset)!=0)
        {
            ILibReadSSDP(module->UNICAST_Socket,module);
        }
#endif
    }
}

void ILibSSDPClientModule_Destroy(void *object)
{
    struct SSDPClientModule *s = (struct SSDPClientModule*)object;

#ifdef UPNP_1_1
    char *key;
    int keyLength;
    void *data;
    void *en = ILibHashTree_GetEnumerator(s->HashTable);

    while(ILibHashTree_MoveNext(en)==0)
    {
        ILibHashTree_GetValue(en,&key,&keyLength,&data);
        free(((struct LocationInfo*)data)->LocationURL);
        if(((struct LocationInfo*)data)->UDN != NULL)
        {
            free(((struct LocationInfo*)data)->UDN);
        }
        free(data);
    }

    ILibHashTree_DestroyEnumerator(en);
    ILibDestroyHashTree(s->HashTable);
#endif

    free(s->DeviceURN);
    if(s->IPAddress!=NULL)
    {
        free(s->IPAddress);
    }
}
void ILibSSDP_IPAddressListChanged(void *SSDPToken)
{
    struct SSDPClientModule *RetVal = (struct SSDPClientModule*)SSDPToken;
    int i;
    struct sockaddr_in dest_addr;

    struct ip_mreq mreq;
    char* buffer;
    int bufferlength;
    struct in_addr interface_addr;

    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr.s_addr = inet_addr(UPNP_GROUP);
    dest_addr.sin_port = htons(UPNP_PORT);

    for(i=0; i<RetVal->NumIPAddress; ++i)
    {
        mreq.imr_multiaddr.s_addr = inet_addr(UPNP_GROUP);
        mreq.imr_interface.s_addr = RetVal->IPAddress[i];
        if (setsockopt(RetVal->SSDPListenSocket, IPPROTO_IP, IP_ADD_MEMBERSHIP,(char*)&mreq, sizeof(mreq)) < 0)
        {
        }

    }

    buffer = (char*)malloc(105+RetVal->DeviceURNLength);
    bufferlength = sprintf(buffer,"M-SEARCH * HTTP/1.1\r\nMX: 3\r\nST: %s\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\n\r\n",RetVal->DeviceURN);

    free(RetVal->IPAddress);
    RetVal->NumIPAddress = ILibGetLocalIPAddressList(&(RetVal->IPAddress));

    for(i=0; i<RetVal->NumIPAddress; ++i)
    {
        interface_addr.s_addr = RetVal->IPAddress[i];
        if (setsockopt(RetVal->MSEARCH_Response_Socket, IPPROTO_IP, IP_MULTICAST_IF,(char*)&interface_addr, sizeof(interface_addr)) == 0)
        {
            sendto(RetVal->MSEARCH_Response_Socket, buffer, bufferlength, 0, (struct sockaddr *) &dest_addr, sizeof(dest_addr));
        }
    }

    free(buffer);
}
void* ILibCreateSSDPClientModule(void *chain, char* DeviceURN, int DeviceURNLength, void (*CallbackPtr)(void *sender, char* UDN, int Alive, char* LocationURL, int Timeout, UPnPSSDP_MESSAGE m,void *user), void *user)
{
    int i,flags;
    struct sockaddr_in addr;
    struct sockaddr_in dest_addr;
    struct SSDPClientModule *RetVal = (struct SSDPClientModule*)malloc(sizeof(struct SSDPClientModule));
    int ra = 1;
    struct ip_mreq mreq;
    char* buffer;
    int bufferlength;
    char* _DeviceURN;
    struct in_addr interface_addr;
    unsigned char TTL = 4;
    struct parser_result *pr;


    memset((char *)&addr, 0, sizeof(addr));
    memset((char *)&interface_addr, 0, sizeof(interface_addr));
    memset((char *)&(addr), 0, sizeof(dest_addr));

    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr.s_addr = inet_addr(UPNP_GROUP);
    dest_addr.sin_port = htons(UPNP_PORT);

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(UPNP_PORT);

    RetVal->Destroy = &ILibSSDPClientModule_Destroy;
    RetVal->PreSelect = &ILibSSDPClientModule_PreSelect;
    RetVal->PostSelect = &ILibSSDPClientModule_PostSelect;

    RetVal->Reserved = user;
    RetVal->Terminate = 0;
    RetVal->FunctionCallback = CallbackPtr;
    RetVal->DeviceURN = (char*)malloc(DeviceURNLength+1);
    memcpy(RetVal->DeviceURN,DeviceURN,DeviceURNLength);
    RetVal->DeviceURN[DeviceURNLength] = '\0';
    RetVal->DeviceURNLength = DeviceURNLength;

    // Populate the Prefix portion of the URN, for matching purposes
    RetVal->DeviceURN_Prefix = RetVal->DeviceURN;
    pr = ILibParseString(RetVal->DeviceURN,0,RetVal->DeviceURNLength,":",1);
    RetVal->DeviceURN_PrefixLength = (int)((pr->LastResult->data)-(RetVal->DeviceURN));
    pr->LastResult->data[pr->LastResult->datalength]=0;
    RetVal->BaseDeviceVersionNumber = atoi(pr->LastResult->data);
    ILibDestructParserResults(pr);


    RetVal->NumIPAddress = ILibGetLocalIPAddressList(&(RetVal->IPAddress));
    RetVal->SSDPListenSocket = socket(AF_INET, SOCK_DGRAM, 0);
#	if defined(WIN32) || defined(_WIN32_WCE)
    ILibGetDGramSocket(htonl(INADDR_ANY), (HANDLE*)&(RetVal->MSEARCH_Response_Socket));
#	else
    ILibGetDGramSocket(htonl(INADDR_ANY), (int*)&(RetVal->MSEARCH_Response_Socket));
#	endif

    if (setsockopt(RetVal->MSEARCH_Response_Socket, IPPROTO_IP, IP_MULTICAST_TTL,(char*)&TTL, sizeof(TTL)) < 0)
    {
        /* Ignore this case */
    }
    if (setsockopt(RetVal->SSDPListenSocket, SOL_SOCKET, SO_REUSEADDR,(char*)&ra, sizeof(ra)) < 0)
    {
        DEBUGSTATEMENT(printf("Setting SockOpt SO_REUSEADDR failed\r\n"));
        exit(1);
    }
    if (bind(RetVal->SSDPListenSocket, (struct sockaddr *) &(addr), sizeof(addr)) < 0)
    {
        printf("SSDPListenSocket bind");
        exit(1);
    }

#ifdef UPNP_1_1
#	if defined(WIN32) || defined(_WIN32_WCE)
    addr.sin_port = htons(ILibGetDGramSocket(htonl(INADDR_ANY), (HANDLE*)&(RetVal->UNICAST_Socket)));
#	else
    addr.sin_port = htons(ILibGetDGramSocket(htonl(INADDR_ANY), (int*)&(RetVal->UNICAST_Socket)));
#	endif
    setsockopt(RetVal->UNICAST_Socket, SOL_SOCKET, SO_REUSEADDR,(char*)&ra, sizeof(ra));
    bind(RetVal->UNICAST_Socket, (struct sockaddr *) &(addr), sizeof(addr));
#	if defined(WIN32) || defined(_WIN32_WCE)
    flags = 1;
    ioctlsocket(RetVal->UNICAST_Socket,FIONBIO,&flags);
#	elif _POSIX
    flags = fcntl(RetVal->UNICAST_Socket,F_GETFL,0);
    fcntl(RetVal->UNICAST_Socket,F_SETFL,O_NONBLOCK|flags);
#	endif
#endif


    /*  Setting Sockets to Non-Blocking mode */
#if defined(WIN32) || defined(_WIN32_WCE)
    flags = 1;
    ioctlsocket(RetVal->SSDPListenSocket,FIONBIO,&flags);
    ioctlsocket(RetVal->MSEARCH_Response_Socket,FIONBIO,&flags);
#elif _POSIX
    flags = fcntl(RetVal->SSDPListenSocket,F_GETFL,0);
    fcntl(RetVal->SSDPListenSocket,F_SETFL,O_NONBLOCK|flags);
    fcntl(RetVal->MSEARCH_Response_Socket,F_SETFL,O_NONBLOCK|flags);
#endif

    for(i=0; i<RetVal->NumIPAddress; ++i)
    {
        mreq.imr_multiaddr.s_addr = inet_addr(UPNP_GROUP);
        mreq.imr_interface.s_addr = RetVal->IPAddress[i];
        if (setsockopt(RetVal->SSDPListenSocket, IPPROTO_IP, IP_ADD_MEMBERSHIP,(char*)&mreq, sizeof(mreq)) < 0)
        {
            printf("SSDPListenSocket setsockopt mreq");
            exit(1);
        }

    }

    ILibAddToChain(chain,RetVal);
    _DeviceURN = (char*)malloc(DeviceURNLength+1);
    memcpy(_DeviceURN,DeviceURN,DeviceURNLength);
    _DeviceURN[DeviceURNLength] = '\0';
    buffer = (char*)malloc(105+DeviceURNLength);
    bufferlength = sprintf(buffer,"M-SEARCH * HTTP/1.1\r\nMX: 3\r\nST: %s\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\n\r\n",_DeviceURN);

    for(i=0; i<RetVal->NumIPAddress; ++i)
    {
        interface_addr.s_addr = RetVal->IPAddress[i];
        if (setsockopt(RetVal->MSEARCH_Response_Socket, IPPROTO_IP, IP_MULTICAST_IF,(char*)&interface_addr, sizeof(interface_addr)) == 0)
        {
            sendto(RetVal->MSEARCH_Response_Socket, buffer, bufferlength, 0, (struct sockaddr *) &dest_addr, sizeof(dest_addr));
        }
    }

    free(_DeviceURN);
    free(buffer);
#ifdef UPNP_1_1
    RetVal->HashTable = ILibInitHashTree();
    RetVal->TIMER = ILibCreateLifeTime(chain);
#endif
    return(RetVal);
}
