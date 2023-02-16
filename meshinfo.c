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


#ifndef __MeshInfo_h__
#include "meshinfo.h"
#endif
//! temporary workaround
#define MESH_AGENT_PORT 16990
#define MESH_AGENT_VERSION 12					// Used for self-update system


// Convert hex string to int
int util_hexToint(char *hexString, int hexStringLength)
{
    int i, res = 0;

    // Ignore the leading zeroes
    while (*hexString == '0') 
    {
        hexString++;
        hexStringLength--;
    }

    // Process the rest of the string
    for (i = 0; i < hexStringLength; i++)
    {
        if (hexString[i] >= '0' && hexString[i] <= '9') res = (res << 4) + (hexString[i] - '0');
        if ((hexString[i] >= 'a' && hexString[i] <= 'f') || (hexString[i] >= 'A' && hexString[i] <= 'F')) res = (res << 4) + (hexString[i] - 'a' + 10);
    }
    return res;
}

// This method reads a stream where the length of the file can't be determined. Useful in POSIX only
int util_readfile2(char* filename, char** data)
{
    FILE * pFile;
    int count = 0;
    int len = 0;
    *data = NULL;

    pFile = fopen(filename,"rb");
    if (pFile != NULL)
    {
        *data = malloc(1024);
        do
        {
            len = fread((*data) + count, 1, 1023, pFile);
            count += len;
            if (len == 1023) *data = realloc(*data, count + 1024);
        }
        while (len == 100);
        (*data)[count] = 0;
        fclose(pFile);
    }

    return count;
}



// Get information about this computer
struct ComputerInformationStruct* info_GetComputerInformation()
{
#if defined WIN32
    OSVERSIONINFO osver;
    char temp[64];
    int t;
#endif

    struct ComputerInformationStruct* info = malloc(sizeof(struct ComputerInformationStruct));
    if (info == NULL) return NULL;
    memset(info, 0, sizeof(struct ComputerInformationStruct));
    info->structtype = 0x01;
    info->structsize = sizeof(struct ComputerInformationStruct);
    info->agenttype = g_agentid;
    info->agentversion = MESH_AGENT_VERSION;
    info->agentport = MESH_AGENT_PORT;
    gethostname((char*)info->name, sizeof(info->name));

#if defined WIN32
    osver.dwOSVersionInfoSize = sizeof(osver);
    if (GetVersionEx(&osver))
    {
        if (osver.dwPlatformId == VER_PLATFORM_WIN32s) strcpy_s(info->osdesc, sizeof(info->osdesc), "Win32");
        else if (osver.dwPlatformId == VER_PLATFORM_WIN32_WINDOWS)
        {
            if (osver.dwMinorVersion == 0) strcpy_s(info->osdesc, sizeof(info->osdesc), "Windows 95");
            else if (osver.dwMinorVersion == 10) strcpy_s(info->osdesc, sizeof(info->osdesc), "Windows 98");
            else if (osver.dwMinorVersion == 90) strcpy_s(info->osdesc, sizeof(info->osdesc), "Windows ME");
        }
        else if (osver.dwPlatformId == VER_PLATFORM_WIN32_NT)
        {
            t = sprintf_s(temp, sizeof(info->osdesc), "Windows NT %d.%d.%d", osver.dwMajorVersion, osver.dwMinorVersion, (osver.dwBuildNumber & 0xffff));
            memcpy(info->osdesc, temp, t);
        }
    }
#elif defined _POSIX
    memcpy(info->osdesc, "POSIX", 6); // TODO
#else
    memcpy(info->osdesc, "Unknown", 8);
#endif

#if defined WIN32
    info->agentbuild = 1;	// Win32
#elif defined _POSIX
    info->agentbuild = 2;	// POSIX
#endif

    return info;
}


// Checks the computer information structure for any problems.
// Returns 1 is the information passes, 0 if rejected.
int info_CheckComputerInformation(struct ComputerInformationStruct* computerinfo, int len)
{
    if (computerinfo == NULL || len == 0) return 1; // This is a normal empty struct
    if (len != sizeof(struct ComputerInformationStruct)) return 0; // bad length
    if (computerinfo->structsize != sizeof(struct ComputerInformationStruct)) return 0; // bad length

    // TODO

    return 1;
}

const char* AgentBuildTable[3] = {"Unknown", "Win32", "POSIX"};

// Print out information about this computer
void info_PrintComputerInformation(struct ComputerInformationStruct* computerinfo)
{
    printf("**Computer Info\r\n");
    if (computerinfo == NULL)
    {
        printf("  Computer info null\r\n");
        return;
    }
    printf("  Name              : %s\r\n", computerinfo->name);
    printf("  OS                : %s\r\n", computerinfo->osdesc);
    printf("  AgentType         : %d\r\n", computerinfo->agenttype);
    printf("  AgentBuild        : %s\r\n", AgentBuildTable[computerinfo->agentbuild]);
    printf("  AgentVersion      : %d\r\n", computerinfo->agentversion);
    printf("  AgentPort         : %d\r\n", computerinfo->agentport);
}





#ifdef WINSOCK2
// This is the Windows implementation of a method that gets information about local interfaces
struct LocalInterfaceStruct* info_GetLocalInterfaces()
{
    struct LocalInterfaceStruct* interfaces;
    IP_ADAPTER_INFO			*pAdapterInfo;
    IP_ADAPTER_ADDRESSES	*pAdapterAddresses;
    PIP_ADAPTER_INFO		pAdapter;
    PIP_ADAPTER_ADDRESSES	pAdapterAddr;
    ULONG					ulOutBufLen = 0;
    DWORD					dwRetVal;
    unsigned int			j;
    size_t					len;
    int						adapterCount = 0;
    DWORD					r;
    unsigned long			palen;
    char					pa[16];

    // Lets see how much memory we need to get the list of local interfaces
    pAdapterInfo = (IP_ADAPTER_INFO *)malloc( sizeof(IP_ADAPTER_INFO) );
    if (pAdapterInfo == NULL) return NULL;
    ulOutBufLen = sizeof(IP_ADAPTER_INFO);
    if (GetAdaptersInfo( pAdapterInfo, &ulOutBufLen) != ERROR_SUCCESS)
    {
        free(pAdapterInfo);
        if (ulOutBufLen == 0) return NULL;
        pAdapterInfo = (IP_ADAPTER_INFO *) malloc ( ulOutBufLen );
    }

    // Get the list of all local interfaces
    if ((dwRetVal = GetAdaptersInfo( pAdapterInfo, &ulOutBufLen)) != ERROR_SUCCESS || ulOutBufLen == 0)
    {
        free(pAdapterInfo);
        return NULL;
    }

    // Count how many interfaces are present
    pAdapter = pAdapterInfo;
    while (pAdapter)
    {
        adapterCount++;
        pAdapter = pAdapter->Next;
    }

    // Lets see how much memory we need to get the list of local adapters
    pAdapterAddresses = (IP_ADAPTER_ADDRESSES *) malloc( sizeof(IP_ADAPTER_ADDRESSES) );
    if (pAdapterAddresses == NULL) 
    {
        free(pAdapterInfo);
        return NULL;
    }
    ulOutBufLen = sizeof(IP_ADAPTER_ADDRESSES);
    if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_INCLUDE_PREFIX, NULL, pAdapterAddresses, &ulOutBufLen) != ERROR_SUCCESS)
    {
        free (pAdapterAddresses);
        if (ulOutBufLen == 0) return NULL;
        pAdapterAddresses = (IP_ADAPTER_ADDRESSES *) malloc ( ulOutBufLen );
    }

    // Get the list of all local interfaces
    if ((dwRetVal = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_INCLUDE_PREFIX, NULL, pAdapterAddresses, &ulOutBufLen)) != ERROR_SUCCESS || ulOutBufLen == 0)
    {
        free(pAdapterInfo);
        free(pAdapterAddresses);
        return NULL;
    }

    // Allocate memory for the local interface structures
    interfaces = malloc(sizeof(struct LocalInterfaceStruct) * adapterCount);
    if (interfaces == NULL) 
    {
        free(pAdapterInfo);
        free(pAdapterAddresses);
        return NULL;
    }
    memset(interfaces, 0, sizeof(struct LocalInterfaceStruct) * adapterCount);

    j = 0;
    pAdapter = pAdapterInfo;
    while (pAdapter)
    {
        // Find the corresponding adapter for this interface
        pAdapterAddr = pAdapterAddresses;
        while (pAdapterAddr && pAdapterAddr->IfIndex != pAdapter->ComboIndex) 
        {
            pAdapterAddr = pAdapterAddr->Next;
        }
        if (pAdapterAddr == NULL)
        {
            free(pAdapterInfo);
            free(pAdapterAddresses);
            free(interfaces);
            return NULL;
        }

        // Setup the interface struct
        interfaces[j].structtype = 0x02;
        interfaces[j].structsize = sizeof(struct LocalInterfaceStruct);

        // Get the interface type and MAC address.
        interfaces[j].iftype = (unsigned short)(pAdapter->Type);
        if (pAdapter->AddressLength == 6) memcpy(interfaces[j].mac, pAdapter->Address, 6);

        // Get the DNS suffix
        wcstombs_s(&len, interfaces[j].fqdn, 64, pAdapterAddr->DnsSuffix, wcslen(pAdapterAddr->DnsSuffix));
        memset(interfaces[j].fqdn + len, 0, 64 - len); // Set the rest to zeros

        // Get the IPv4 address and subnet mask (TODO: IPv6)
        ILibInet_pton(AF_INET, pAdapter->IpAddressList.IpAddress.String, &(interfaces[j].address));
        ILibInet_pton(AF_INET, pAdapter->IpAddressList.IpMask.String, &(interfaces[j].subnet));
        ILibInet_pton(AF_INET, pAdapter->GatewayList.IpAddress.String, &(interfaces[j].gateway));

        // Get the MAC address of the gateway (TODO: IPv6)
        r = SendARP(interfaces[j].gateway, interfaces[j].address, pa, &palen);
        if (palen == 6) memcpy(interfaces[j].gatewaymac, pa, 6);

        // Set the interface index and go to the next interface.
        interfaces[j].index = (unsigned short)(adapterCount - j - 1);
        j++;

        pAdapter = pAdapter->Next;
    }

    // Free the local interface memory
    free(pAdapterInfo);
    free(pAdapterAddresses);

    return interfaces;
}
#endif

#ifdef _POSIX

// TODO: Add support for IPv6, and check that it's on the correct interface
int info_GetHwAddress(char* ipaddr, int ipaddrlen, char** hwaddr)
{
    char* arpcache;
    int len, r = 0;
    struct parser_result* parse;
    struct parser_result_field* p;
    struct parser_result* parse2;
    struct parser_result_field* p2;

    *hwaddr = NULL;
    len = util_readfile2("/proc/net/arp", &arpcache);
    if (len == 0) return 0;

    parse = ILibParseString(arpcache, 0, len, "\n", 1);
    p = parse->FirstResult;
    p = p->NextResult; // Skip the first line
    while (p != NULL)
    {
        parse2 = ILibParseString(p->data, 0, p->datalength, " ", 1);
        p2 = parse2->FirstResult;
        if (p2->datalength == ipaddrlen && memcmp(p2->data, ipaddr, ipaddrlen) == 0)
        {
            // Found the correct ARP entry
            while (p2 != NULL)
            {
                p2 = p2->NextResult;;
                if (p2->datalength == 17 && p2->data[2] == ':') break;
            }
            if (p2 != NULL)
            {
                *hwaddr = malloc(6);
                (*hwaddr)[0] = util_hexToint(p2->data, 2);
                (*hwaddr)[1] = util_hexToint(p2->data + 3, 2);
                (*hwaddr)[2] = util_hexToint(p2->data + 6, 2);
                (*hwaddr)[3] = util_hexToint(p2->data + 9, 2);
                (*hwaddr)[4] = util_hexToint(p2->data + 12, 2);
                (*hwaddr)[5] = util_hexToint(p2->data + 15, 2);
                r = 6;
            }
            ILibDestructParserResults(parse2);
            break;
        }
        ILibDestructParserResults(parse2);
        p = p->NextResult; // Skip to next line
    }
    ILibDestructParserResults(parse);
    free(arpcache);
    return r;
}

// TODO: See if we can do this for each interface, right now interface is ignored
int info_GetDefaultFqdn(char* ifname, char** fqdn)
{
    char* resolv;
    int len, r = 0;
    struct parser_result* parse;
    struct parser_result_field* p;
    struct parser_result* parse2;
    struct parser_result_field* p2;

    *fqdn = NULL;
    len = util_readfile2("/etc/resolv.conf", &resolv);
    if (len == 0) return 0;

    parse = ILibParseString(resolv, 0, len, "\n", 1);
    p = parse->FirstResult;
    while (p != NULL)
    {
        parse2 = ILibParseString(p->data, 0, p->datalength, " ", 1);
        p2 = parse2->FirstResult;
        if (p2->datalength == 6 && memcmp(p2->data, "domain", 6) == 0)
        {
            // We found the system's default FQDN
            r = p2->NextResult->datalength;
            *fqdn = malloc(r + 1);
            memcpy(*fqdn, p2->NextResult->data, r);
            (*fqdn)[r] = 0;
            ILibDestructParserResults(parse2);
            break;
        }
        ILibDestructParserResults(parse2);
        p = p->NextResult; // Skip to next line
    }
    ILibDestructParserResults(parse);
    free(resolv);
    return r;
}

// TODO: Add IPv6 support
int info_GetDefaultGateway(char* ifname, char** gateway)
{
    char* route;
    char* temp;
    int len, r = 0, i;
    int ifnamelen = strlen(ifname);
    struct parser_result* parse;
    struct parser_result_field* p;
    struct parser_result* parse2;
    struct parser_result_field* p2;

    *gateway = NULL;
    len = util_readfile2("/proc/net/route", &route);
    if (len == 0) return 0;

    parse = ILibParseString(route, 0, len, "\n", 1);
    p = parse->FirstResult;
    p = p->NextResult; // Skip the first line
    while (p != NULL)
    {
        parse2 = ILibParseString(p->data, 0, p->datalength, "\t", 1);
        p2 = parse2->FirstResult;
        if (ifnamelen == p2->datalength && memcmp(p2->data, ifname, ifnamelen) == 0)
        {
            if (p2->NextResult->datalength == 8 && memcmp(p2->NextResult->data, "00000000", 8) == 0)
            {
                // We found the default gateway for this interface
                r = p2->NextResult->NextResult->datalength / 2;
                *gateway = malloc(r);
                temp = p2->NextResult->NextResult->data;
                for (i=0; i<r; i++) (*gateway)[r-(i+1)] = util_hexToint(temp + (i*2), 2);
                ILibDestructParserResults(parse2);
                break;
            }
        }
        ILibDestructParserResults(parse2);
        p = p->NextResult; // Skip to next line
    }
    ILibDestructParserResults(parse);
    free(route);
    return r;
}

// This is the POSIX implementation of a method that gets information about local interfaces
struct LocalInterfaceStruct* info_GetLocalInterfaces()
{
    struct LocalInterfaceStruct tinterface;
    struct LocalInterfaceStruct* interfaces = NULL;
    int                           sockfd, size  = 1, j;
    int adapterCount = 0;
    struct ifreq            *ifr;
    struct ifconf           ifc;
    struct sockaddr_in sa;
    char*					gateway;

    // Fetch the list of local interfaces
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP)) < 0) return NULL;
    ifc.ifc_len = IFRSIZE;
    ifc.ifc_req = NULL;
    do
    {
        ++size;
        // realloc buffer size until no overflow occurs
        if ((ifc.ifc_req = realloc(ifc.ifc_req, IFRSIZE)) == NULL) return NULL;
        ifc.ifc_len = IFRSIZE;
        if (ioctl(sockfd, SIOCGIFCONF, &ifc) != 0) return NULL;
    }
    while  (IFRSIZE <= ifc.ifc_len);

    ifr = ifc.ifc_req;
    for (; (char *) ifr < (char *) ifc.ifc_req + ifc.ifc_len; ++ifr)
    {
        if (ifr->ifr_addr.sa_data == (ifr+1)->ifr_addr.sa_data) continue;  // Duplicate
        if (ioctl(sockfd, SIOCGIFFLAGS, ifr)) continue; // Failed

        // Reset the temporary structure
        memset(&tinterface, 0, sizeof(struct LocalInterfaceStruct));

        // Setup the interface struct
        tinterface.structtype = 0x02;
        tinterface.structsize = sizeof(struct LocalInterfaceStruct);

        // Get the Default Gateway IP address
        j = info_GetDefaultGateway(ifr->ifr_name, &gateway);
        if (j == 4) memcpy(&(tinterface.gateway), gateway, 4);
        if (j > 0) free(gateway);

        // Get the Default Gateway MAC address
        j = info_GetHwAddress("192.168.2.1", 11, &gateway); // ???????????????????????????????????????????????????????????????????????????????????????????
        if (j == 6) memcpy(tinterface.gatewaymac, gateway, 6);
        if (j > 0) free(gateway);

        // Get the FQDN (DNS Suffix)
        j = info_GetDefaultFqdn(ifr->ifr_name, &gateway);
        if (j > 0)
        {
            if (j > 64) j = 63;
            memcpy(&(tinterface.fqdn), gateway, j);
            free(gateway);
        }

        // Attempt to figure out the interface type
        if (strlen(ifr->ifr_name) > 3 && memcmp(ifr->ifr_name, "eth", 3) == 0) tinterface.iftype = 6;

        // Get the local IP address
        tinterface.address = inaddrr(ifr_addr.sa_data).s_addr;

        // Get the hardware address
        if (ioctl(sockfd, SIOCGIFHWADDR, ifr) != 0) continue; // Not a real adapter
        //if (ifr->ifr_hwaddr.sa_family == 772) continue; // Loopback adapter
        switch (ifr->ifr_hwaddr.sa_family)
        {
			default:
				continue;
			case  ARPHRD_NETROM:
			case  ARPHRD_ETHER:
			case  ARPHRD_PPP:
			case  ARPHRD_EETHER:
			case  ARPHRD_IEEE802:
				break;
        }
        memcpy(tinterface.mac, ifr->ifr_addr.sa_data, 6);

        // Get the subnet mask
        if (ioctl(sockfd, SIOCGIFNETMASK, ifr) == 0) tinterface.subnet = inaddrr(ifr_addr.sa_data).s_addr;

        // Resize and copy this interface into the interface array
        if (adapterCount == 0)
        {
            interfaces = malloc(sizeof(struct LocalInterfaceStruct));
            memcpy(&interfaces[adapterCount], &tinterface, sizeof(struct LocalInterfaceStruct));
        }
        else
        {
            interfaces = realloc(interfaces, (adapterCount + 1) * sizeof(struct LocalInterfaceStruct));
            memcpy(&interfaces[adapterCount], &tinterface, sizeof(struct LocalInterfaceStruct));
        }
        adapterCount++;
    }

    // Set the adapter index in the structures, start with count and go down to zero.
    for (j=0; j<adapterCount; j++) 
    {
        interfaces[j].index = adapterCount - (j + 1);
    }

    free(ifc.ifc_req);
    close(sockfd);
    return interfaces;
}
#endif

// Checks the local interfaces information structure for any problems.
// Returns 1 is the information passes, 0 if rejected.
int info_CheckLocalInterfaces(struct LocalInterfaceStruct* interfaces, int len)
{
    if (interfaces == NULL || len == 0) return 1; // This is a normal empty struct
    if (len % sizeof(struct LocalInterfaceStruct) != 0) return 0; // bad length
    if (interfaces->structsize != sizeof(struct LocalInterfaceStruct)) return 0; // bad length

    // TODO

    return 1;
}

// Print the local interface structure
void info_PrintLocalInterfaces(struct LocalInterfaceStruct* interfaces)
{
    int i = -1;
    char temp[128];
    if (interfaces == NULL)
    {
        printf("**No Interfaces\r\n");
        return;
    }
    do
    {
        i++;
        printf("**Interface #%d\r\n", interfaces[i].index);
        printf("  IF Type           : %d\r\n", interfaces[i].iftype);  // 6 = Wired Ethernet, 71 = Wireless 802.11
        printf("  IPv4 Address      : %s\r\n", ILibInet_ntop(AF_INET, &(interfaces[i].address), temp, 128));
        printf("  IPv4 Subnet       : %s\r\n", ILibInet_ntop(AF_INET, &(interfaces[i].subnet), temp, 128));
        printf("  IPv4 Gateway      : %s\r\n", ILibInet_ntop(AF_INET, &(interfaces[i].gateway), temp, 128));
        printf("  IPv6 Address      : %s\r\n", ILibInet_ntop(AF_INET6, interfaces[i].address6, temp, 128));
        printf("  Local MAC         : %2.2x.%2.2x.%2.2x.%2.2x.%2.2x.%2.2x\r\n", interfaces[i].mac[0], interfaces[i].mac[1], interfaces[i].mac[2], interfaces[i].mac[3], interfaces[i].mac[4], interfaces[i].mac[5]);
        printf("  Gateway MAC       : %2.2x.%2.2x.%2.2x.%2.2x.%2.2x.%2.2x\r\n", interfaces[i].gatewaymac[0], interfaces[i].gatewaymac[1], interfaces[i].gatewaymac[2], interfaces[i].gatewaymac[3], interfaces[i].gatewaymac[4], interfaces[i].gatewaymac[5]);
        printf("  DNS Suffix        : %s\r\n", interfaces[i].fqdn);
    }
    while (interfaces[i].index != 0);
}




// Get Intel(R) AMT information
struct MeInformationStruct* info_GetMeInformation()
{
#ifdef _NOHECI
    return NULL;
#else
    char* tmp;
    int len;
    struct MeInformationStruct* info;
    HECI_VERSION heci_version;
    CFG_PROVISIONING_MODE provisioningmode;
    AMT_PROVISIONING_STATE provisioningstate;
    AMT_BOOLEAN b;
    UINT8 DedicatedMac[6];
    UINT8 HostMac[6];

    // Look for HECI driver
    if (heci_Init() == 0) return NULL;
    if (heci_GetHeciVersion(&heci_version) == 0) return NULL;

    // Setup the structure
    info = malloc(sizeof(struct MeInformationStruct));
    if (info == NULL) return NULL;
    memset(info, 0, sizeof(struct MeInformationStruct));
    info->structtype = 0x03;
    info->structsize = sizeof(struct MeInformationStruct);

    // Get the HECI version
    info->version = (((unsigned long)(heci_version.major)) << 16) | (((unsigned long)(heci_version.minor)) << 8) | ((unsigned long)(heci_version.hotfix));

    // Get provisioning state & mode
    if (pthi_GetProvisioningState(&provisioningstate) == 0) info->provisioningstate = provisioningstate;
    if (pthi_GetProvisioningMode(&provisioningmode, &b) == 0) info->provisioningmode = provisioningmode;

    // Get wired MAC addresses
    if (pthi_GetMacAddresses(DedicatedMac, HostMac) == 0)
    {
        memcpy(info->dedicatedmac, DedicatedMac, 6);
        memcpy(info->hostmac, HostMac, 6);
    }

    // TODO: DHCP & Wireless

    // Get TLS setting
    info->tlsenabled = (unsigned char)mdb_get_i("amt_tls");

    // Get Guest Username & Password
    len = mdb_get("amt_guest_user", &tmp);
    if (len > 0 && len < 32) memcpy(info->guestuser, tmp, len);
    if (tmp != NULL) free(tmp);
    len = mdb_get("amt_guest_pass", &tmp);
    if (len > 0 && len < 32) memcpy(info->guestpassword, tmp, len);
    if (tmp != NULL) free(tmp);

    return info;
#endif
}

// Checks the Intel AMT information structure for any problems.
// Returns 1 is the information passes, 0 if rejected.
int info_CheckMeInformation(struct MeInformationStruct* amtinfo, int len)
{
    if (amtinfo == NULL || len == 0) return 1; // This is a normal empty struct
    if (len != sizeof(struct MeInformationStruct)) return 0; // bad length
    if (amtinfo->structsize != sizeof(struct MeInformationStruct)) return 0; // bad length
    if (((amtinfo->version) >> 24) != 0) return 0; // Unsupported version
    if ((((amtinfo->version) >> 16) > 8) || (((amtinfo->version) >> 16) < 2)) return 0; // Unsupported version

    return 1;
}

#ifdef _DEBUG
const char* PStateTable[3] = {"Pre", "In", "Post"};
const char* PModeTable[4] = {"None", "Enterprise", "SMB", "RemoteAssist"};
const char* TlsEnabledTable[3] = {"Unknown", "Disabled", "Enabled"};
#endif

// Print out Intel(R) AMT information. This method does nothing in release mode.
void info_PrintMeInformation(struct MeInformationStruct* amtinfo)
{
#ifdef _DEBUG
    unsigned long i;

    if (amtinfo == NULL)
    {
        printf("**No Intel(R) ME.\r\n");
        return;
    }
    i = amtinfo->version;

    printf("**Intel(R) ME Info\r\n");
    printf("  Version           : %d.%d.%d\r\n", (int)(i>>16), (int)((i>>8)&0xFF), (int)((i)&0xFF));
    printf("  ProvisioningState : %s\r\n", PStateTable[amtinfo->provisioningstate]);
    printf("  ProvisioningMode  : %s\r\n", PModeTable[amtinfo->provisioningmode]);
    printf("  TLS Enabled       : %s\r\n", TlsEnabledTable[amtinfo->tlsenabled]);
    printf("  Guest Account     : %s\r\n", amtinfo->guestuser);
    printf("  Guest Password    : %s\r\n", amtinfo->guestpassword);
    printf("  Host MAC          : %2.2x.%2.2x.%2.2x.%2.2x.%2.2x.%2.2x\r\n", amtinfo->hostmac[0], amtinfo->hostmac[1], amtinfo->hostmac[2], amtinfo->hostmac[3], amtinfo->hostmac[4], amtinfo->hostmac[5]);
    printf("  Dedicated MAC     : %2.2x.%2.2x.%2.2x.%2.2x.%2.2x.%2.2x\r\n", amtinfo->dedicatedmac[0], amtinfo->dedicatedmac[1], amtinfo->dedicatedmac[2], amtinfo->dedicatedmac[3], amtinfo->dedicatedmac[4], amtinfo->dedicatedmac[5]);
#endif
}

// Process incoming Intel(R) AMT web page
// This may be ugly, but it's optimized for both size and speed.
int info_ProcessAmtWebPage(char* page, int pagelen, unsigned char* state, char** guid)
{
    char *ptr1, *ptr2;
    *state = 0;
    *guid = NULL;

    page[pagelen-1] = 0; // Make sure we have a null character at the end of the page
    ptr1 = strstr(page, "Power</td>\n\t<td>");
    if (ptr1 != NULL)
    {
        // Intel(R) AMT 2.0
        ptr1 += 16;
        // Fetch platform ID
        if ((ptr2 = strstr(ptr1, "System ID</td>\n\t<td>")) == NULL) return 0;
        ptr2 += 20;
    }
    else
    {
        // Intel(R) AMT 3.0+
        if ((ptr1 = strstr(page, "<p>Power\n\t<td>")) == NULL) return 0;
        ptr1 += 14;
        // Fetch platform ID
        if ((ptr2 = strstr(ptr1, "<p>System ID\n\t<td>")) == NULL) return 0;
        ptr2 += 18;
    }
    ptr2[36] = 0;
    *guid = ptr2; // Set the platform GUID

    // Decode power state indicator
    switch (((unsigned short*)ptr1)[0])
    {
    case 0x6E4F:
        *state = 1;
        break; // "On"			// On = 0x6E4F
    case 0x664F:
        *state = 6;
        break; // "Off"		// Of = 0x664F
    case 0x7453:
        *state = 4;
        break; // "Standby"	// St = 0x7453
    case 0x6948:
        *state = 5;
        break; // "Hibernate"	// Hi = 0x6948
    default:
        return 0;
    }

    return 1;
}

// Get a block of data containing all of the structures included the the includes parameter
struct NodeInfoBlock* info_CreateInfoBlock(unsigned short* includes, int headersize)
{
    int len = headersize;
    int ptr;
    unsigned short* includeindx = includes;
    struct NodeInfoBlock b;
    struct NodeInfoBlock* node = NULL;
    char* rawblock;

    memset(&b, 0, sizeof(struct NodeInfoBlock));

    // Fetch all the data needed from the data providers, compute total length of final block at the same time
    while (*includeindx != 0)
    {
        switch(*includeindx)
        {
        case 1:
            if (b.compinfo != NULL) break;
            b.compinfo = info_GetComputerInformation();
            if (b.compinfo != NULL) len += b.compinfo->structsize;
            break;
        case 2:
            if (b.netinfo != NULL) break;
            b.netinfo = info_GetLocalInterfaces();
            if (b.netinfo != NULL) len += (b.netinfo->structsize * (b.netinfo->index + 1));
            break;
        case 3:
            if (b.meinfo != NULL) break;
            b.meinfo = info_GetMeInformation();
            if (b.meinfo != NULL) len += b.meinfo->structsize;
            break;
        }
        includeindx++;
    }

    // Setup the raw block
    rawblock = malloc(len);
    node = malloc(sizeof(struct NodeInfoBlock));

    if (node == NULL || rawblock == NULL)
    {
        if (node != NULL) free(node);
        if (rawblock != NULL) free(rawblock);
        if (b.compinfo != NULL) free(b.compinfo);
        if (b.netinfo != NULL) free(b.netinfo);
        if (b.meinfo != NULL) free(b.meinfo);
        return NULL;
    }
    memset(rawblock, 0, len);
    memset(node, 0, sizeof(struct NodeInfoBlock));
    node->headersize = headersize;
    node->rawdata = rawblock;
    node->rawdatasize = len;
    ptr = headersize;

    // Copy the blocks
    if (b.compinfo != NULL)	// #1
    {
        node->compinfo = (struct ComputerInformationStruct*)(rawblock + ptr);
        memcpy(rawblock + ptr, b.compinfo, b.compinfo->structsize);
        ptr += b.compinfo->structsize;
        free(b.compinfo);
    }
    if (b.netinfo != NULL)	// #2
    {
        node->netinfo = (struct LocalInterfaceStruct*)(rawblock + ptr);
        memcpy(rawblock + ptr, b.netinfo, (b.netinfo->structsize * (b.netinfo->index + 1)));
        ptr += (b.netinfo->structsize * (b.netinfo->index + 1));
        free(b.netinfo);
    }
    if (b.meinfo != NULL)	// #3
    {
        node->meinfo = (struct MeInformationStruct*)(rawblock + ptr);
        memcpy(rawblock + ptr, b.meinfo, b.meinfo->structsize);
        ptr += b.meinfo->structsize;
        free(b.meinfo);
    }

    return node;
}


// Parse a block of data and returns a node info block structure.
struct NodeInfoBlock* info_ParseInfoBlock(char* rawblock, int rawblocksize, int headersize)
{
    int ptr = headersize;
    int blklen;
    int blktyp;
    struct NodeInfoBlock* node = NULL;
    if (rawblock == NULL || rawblocksize == 0) return NULL; // The block is empty.

    // Setup the node info block structure
    node = (struct NodeInfoBlock*)malloc(sizeof(struct NodeInfoBlock));
    if (node == NULL) return NULL;
    memset(node, 0, sizeof(struct NodeInfoBlock));
    node->headersize = headersize;
    node->rawdata = rawblock;
    node->rawdatasize = rawblocksize;

    while (ptr < rawblocksize)
    {
        blktyp = (*((unsigned short*)(rawblock + ptr))); // Get the block type
        blklen = (*((unsigned short*)(rawblock + ptr + 2))); // Get the block length
        if (ptr + blklen > rawblocksize) {
            free(node);    // We are pass the end of the data, fail.
            return NULL;
        }

        if (blktyp == 0x01)
        {
            // Computer information block
            if (blklen != sizeof(struct ComputerInformationStruct)) {
                free(node);    // This is not the right struct size, fail.
                return NULL;
            }
            node->compinfo = (struct ComputerInformationStruct*)(rawblock + ptr); // Set the computer information struct
            if (info_CheckComputerInformation(node->compinfo, blklen)==0) {
                free(node);    // Check the values in this struct
                return NULL;
            }
        }
        else if (blktyp == 0x02)
        {
            // Local network information block
            node->netinfo = (struct LocalInterfaceStruct*)(rawblock + ptr); // Get the local network information block
            if (info_CheckLocalInterfaces(node->netinfo, blklen)==0) {
                free(node);    // Check the values in this struct
                return NULL;
            }
            ptr += blklen * (node->netinfo->index);
        }
        else if (blktyp == 0x03)
        {
            // Intel(R) ME information block
            node->meinfo = (struct MeInformationStruct*)(rawblock + ptr); // Get the Intel(R) ME information block
            if (info_CheckMeInformation(node->meinfo, blklen)==0) {
                free(node);    // Check the values in this struct
                return NULL;
            }
        }

        ptr += blklen; // Advance the pointer
    }

    if (ptr > rawblocksize) {
        free(node);    // Bad length, fail.
        return NULL;
    }
    return node; // Everything ok.
}

void info_PrintInfoBlock(struct NodeInfoBlock* nodeblock)
{
    if (nodeblock == NULL)
    {
        printf("Node block is NULL.\r\n");
        return;
    }
    printf("--- Node Block ---\r\n");
    info_PrintComputerInformation(nodeblock->compinfo);
    info_PrintLocalInterfaces(nodeblock->netinfo);
    info_PrintMeInformation(nodeblock->meinfo);
    printf("------------------\r\n");
}

void info_FreeInfoBlock(struct NodeInfoBlock* nodeblock)
{
    if (nodeblock == NULL) return;
    if (nodeblock->rawdata != NULL) free(nodeblock->rawdata);
    free(nodeblock);
}



