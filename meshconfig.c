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



#ifndef __MeshConfig_h__
#include "meshconfig.h"
#endif

// home of configuration data...

//struct util_cert selfcert;
//struct util_cert selftlscert;
//struct util_cert selftlsclientcert;

// Convert a block of data to HEX
// The "out" must have (len*2)+1 free space.
char utils_HexTable[16] = { '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f' };




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



// Frees a block of memory returned from this module.
void util_free(char* ptr)
{
    free(ptr);
    ptr = NULL;
}


// Generates a random text string, useful for HTTP nonces.
void util_randomtext(int length, char* result)
{
    int l;
    util_random(length, result);
    for (l=0; l<length; l++) result[l] = (unsigned char)((result[l] % 26) + 'A');
}
/*!
 * 
 *   The <time.h> header shall declare the timespec structure, which
       shall include at least the following members:

           time_t  tv_sec    Seconds.
           long    tv_nsec   Nanoseconds.
*/
//! \var time_local 
struct timespec time_local;
// Generates a random string of data. TODO: Use Hardware RNG if possible
void util_random(int length, char* result)
{

	// old code
    //RAND_bytes((unsigned char*)result, length);
	// old code    
    unsigned int seed;
    int r;
    time_local.tv_sec = time(NULL);
    seed = time_local.tv_sec;
    time_local.tv_nsec |= time_local.tv_sec;
    srand(seed);
    for (int j = 0; j < length; j++) 
    {
		r =  rand();
		printf("%d ", r);		
		result[j] = r % rand() / time_local.tv_nsec;
        
    }
    printf("%d end rando util_random\n", r);
}


void util_tohex(char* data, int len, char* out)
{
    int i;
    char *p = out;
    if (data == NULL || len == 0) 
    {
        *p = 0;
        return;
    }
    for(i = 0; i < len; i++)
    {
        *(p++) = utils_HexTable[((unsigned char)data[i]) >> 4];
        *(p++) = utils_HexTable[((unsigned char)data[i]) & 0x0F];
    }
    *p = 0;
}




size_t util_writefile(char* filename, char* data, int datalen)
{
    FILE * pFile = NULL;
    size_t count = 0;

#ifdef WIN32
    fopen_s(&pFile, filename,"wb");
#else
    pFile = fopen(filename,"wb");
#endif

    if (pFile != NULL)
    {
        count = fwrite(data, datalen, 1, pFile);
        fclose(pFile);
    }
    return count;
}

size_t util_readfile(char* filename, char** data)
{
    FILE *pFile = NULL;
    size_t count = 0;
    size_t len = 0;
    *data = NULL;
    if (filename == NULL) return 0;

#ifdef WIN32
    fopen_s(&pFile, filename,"rb");
#else
    pFile = fopen(filename,"rb");
#endif

    if (pFile != NULL)
    {
        fseek(pFile, 0, SEEK_END);
        count = ftell(pFile);
        fseek(pFile, 0, SEEK_SET);
        *data = malloc(count+1);
        if (*data == NULL) 
        {
            fclose(pFile);
            return 0;
        }
        while (len < count) len += fread(*data, 1, count-len, pFile);
        (*data)[count] = 0;
        fclose(pFile);
    }
    return count;
}

//! \note superfluous functions that can be removed... It adds nothing and slows down until it's optimized out.
//! \note superfluous functions that can be removed... It adds nothing and slows down until it's optimized out.
int util_deletefile(char* filename)
{
    return remove(filename);
}




// Compresses an input buffer using deflate, the result output buffer must be freed using util_free().
int util_compress(char* inbuf, unsigned int inbuflen, char** outbuf, unsigned int headersize)
{
	z_stream c_stream; // compression stream
	int err;
	char* tbuf;

	unsigned int outbuflen = inbuflen - headersize;
	*outbuf = malloc((int)outbuflen + headersize + 4 );
	if (*outbuf == NULL) return 0;
	if (headersize != 0) memcpy(*outbuf, inbuf, headersize);

	c_stream.zalloc = (alloc_func)0;
	c_stream.zfree = (free_func)0;
	c_stream.opaque = (voidpf)0;

	err = deflateInit(&c_stream, Z_DEFAULT_COMPRESSION);
	//CHECK_ERR(err, "deflateInit");

	c_stream.next_in  = (unsigned char*)(inbuf + headersize);
	c_stream.next_out = (unsigned char*)(*outbuf + headersize + 4);

	while (c_stream.total_in != (inbuflen - headersize) && c_stream.total_out < outbuflen) 
	{
		c_stream.avail_in = inbuflen - headersize;
		c_stream.avail_out = outbuflen;
		err = deflate(&c_stream, Z_NO_FLUSH);
		//CHECK_ERR(err, "deflate");
	}

	for (;;) 
	{
		err = deflate(&c_stream, Z_FINISH);
		if (err == Z_STREAM_END || outbuflen <= c_stream.total_out) break;
		//CHECK_ERR(err, "deflate");
	}

	err = deflateEnd(&c_stream);
	//CHECK_ERR(err, "deflateEnd");

	if (outbuflen <= c_stream.total_out)
	{
		// Compression failed (it's larger than before)
		((int*)(*outbuf + headersize))[0] = -1;
		memcpy((*outbuf) + headersize + 4, inbuf + headersize, inbuflen - headersize);
		return outbuflen + headersize + 4;
	}

	outbuflen = c_stream.total_out;
	if ((tbuf = realloc(*outbuf, outbuflen + headersize + 4)) == NULL) return 0;
	*outbuf = tbuf;
	((int*)(*outbuf + headersize))[0] = inbuflen - headersize;
	return outbuflen + headersize + 4;
}

// Decompresses an input buffer using deflate, the result output buffer must be freed using util_free().
int util_decompress(char* inbuf, unsigned int inbuflen, char** outbuf, unsigned int headersize)
{
	int err, len;
	z_stream d_stream;
	unsigned int outbuflen = ((int*)(inbuf + headersize))[0];

	if (outbuflen == -1)
	{
		// Failed compression
		*outbuf = malloc(inbuflen - 4);
		if (*outbuf == NULL) return 0;
		if (headersize != 0) memcpy(*outbuf, inbuf, headersize); // Copy the header as-is
		memcpy(*outbuf + headersize, inbuf + headersize + 4, inbuflen - headersize - 4); // Copy the data as-is
		return inbuflen - 4;
	}

	len = outbuflen + headersize;
	*outbuf = malloc(len + 1);
	if (*outbuf == NULL) return 0;
	(*outbuf)[len] = 0;
	if (headersize != 0) memcpy(*outbuf, inbuf, headersize); // Copy the header as-is

	d_stream.zalloc = (alloc_func)0;
	d_stream.zfree = (free_func)0;
	d_stream.opaque = (voidpf)0;

	d_stream.next_in  = (unsigned char*)(inbuf + headersize + 4);
	d_stream.avail_in = 0;
	d_stream.next_out = (unsigned char*)(*outbuf + headersize);

	err = inflateInit(&d_stream);
	//CHECK_ERR(err, "inflateInit");

	while (d_stream.total_out < outbuflen && d_stream.total_in < inbuflen)
	{
		d_stream.avail_in = inbuflen;
		d_stream.avail_out = outbuflen;
		err = inflate(&d_stream, Z_NO_FLUSH);
		if (err == Z_STREAM_END) break;
		//CHECK_ERR(err, "inflate");
	}

	err = inflateEnd(&d_stream);
	//CHECK_ERR(err, "inflateEnd");

	return outbuflen + headersize;
}





// Compute the mesh distance from self to a given NodeID. We use an XOR technique widely used in
// distributed hash tables. Only the first 32 bits of the NodeID are considered, this should be plenty.
int ctrl_Distance(char* nodeid)
{
    unsigned int xor, i = 31, bit = 0x80000000;
    xor = ((unsigned int)ntohl(((unsigned int*)g_selfid)[0]))^((unsigned int)ntohl(((unsigned int*)nodeid)[0]));
    while (i > 0)
    {
        if (xor & bit) return i;
        i--;
        bit = bit >> 1;
    }
    return 0;
}



void info_event_updatetarget(char* nodeid, char* addrptr, int addrlen, unsigned char state, unsigned char power)
{
    char *ptr;
    int len = 43 + addrlen;

    // Build the event packet
    if (len > 300) ILIBCRITICALEXIT2(253, len);
    if ((ptr = malloc(len)) == NULL) ILIBCRITICALEXIT(254);
    ((unsigned short*)ptr)[0] = PB_TARGETSTATUS;				// Local Event Type
    ((unsigned short*)ptr)[1] = (unsigned short)len;			// Packet Size
    if (nodeid != NULL) memcpy(ptr + 4, nodeid, UTIL_HASHSIZE);
    else memset(ptr + 4, 0, UTIL_HASHSIZE); // Target Node ID (zeros if deleted node)
    ptr[4 + UTIL_HASHSIZE] = (char)state;						// State
    ptr[5 + UTIL_HASHSIZE] = (char)power;						// Power
    ((unsigned int*)(ptr + UTIL_HASHSIZE + 6))[0] = 0xFFFFFFFF;	// LastContact (TODO)
    ptr[42] = (char)addrlen;									// Target Address Lenght
    memcpy(ptr + 43, addrptr, addrlen);							// Target NodeID

    // Send the event and clear
    //! commented out for now
    ///ctrl_SendSubscriptionEvent(ptr, len);
    free(ptr);
}





/**
struct util_cert* ctrl_GetCert() 
{
    return &selfcert;
}
struct util_cert* ctrl_GetTlsCert() 
{
    return &selftlscert;
}
struct util_cert* ctrl_GetTlsClientCert() 
{
    return &selftlsclientcert;
}
* */
char* ctrl_GetSelfNodeId() 
{
    return g_selfid;
}


// Return the well known port on which the mesh agent runs
int GetMeshPort() 
{
    return MESH_AGENT_PORT;
}

unsigned long util_gettime()
{
    struct timeval tv;
    gettimeofday(&tv,NULL);
    return (tv.tv_sec * 1000) + (tv.tv_usec / 1000);
}

long util_Chronometer;
void util_startChronometer()
{
    struct timeval tv;
    gettimeofday(&tv,NULL);
    util_Chronometer = (tv.tv_sec * 1000) + (tv.tv_usec / 1000);
}

long util_readChronometer()
{
    struct timeval tv;
    gettimeofday(&tv,NULL);
    return ((tv.tv_sec * 1000) + (tv.tv_usec / 1000)) - util_Chronometer;
}


// Perform a SHA256 hash on the data
void util_sha256(char* data, int datalen, char* result)
{
/*
    SHA256_CTX c;
    SHA256_Init(&c);
    SHA256_Update(&c, data, datalen);
    SHA256_Final((unsigned char*)result, &c);
*/
}

// Run SHA256 on a file and return the result
int util_sha256file(char* filename, char* result)
{
 /*
    FILE *pFile = NULL;
    SHA256_CTX c;
    int len = 0;
    char *buf = NULL;

    if (filename == NULL) return -1;
    #ifdef WIN32
    	fopen_s(&pFile, filename,"rb");
    #else
    	pFile = fopen(filename,"rb");
    #endif
    if (pFile == NULL) goto error;
    SHA256_Init(&c);
    if ((buf = malloc(4096)) == NULL) goto error;
    while ((len == fread(buf, 1, 4096, pFile)) > 0) SHA256_Update(&c, buf, len);
    free(buf);
    buf = NULL;
    fclose(pFile);
    pFile = NULL;
    SHA256_Final((unsigned char*)result, &c);
    return 0;

    error:
    if (buf != NULL) free(buf);
    if (pFile != NULL) fclose(pFile);
    return -1;
*/
}



NodeInfoBlock_t * ctrl_GetCurrentNodeInfoBlock() 
{
    return g_nodeblock;
}
unsigned int ctrl_GetSignedBlockSyncCounter() 
{
    return g_signedblocksynccounter;
}

#define INET_SOCKADDR_LENGTH(x) ((x==AF_INET6?sizeof(struct sockaddr_in6):sizeof(struct sockaddr_in)))

int ctrl_MeshInit()
{
/*
    int l, i;
    char* str;

    // Mesh Setup
    l = mdb_open();
    switch (l)
    {
		case 0:
			// Load existing node certificate
			i = mdb_get("SelfNodeCert", &str);
			if (util_from_p12(str, i, "hidden", &selfcert) == 0) 
			{
				MSG("Failed to open node cert.\r\n");    // Failed to load node certificate
				return 100;
			}
			util_free(str);

			// Load existing TLS certificate
			i = mdb_get("SelfNodeTlsCert", &str);
			if (util_from_p12(str, i, "hidden", &selftlscert) == 0) {
				MSG("Failed to open TLS cert.\r\n");    // Failed to load node certificate
				return 100;
			}
			util_free(str);

			// Load existing TLS client certificate
			i = mdb_get("SelfNodeTlsClientCert", &str);
			if (util_from_p12(str, i, "hidden", &selftlsclientcert) == 0) {
				MSG("Failed to open TLS client cert.\r\n");    // Failed to load node certificate
				return 100;
			}
			util_free(str);

			MSG("Loaded existing certificates.\r\n");
			break;
		case 1:
			// Failed to open database
			MSG("Failed to open database.\r\n");
			return 101;
		case 2:
			MSG("Generating new certificates...\r\n");

			// Generate a new node certificate
			l = util_mkCert(NULL, &selfcert, 2048, 10000, "RootCertificate", CERTIFICATE_ROOT);
			l = util_to_p12(selfcert, "hidden", &str);
			mdb_set("SelfNodeCert", str, l);
			util_free(str);

			// Generate a new TLS certificate
			l = util_mkCert(&selfcert, &selftlscert, 2048, 10000, "localhost", CERTIFICATE_TLS_SERVER);
			l = util_to_p12(selftlscert, "hidden", &str);
			mdb_set("SelfNodeTlsCert", str, l);
			util_free(str);

			// Generate a new TLS client certificate
			l = util_mkCert(&selfcert, &selftlsclientcert, 2048, 10000, "localhost", CERTIFICATE_TLS_CLIENT);
			l = util_to_p12(selftlsclientcert, "hidden", &str);
			mdb_set("SelfNodeTlsClientCert", str, l);
			util_free(str);

			MSG("Certificates ready.\r\n");
			break;
    }

    // Get our current serial number, add 1 more for safety.
    g_serial = mdb_get_i("nodeserial") + 1;

    // Setup the session secret key
    g_SessionRandomId = g_serial;
    util_random(32, g_SessionRandom);

    // Compute our own NodeID & setup packet used for multicast at the same time
    util_keyhash(selfcert, g_selfid);
    ((unsigned short*)g_selfid_mcast)[0] = PB_NODEID;
    ((unsigned short*)g_selfid_mcast)[1] = 36;
    memcpy(g_selfid_mcast + 4, g_selfid, UTIL_HASHSIZE);

    // Compute our latest node block
    ctrl_GetCurrentSignedNodeInfoBlock(&str);

    // Setup local subscriptions
    memset(ctrl_SubscriptionChain, 0, sizeof(struct LocalSubscription) * 8);	// Clear the subscription list
    ctrl_SubscriptionLoopback.sin_family = AF_INET;								// IPv4
#ifdef WINSOCK2
    ctrl_SubscriptionLoopback.sin_addr.S_un.S_addr = 0x0100007F;				// 127.0.0.1
#else
    ctrl_SubscriptionLoopback.sin_addr.s_addr = 0x0100007F;						// 127.0.0.1
#endif

    return 0;
*/
}

void ctrl_MeshUnInit()
{
/*
    if (g_nodeblock != NULL) info_FreeInfoBlock(g_nodeblock);
    if (g_signedblock != NULL) free(g_signedblock);
    if (g_signedblockhash != NULL) free(g_signedblockhash);
    g_nodeblock = NULL;
    util_freecert(&selftlsclientcert);
    util_freecert(&selftlscert);
    util_freecert(&selfcert);
    mdb_close();
*/
}


int ctrl_GetCurrentSignedNodeInfoBlock(char** block)
{
    unsigned short includes[] = { 0x01, 0x02, 0x03, 0x00 };
    NodeInfoBlock_t *node = NULL;
    char *hash;
    char *temp;
    int len;

    if ((hash = malloc(UTIL_HASHSIZE)) == NULL) 
    {
        if (block != NULL) *block = g_signedblock;
        return g_signedblocklen;
    }
    // Get the block & run a hash on it
    node = info_CreateInfoBlock(includes, (UTIL_HASHSIZE * 2) + 4);		// [CertHash(UTIL_HASHSIZE) + NodeID(UTIL_HASHSIZE) + Serial(4)] + CompressedInfo
    if (node == NULL) 
    {
        free(hash);
        if (block != NULL) *block = g_signedblock;
        return g_signedblocklen;
    }
    util_sha256(node->rawdata + ((UTIL_HASHSIZE * 2) + 4), node->rawdatasize - ((UTIL_HASHSIZE * 2) + 4), hash);
    if (g_signedblockhash != NULL && memcmp(hash, g_signedblockhash, UTIL_HASHSIZE) == 0)
    {
        // Node block has not changed, return the one in the database
        info_FreeInfoBlock(node);
        free(hash);
        if (block != NULL) *block = g_signedblock;
        return g_signedblocklen;
    }

    // Fetch node serial number & copy it and node id in correct spot
    mdb_set_i("nodeserial", ++g_serial);
    memcpy((node->rawdata)+ (UTIL_HASHSIZE * 2), &g_serial, 4);				// Copy the serial number in correct spot.
    memcpy((node->rawdata)+ UTIL_HASHSIZE, g_selfid, UTIL_HASHSIZE);		// Copy the NodeID in correct spot.

    // Update the global node block
    if (g_nodeblock != NULL) info_FreeInfoBlock(g_nodeblock);
    g_nodeblock = node;

    // Sign it
    //len = util_sign(selfcert, node->rawdata, node->rawdatasize, &temp);

    // Add the header
    if (g_signedblock != NULL) free(g_signedblock);
    if ((g_signedblock = malloc(g_signedblocklen = len + 4)) == NULL) return 0;
    ((unsigned short*)(g_signedblock))[0] = PB_NODEPUSH;
    ((unsigned short*)(g_signedblock))[1] = (unsigned short)g_signedblocklen;
    memcpy(g_signedblock + 4, temp, len);
    free(temp);
    if (g_signedblockhash != NULL) free(g_signedblockhash);
    g_signedblockhash = hash;
    if (block != NULL) *block = g_signedblock;

    // Send the new block as a local event
    ctrl_SendSubscriptionEvent(g_signedblock, g_signedblocklen);

    return g_signedblocklen;
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

int util_keyhash(struct util_cert cert, char* result)
{
	/*
	if (cert.x509 == NULL) return -1;
	util_sha256((char*)(cert.x509->cert_info->key->public_key->data), cert.x509->cert_info->key->public_key->length, result);
	return 0;
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


NodeInfoBlock_t* ctrl_ParseSignedNodeInfoBlock(unsigned short xsize, char* xblock, char* blockid)
{
    int l, r;
    char* data;
    char* nodeid;
    char nodeid2[UTIL_HASHSIZE];
    unsigned int serial;
    struct util_cert cert;
	NodeInfoBlock_t* node;
    unsigned short size = xsize - 4;
    char* block = xblock + 4;

    // Process the incoming signed block
    l = util_verify(block, size, &cert, &data);
    if (data == NULL) return NULL;
    if (l < ((UTIL_HASHSIZE * 2) + 4)) 
    {
        free(data);
        return NULL;
    }

    // Get the summary data
    nodeid = data + UTIL_HASHSIZE;
    serial = ((unsigned int*)(data + (UTIL_HASHSIZE * 2)))[0];

    // If this is our own block, ignore it... but only after checking the serial number.
    if (memcmp(g_selfid, nodeid, UTIL_HASHSIZE) == 0)
    {
        if (serial > g_serial)
        {
            // Found a higher serial number. Set the new serial and clear our current node block.
            g_serial = serial + 1;
            if (g_signedblock != NULL) free(g_signedblock);
            if (g_signedblockhash != NULL) free(g_signedblockhash);
            g_signedblock = NULL;
            g_signedblockhash = NULL;
            ctrl_GetCurrentSignedNodeInfoBlock(NULL);
        }

        // Ignore our own node
        util_freecert(&cert);
        free(data);
        return NULL;
    }

    // Check the NodeID against the cert public key hash
    util_keyhash(cert, nodeid2);
    if (memcmp(nodeid, nodeid2, UTIL_HASHSIZE) != 0)
    {
        // Failed NodeId check.
        util_freecert(&cert);
        free(data);
        return NULL;
    }
    util_freecert(&cert);

    // Parse the data
    node = info_ParseInfoBlock(data, l, ((UTIL_HASHSIZE * 2) + 4));

    // Save the node in the database
    r = mdb_blockset(nodeid, serial, xblock, xsize);
    if (blockid != NULL) memcpy(blockid, nodeid, UTIL_HASHSIZE);

    // If this node is new or updated, analyse the information
    if (r > 0) ctrl_AnalyseNewPushBlock(node, r);

    return node;
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
*/
	return 0;
}

// Process a single block of data.
// OUT: If blockid is not null, it must point to 32 bytes of free memory.
// IN : If the sender's nodeid is known, it will be in nodeid;
int ctrl_ProcessDataBlock(char* block, int blocklen, char* blockid, char* nodeid, struct sockaddr_in6 *remoteInterface, char* returnkey)
{
    NodeInfoBlock_t* node;
    unsigned short type, size;

    // Decode the block header
    if (blocklen < 4) return 0;
    type = ((unsigned short*)(block))[0];
    size = ((unsigned short*)(block))[1];

    // Must check block length overrun here.
    if (size > blocklen) return 0;

    // Switch on the block type
    switch(type)
    {
		case PB_NODEPUSH: // Standard push block
			// Parse the data and add it to the database if needed
			node = ctrl_ParseSignedNodeInfoBlock(size, block, NULL);
			if (node != NULL)
			{

	#ifdef WIN32 // DEBUG
				if (size == 0)
				{
					__asm int 3;
				}
	#endif

				MSG3("Incoming node block, size=%d, name=%s\r\n", size, node->compinfo->name);
				info_FreeInfoBlock(node);
			}
			else
			{
				MSG2("Incoming bad or self node block, size=%d\r\n", size);
			}
			break;
		case PB_AESCRYPTO: // AES-256 encrypted block, decrypt this and run it thru again.
		{
			char *data;
			int len;
			char sourcenode[UTIL_HASHSIZE];

			if ((len = util_decipher(block, size, &data, sourcenode)) == 0)
			{
				//MSG("AES-128-CBC decode FAILED.\r\n");
				break;
			}
			if (blockid != NULL) memcpy(blockid, sourcenode, UTIL_HASHSIZE);

			// If the first block is the return key, use it.
			// Then process the blocks and free the data
			if (((unsigned short*)data)[0] == PB_SESSIONKEY && ((unsigned short*)data)[1] == 40)
			{
				ctrl_ProcessDataBlocks(data + 40, len - 40, blockid, sourcenode, remoteInterface, data + 4);
			}
			else
			{
				ctrl_ProcessDataBlocks(data, len, blockid, sourcenode, remoteInterface, NULL);
			}

			free(data);
		}
		break;
		case PB_SESSIONKEY: // This is a private session key, store it in the database
		{
			// If this is a proper key and we know for what node, store the key in the target database
			if (nodeid != NULL && size == 40) mdb_setsessionkey(nodeid, block + 4);
		}
		break;
		case PB_SYNCSTART:
		{
			// Use to start a sync session, lets fetch a setup of record data and send it back.
			if (nodeid != NULL && size == 36 && remoteInterface != NULL)
			{
				char* data = NULL;
				int datalen = 0;
				char sessionkey[36];
				char nodeid2[32];
				unsigned char power;

				if (returnkey == NULL)
				{
					// Fetch the session key for this node, if we don't already have a return key
					((unsigned int*)sessionkey)[0] = 0;
					if (mdb_gettargetstate((struct sockaddr*)remoteInterface, nodeid2, &power, sessionkey, NULL) == 0) break; // If we don't have state for this target, exit.
					if (((unsigned int*)sessionkey)[0] == 0 || memcmp(nodeid, nodeid2, 32) != 0) break; // This packet was received from an unexpected source
				}

				// Fetch a block of metadata, maximum size of the block is 1000 bytes
				datalen = mdb_getmetadatablock(block + 4, 1000, &data, nodeid);

				// Send it back to the requester & free the block
				///if (data != NULL && datalen != 0) SendCryptoUdpToTarget((struct sockaddr*)remoteInterface, nodeid, returnkey == NULL?sessionkey:returnkey, data, datalen, 0);
				free(data);
			}
		}
		break;
		case PB_SYNCMETADATA:
		{
			// We received metadata from another node, lets compare it against our own data and see what is different
			if (nodeid != NULL && size >= 36 && remoteInterface != NULL)
			{
				char sessionkey[36];
				char nodeid2[32];
				unsigned char power;
				unsigned int serial;

				if (returnkey == NULL)
				{
					// Fetch the session key for this node, if we don't already have a return key					((unsigned int*)sessionkey)[0] = 0;
					if (mdb_gettargetstate((struct sockaddr*)remoteInterface, nodeid2, &power, sessionkey, &serial) == 0) break; // If we don't have state for this target, exit.
					if (((unsigned int*)sessionkey)[0] == 0 || memcmp(nodeid, nodeid2, 32) != 0) break; // This packet was received from an unexpected source
				}

				// Since we have proof that a node is at a given address and running, update the target.
				if (remoteInterface != NULL) mdb_updatetarget(nodeid, (struct sockaddr*)remoteInterface, MDB_AGENT, 1);

				// Now, our database module will do the really difficult work
				mdb_performsync(block + 4, size - 4, nodeid, (struct sockaddr*)remoteInterface, returnkey == NULL?sessionkey:returnkey, serial);

				// One more thing, lets fire the metadata from this node as an event, but we need to also include the source node in the event.
				if (ctrl_SubscriptionChainCount > 0)
				{
					// This is an expensive memcopy, would be nice to find a way around it. Still, it only happens when there are local subscribers.
					char* buf;
					if ((buf = malloc(36 + size)) == NULL) ILIBCRITICALEXIT(254);
					((unsigned short*)buf)[0] = PB_NODEID;
					((unsigned short*)buf)[1] = 36;
					memcpy(buf + 4, nodeid, 32);
					memcpy(buf + 36, block, size);
					ctrl_SendSubscriptionEvent(buf, size + 36);
					free(buf);
				}
			}
		}
		break;
		case PB_SYNCREQUEST:
		{
			// This is a list of requested blocks, lets push them back.
			if (nodeid != NULL && size >= 36 && remoteInterface != NULL)
			{
				int ptr = 4;
				char* data;
				int datalen;
				char sessionkey[36];
				char nodeid2[32];
				unsigned char power;

				if (returnkey == NULL)
				{
					// Fetch the session key for this node, if we don't already have a return key
					((unsigned int*)sessionkey)[0] = 0;
					if (mdb_gettargetstate((struct sockaddr*)remoteInterface, nodeid2, &power, sessionkey, NULL) == 0) break; // If we don't have state for this target, exit.
					if (((unsigned int*)sessionkey)[0] == 0 || memcmp(nodeid, nodeid2, 32) != 0) break; // This packet was received from an unexpected source
				}

				// Go thru the list of requests and send them all
				while (ptr < size)
				{
					// Fetch the block from the database
					datalen = mdb_blockget(block + ptr, &data);
					if (data != NULL)
					{
						// We got the requested block, send it out
						//SendCryptoUdpToTarget((struct sockaddr*)remoteInterface, nodeid, returnkey == NULL?sessionkey:returnkey, data, datalen, 0);
						free(data);
					}
					else
					{
						// This block is not in the database, check to see if the request is for our own block
						if (memcmp(block + ptr, g_selfid, UTIL_HASHSIZE) == 0 && g_signedblock != NULL && g_signedblocklen != 0)
						{
							// Yes, it's out own block, send it out. This is simple, we got that in memory and ready to go.
							///SendCryptoUdpToTarget((struct sockaddr*)remoteInterface, nodeid, returnkey == NULL?sessionkey:returnkey, g_signedblock, g_signedblocklen, 0);
						}
					}
					ptr += 32;
				}
			}
		}
		break;
		case PB_NODEID:
		{
			if (blockid != NULL && size == 36 && remoteInterface != NULL)
			{
				// This is a simple NodeID block
				memcpy(blockid, block+4, UTIL_HASHSIZE);
			}
		}
		break;
		case PB_AGENTID:
		{
			if (size == 10 && remoteInterface != NULL)
			{
				struct HttpRequestBlock* user;
				unsigned short r_agentid = ntohs(((unsigned short*)block)[4]);
				unsigned long r_agentversion = ntohl(((unsigned int*)block)[1]);

				// Let check to see if this node has a better version of the agent
				if (g_PerformingSelfUpdate == 0 && g_agentid != 0 && r_agentid != 0 && g_agentid == r_agentid && r_agentversion > MESH_AGENT_VERSION)
				{
					// Attempt an HTTP connection to that target
					if ((user = malloc(sizeof(struct HttpRequestBlock))) == NULL) ILIBCRITICALEXIT(254);
					memset(user, 0, sizeof(struct HttpRequestBlock));
					if ((user->addr = malloc(sizeof(struct sockaddr_in6))) == NULL) ILIBCRITICALEXIT(254);

					// Copy the address and set to port
					memcpy(user->addr, remoteInterface, sizeof(struct sockaddr_in6));
					if (((struct sockaddr_in*)(user->addr))->sin_family == AF_INET) ((struct sockaddr_in*)(user->addr))->sin_port = htons(MESH_AGENT_PORT);
					else ((struct sockaddr_in6*)(user->addr))->sin6_port = htons(MESH_AGENT_PORT);

					// Setup and perform the HTTP request to get the updated executable
					user->requesttype = 3;
					g_PerformingSelfUpdate = 1;
					///PerformHttpRequest(1, (struct sockaddr*)user->addr, "/mesh/selfexe.bin", user, NULL, 0);
				}
			}
		}
		break;
		default:
			MSG3("Incoming block, type=%d, size=%d\r\n", type, size);
	#ifdef WIN32
			//_asm int 3;
	#endif
			break;
    }
    return size;
}

// Process a series of blocks
// OUT: If blockid is not null, it must point to 32 bytes of free memory.
// IN : If the sender's nodeid is known, it will be in nodeid;
int ctrl_ProcessDataBlocks(char* block, int blocklen, char* blockid, char* nodeid, struct sockaddr_in6 *remoteInterface, char* returnkey)
{
    int bl, ptr = 0;
    mdb_begin();
    while ((blocklen - ptr) > 4)
    {
        // Process this block of data
        if ((bl = ctrl_ProcessDataBlock(block + ptr, blocklen - ptr, (ptr==0)?blockid:NULL, nodeid, remoteInterface, returnkey)) == 0) break;
        ptr += bl;
    }
    mdb_commit();
    return ptr;
}

// Sync with another node
void ctrl_SyncToNodeUDP(struct sockaddr *addr, char *nodeid, int state, char* key, char* nextsyncblock, unsigned int lastcontact, unsigned int serial)
{
    // If this target is in Intel(R) AMT only mode, keep using Intel(R) AMT for sync.
    if (state == MDB_AMTONLY) return;

    // Send Syncronization Request
    if (key != NULL && ((unsigned int*)key)[0] != 0)
    {
        ///SendCryptoUdpToTarget(addr, nodeid, key, nextsyncblock, 36, 1); // Send the SYNCSTART block using UDP
    }
}
/*
// Sync with another node
void ctrl_SyncToNodeTCP(struct sockaddr *addr, char *nodeid, int state, char* key, char* nextsyncblock, unsigned int lastcontact, unsigned int serial)
{
    struct HttpRequestBlock* user;
    NodeInfoBlock_t* nodeinfo;
    char* post;

    // If this target is in Intel(R) AMT only mode, keep using Intel(R) AMT for sync.
    if (state == MDB_AMTONLY)
    {
        if ((nodeinfo = ctrl_GetNodeInfoBlock(nodeid)) != NULL)
        {
            if (nodeinfo->meinfo != NULL && nodeinfo->meinfo->guestuser[0] != 0 && nodeinfo->meinfo->guestpassword[0] != 0)
            {
                // Launch a sync with Intel AMT
                ctrl_SyncToIntelAmt(nodeinfo->meinfo->tlsenabled, addr, (nodeinfo->meinfo->tlsenabled==0?16992:16993), nodeid, (char*)(nodeinfo->meinfo->guestuser), (char*)(nodeinfo->meinfo->guestpassword));
            }
            else
            {
                // Target is in Intel AMT mode but with not Intel AMT credentials. In this rare case, remove this target.
                mdb_updatetarget(NULL, addr, MDB_UNKNOWN, 0);
            }
            info_FreeInfoBlock(nodeinfo);
        }
        return;
    }

    // Let perform a normal agent-to-agent QuickSick connection. Setup the request.
    if ((user = malloc(sizeof(struct HttpRequestBlock))) == NULL) ILIBCRITICALEXIT(254);
    memset(user, 0, sizeof(struct HttpRequestBlock));
    user->requesttype = 1;
    if ((user->nodeid = malloc(UTIL_HASHSIZE)) == NULL) ILIBCRITICALEXIT(254);
    memcpy(user->nodeid, nodeid, UTIL_HASHSIZE);
    if ((user->addr = malloc(sizeof(struct sockaddr_in6))) == NULL) ILIBCRITICALEXIT(254);
    memcpy(user->addr, addr, INET_SOCKADDR_LENGTH(addr->sa_family));

    // We need to package own NodeID & serial number in the post
    if ((post = malloc(4 + UTIL_HASHSIZE)) == NULL) ILIBCRITICALEXIT(254);
    ((unsigned int*)post)[0] = htonl(serial);
    memcpy(post + 4, nodeid, UTIL_HASHSIZE);

    // This will launch a TLS connection and ask for the remote push block and session key
    PerformHttpRequest(1, addr, "/mesh/quicksync.bin", user, post, 4 + UTIL_HASHSIZE);
}
*/
/**
// Get the node information block for a given NodeID
// TODO: Optimize: This method is far from optimal since it re-verifies the PKCS#7 signature, etc.
// a possible solution is to avoid calling this and store seperate computer data in the database
// upon first decode.*/
NodeInfoBlock_t* ctrl_GetNodeInfoBlock(char* nodeid)
{
    char* block;
    int len;
    struct util_cert cert;
    char* data;

    // Fetch the block from the database
    len = mdb_blockget(nodeid, &block);
    if (block == NULL) return NULL;

    // Unpack the PKCS#12 message
    len = util_verify(block+4, len-4, &cert, &data);
    util_freecert(&cert);
    free(block);

    // Parse the computer information
    return info_ParseInfoBlock(data, len, ((UTIL_HASHSIZE * 2) + 4));
}



// This method is called when a new push block is received that is better than the previous
// one we had before or this is a completely new block. We should look into the block to see
// if there is anything interesting.
void ctrl_AnalyseNewPushBlock(NodeInfoBlock_t* node, int newnode)
{
    //info_PrintInfoBlock(node);
}

// Add a local event subscriber. Only the port is needed because the target will be IPv4 127.0.0.1
// Subscribers must renew subscriptions every 2 minutes
void ctrl_AddSubscription(unsigned short port)
{
    int i = 0;
    char e = LOCALEVENT_UNSUBSCRIBE;
    unsigned long time = util_gettime();
    unsigned long expired = time - (60000 * MESH_LOCAL_EVENT_SUBSCRIPTION_TIMEOUT);				// Minutes event expiration
    ctrl_SubscriptionLoopback.sin_port = port;

    // Go thru the list and find a spot for this new subscriber. It's possible this is just a renewal.
    ctrl_SubscriptionChainCount++;
    while (i < 8)
    {
        if (ctrl_SubscriptionChain[i].time < expired || ctrl_SubscriptionChain[i].port == port)
        {
            ctrl_SubscriptionChain[i].time = time;
            ctrl_SubscriptionChain[i].port = port;
            e = LOCALEVENT_SUBSCRIBE;
            time = 0;
            port = 0;
        }
        i++;
    }

    // Send an unicast event back to the subscriber
    // old line DRE 2022    
    //UnicastUdpPacket((struct sockaddr*)&ctrl_SubscriptionLoopback, &e, 1);
    // new line getting rid of fcn call and replacing function params
    ILibMulticastSocket_Unicast(Mesh.MulticastSocket, (struct sockaddr*)&ctrl_SubscriptionLoopback,  &e, 1);    
}

// Remove a local event subscriber
void ctrl_RemoveSubscription(unsigned short port)
{
    int i = 0;
    char e = LOCALEVENT_UNSUBSCRIBE;

    // Go thru the list and find subscriber to delete
    while (i < 8)
    {
        if (ctrl_SubscriptionChain[i].port == port) ctrl_SubscriptionChain[i].time = ctrl_SubscriptionChain[i].port = 0;
        i++;
    }

    // Send an unicast event back to the subscriber
    ctrl_SubscriptionLoopback.sin_port = port;
    // old line DRE 2022
    // UnicastUdpPacket((struct sockaddr*)&ctrl_SubscriptionLoopback, &e, 1);
    // new line getting rid of fcn call and replacing function params
    ILibMulticastSocket_Unicast(Mesh.MulticastSocket, (struct sockaddr*)&ctrl_SubscriptionLoopback,  &e, 1);
}

// Notify the subscribers of an event. All valid subscribers will get a UDP packet
extern char IPv4Loopback[4];
void ctrl_SendSubscriptionEvent(char *data, int datalen)
{
    int i = 0;
    int count = 0;
    unsigned long expired;

    if (ctrl_SubscriptionChainCount == 0) return;
    expired = util_gettime() - (60000 * MESH_LOCAL_EVENT_SUBSCRIPTION_TIMEOUT);	// Minutes event expiration
    while (i < 8)
    {
        if (ctrl_SubscriptionChain[i].time > expired && ctrl_SubscriptionChain[i].port != 0)
        {
            // Send the event using UDP to 127.0.0.1 and the specified port
            ctrl_SubscriptionLoopback.sin_port = ctrl_SubscriptionChain[i].port;
            // old line DRE 2022
            //UnicastUdpPacket((struct sockaddr*)&ctrl_SubscriptionLoopback, data, datalen);
            // new line getting rid of fcn call and replacing function params
            ILibMulticastSocket_Unicast(Mesh.MulticastSocket, (struct sockaddr*)&ctrl_SubscriptionLoopback, data, datalen);
            count++;
        }
        i++;
    }
    ctrl_SubscriptionChainCount = count;
}

char* ctrl_GetChallengeHash(char* nonce, char* secret, int counter)
{
    char input[68];
    char* output;
    if ((output = malloc(UTIL_HASHSIZE)) == NULL) return NULL;

    // temp3 = Hash(random + secret + counter)
    memcpy(input, nonce, 32);
    memcpy(input + 32, secret, 32);
    memcpy(input + 64, (char*)&counter, 4);
    util_sha256(input, 68, output);

    return output;
}
/**
// Generates a node challenge block, used to check the identitiy of a node
int ctrl_GetNodeChallenge(char* secret, int counter, char** challenge)
{
    char random[32];
    char* temp3 = NULL;
    char* block;
    *challenge = NULL;

    // Get random string and compute hash
    util_random(32, random);
    temp3 = ctrl_GetChallengeHash(random, secret, counter);
    if (temp3 == NULL) return 0;
    if ((block = malloc(72)) == NULL) ILIBCRITICALEXIT(254);

    // block = header + counter + hash + random
    ((unsigned short*)block)[0] = PB_NODECHALLENGE;	// Block Type
    ((unsigned short*)block)[1] = 72;				// Block Length
    memcpy(block + 4, (char*)&counter, 4);			// Counter
    memcpy(block + 8, temp3, 32);					// Hash
    memcpy(block + 40, random, 32);					// Random

    // Cleanup
    free(temp3);

    *challenge = block;
    return 72;
}

// Resolves a node identity challenge, returning a response block
int ctrl_PerformNodeChallenge(struct util_cert cert, char* challenge, int challengelen, char** response)
{
    int len;
    char* sign = NULL;
    char* block;
    char* challenge2;
    *response = NULL;
    if (challenge == NULL || challengelen != 72) return 0;
    if (((unsigned short*)challenge)[0] != PB_NODECHALLENGE) return 0;
    if (((unsigned short*)challenge)[1] != 72) return 0;

    // Build the same block but with 32 bytes spare in front.
    if ((challenge2 = malloc(32 + 68)) == NULL) return 0;
    memcpy(challenge2 + 32, challenge + 4, 68);

    // Sign and build a response
    len = util_sign(cert, challenge2, 32 + 68, &sign);
    free(challenge2);
    if (len == 0 || sign == NULL) return 0;
    if ((block = malloc(len + 4)) == NULL) return 0;
    ((unsigned short*)block)[0] = PB_NODECRESPONSE;	// Block Type
    ((unsigned short*)block)[1] = (unsigned short)len + 4;			// Block Length
    memcpy(block + 4, sign, len);
    free(sign);

    *response = block;
    return len + 4;
}

// Checks a node challenge block, returns the node identifier
int ctrl_CheckNodeChallenge(char* secret, char* response, int len, char* nodeid, int* counter)
{
    int templen;
    char* temp = NULL;
    char* temp3 = NULL;
    struct util_cert cert;
    if (response == NULL || len < 8) return 0;
    if (((unsigned short*)response)[0] != PB_NODECRESPONSE) return -1;
    if (((unsigned short*)response)[1] != len) return -1;

    UNREFERENCED_PARAMETER( counter );

    // Check the signature
    templen = util_verify(response + 4, len - 4, &cert, &temp);
    if (temp == NULL) return 0;
    if (templen != 100) goto error; // Signature verification failed

    // Check the hash
    temp3 = ctrl_GetChallengeHash(temp + 32 + 36, secret, ((int*)(temp + 32))[0]);
    if (temp3 == NULL) goto error;
    if (memcmp(temp3, temp + 32 + 4, 32) != 0) goto error; // Failed the hash check

    // Get the node identifier
    util_keyhash(cert, nodeid);

    // Cleanup
    util_freecert(&cert);
    free(temp);
    free(temp3);

    return 0;

    //! \note commented out certification
error:
    //if (cert.pkey != NULL || cert.x509 != NULL) util_freecert(&cert);
    if (temp != NULL) free(temp);
    if (temp3 != NULL) free(temp3);
    return -1;
}
*/
// Initiate a sync to another nodes Intel AMT.
// Intel AMT username and password will be fetched from database once we get the Intel AMT TLS certificate...
void ctrl_SyncToIntelAmt(int tls, struct sockaddr *addr, unsigned short port, char* nodeid, char* username, char* password)
{
    struct HttpRequestBlock* user;
    size_t len;

    // Setup the request
    if ((user = malloc(sizeof(struct HttpRequestBlock))) == NULL) ILIBCRITICALEXIT(254);
    memset(user, 0, sizeof(struct HttpRequestBlock));
    user->requesttype = 2;

    // Setup the target address
    if (addr->sa_family == AF_INET6) ((struct sockaddr_in6*)addr)->sin6_port = htons(port);
    if (addr->sa_family == AF_INET) ((struct sockaddr_in*)addr)->sin_port = htons(port);
    if ((user->addr = malloc(sizeof(struct sockaddr_in6))) == NULL) ILIBCRITICALEXIT(254);
    memcpy(user->addr, &addr, sizeof(struct sockaddr_in6));

    // Copy NodeID
    if ((user->nodeid = malloc(UTIL_HASHSIZE)) == NULL) ILIBCRITICALEXIT(254);
    memcpy(user->nodeid, nodeid, UTIL_HASHSIZE);

    // Copy username
    len = strlen(username) + 1;
    if ((user->username = malloc(len)) == NULL) ILIBCRITICALEXIT(254);
    memcpy(user->username, username, len);

    // Copy password
    len = strlen(password) + 1;
    if ((user->password = malloc(len)) == NULL) ILIBCRITICALEXIT(254);
    memcpy(user->password, password, len);

    // Update the target attempt time
    mdb_attempttarget((struct sockaddr*)&addr);

    // Send the request
    //PerformHttpRequest(tls, (struct sockaddr*)&addr, "/index.htm", user, NULL, 0);
}

// Setup the local Intel(R) AMT admin username and password
void ctrl_SetLocalIntelAmtAdmin(int tls, char* username, char* password)
{
    // TODO: Verify that these setting are correct before storing.
    mdb_set_i("amt_tls", (tls==0)?0:1);
    mdb_set("amt_admin_user", username, (int)strlen(username));
    mdb_set("amt_admin_pass", password, (int)strlen(password));

    // TODO: Use the admin account to setup uguest account.
    mdb_set("amt_guest_user", username, (int)strlen(username));
    mdb_set("amt_guest_pass", password, (int)strlen(password));

    // Reset our current node info block
    ctrl_GetCurrentSignedNodeInfoBlock(NULL);
}

#ifdef WIN32
// Perform self-update (Windows console/tray version)
void ctrl_PerformSelfUpdate(char* selfpath, char* exepath)
{
    STARTUPINFOA info = {sizeof(info)};
    PROCESS_INFORMATION processInfo;

    // First, we wait a little to give time for the calling process to exit
    Sleep(5000);

    // Attempt to copy our own exe over the
    remove(exepath);
    CopyFileA(selfpath, exepath, FALSE);

    // Now run the process
    if (!CreateProcessA(NULL, exepath, NULL, NULL, TRUE, 0, NULL, NULL, &info, &processInfo))
    {
        // TODO: Failed to run update.
    }
}
#else
// Perform self-update (Linux version)
void ctrl_PerformSelfUpdate(char* selfpath, char* exepath)
{
    char temp[6000];

    // First, we wait a little to give time for the calling process to exit
    sleep(5);

    // Attempt to copy our own exe over the
    remove(exepath);
    snprintf(temp, 6000, "cp %s %s", selfpath, exepath);
    system(temp);

    // Now run the updated process
    snprintf(temp, 6000, "%s &", exepath);
    system(temp);
}
#endif


/*! 
 * SQLite Storage Classes

Each value stored in an SQLite database has one of the following storage classes −
Sr.No. 	Storage Class & Description
1 	

NULL

The value is a NULL value.
2 	

INTEGER

The value is a signed integer, stored in 1, 2, 3, 4, 6, or 8 bytes depending on the magnitude of the value.
3 	

REAL

The value is a floating point value, stored as an 8-byte IEEE floating point number.
4 	

TEXT

The value is a text string, stored using the database encoding (UTF-8, UTF-16BE or UTF-16LE)
5 	

BLOB

The value is a blob of data, stored exactly as it was input.

SQLite storage class is slightly more general than a datatype. The INTEGER storage class, for example, includes 6 different integer datatypes of different lengths.
SQLite Affinity Type

SQLite supports the concept of type affinity on columns. Any column can still store any type of data but the preferred storage class for a column is called its affinity. Each table column in an SQLite3 database is assigned one of the following type affinities −
Sr.No. 	Affinity & Description
1 	 TEXT

This column stores all data using storage classes NULL, TEXT or BLOB.
2 	NUMERIC

This column may contain values using all five storage classes.
3 	INTEGER

Behaves the same as a column with NUMERIC affinity, with an exception in a CAST expression.
4 	REAL

Behaves like a column with NUMERIC affinity except that it forces integer values into floating point representation.
5 	NONE

A column with affinity NONE does not prefer one storage class over another and no attempt is made to coerce data from one storage class into another.
SQLite Affinity and Type Names

Following table lists down various data type names which can be used while creating SQLite3 tables with the corresponding applied affinity.
Data Type 						Affinity

    INT
    INTEGER
    TINYINT
    SMALLINT					INTEGER
    MEDIUMINT
    BIGINT
    UNSIGNED BIG INT
    INT2
    INT8

	

    CHARACTER(20)
    VARCHAR(255)
    VARYING CHARACTER(255)	    TEXT
    NCHAR(55)
    NATIVE CHARACTER(70)
    NVARCHAR(100)
    TEXT
    CLOB

	

    BLOB					 no datatype specified
   

	NONE

    REAL					REAL
    DOUBLE
    DOUBLE PRECISION
    FLOAT

	

    NUMERIC
    DECIMAL(10,5)			NUMERIC
    BOOLEAN
    DATE   				    DATETIME

	
Boolean Datatype

SQLite does not have a separate Boolean storage class. Instead, Boolean values are stored as integers 0 (false) and 1 (true).
Date and Time Datatype

SQLite does not have a separate storage class for storing dates and/or times, but SQLite is capable of storing dates and times as TEXT, REAL or INTEGER values.
Sr.No. 		Storage  Class & Date Formate
1 			TEXT     A date in a format like "YYYY-MM-DD HH:MM:SS.SSS"
2 			REAL     The number of days since noon in Greenwich on November 24, 4714 B.C.
3 			INTEGER  The number of seconds since 1970-01-01 00:00:00 UTC

You can choose to store dates and times in any of these formats and freely convert between formats using the built-in date and time functions.
 * 
 * 
 * */



sqlite3 *db = NULL;
sqlite3 *mdb = NULL;
const char *zErrMsg = 0;
//! \var rc is the global rc from the database functions
int rc;

unsigned int synccounter;

#define DB_VERSION 1
#define INET_SOCKADDR_LENGTH(x) ((x==AF_INET6?sizeof(struct sockaddr_in6):sizeof(struct sockaddr_in)))

// Block Prepared Statements
sqlite3_stmt *stmt_obtain_block;
sqlite3_stmt *stmt_delete_block;
sqlite3_stmt *stmt_insert_block;
sqlite3_stmt *stmt_update_block;
sqlite3_stmt *stmt_metadt_block;

// Node Prepared Statements
sqlite3_stmt *stmt_insert_target;
sqlite3_stmt *stmt_atempt_target;
sqlite3_stmt *stmt_update_target;
sqlite3_stmt *stmt_obtain_target;
sqlite3_stmt *stmt_select_target;
sqlite3_stmt *stmt_rowcnt_target;
sqlite3_stmt *stmt_workit_target;
sqlite3_stmt *stmt_delete_target;
sqlite3_stmt *stmt_setkey_target;
sqlite3_stmt *stmt_metaup_target;
sqlite3_stmt *stmt_metadt_target;

// Settings Prepared Statements
sqlite3_stmt *stmt_obtain_setting;
sqlite3_stmt *stmt_delete_setting;
sqlite3_stmt *stmt_update_setting;

// Settings Prepared Statements
sqlite3_stmt *stmt_obtain_events;
sqlite3_stmt *stmt_insert_events;

//! \note These are great for understanding the way that this source code 


// Block Statement Strings
const char* stmt_obtain_block_str = "SELECT * FROM blocks WHERE blockid=?1";
const char* stmt_getall_block_str = "SELECT * FROM blocks WHERE synccount>?1";
const char* stmt_delete_block_str = "DELETE FROM blocks WHERE blockid=?1";
const char* stmt_insert_block_str = "INSERT INTO blocks VALUES (?1, ?2, ?3, DATETIME('now'), ?4, ?5)";
const char* stmt_update_block_str = "UPDATE blocks SET serial=?2, data=?3, schange=DATETIME('now'), synccount=?4 WHERE blockid=?1";
const char* stmt_metadt_block_str = "SELECT blockid, serial, data FROM blocks WHERE blockid > ?1 ORDER BY blockid";

// Targets Statement Strings
const char* stmt_insert_target_str = "INSERT INTO targets VALUES (?1, ?2, ?3, DATETIME('now'), \"1960-01-01 00:00:00\", ?4, NULL, 0, ?5, ?6, ?7)";
const char* stmt_atempt_target_str = "UPDATE targets SET lastattempt=DATETIME('now') WHERE address=?1";
const char* stmt_update_target_str = "UPDATE targets SET blockid=?2, lastattempt=DATETIME('now'), lastcontact=DATETIME('now'), state=?3, power=?4, distance=?5 WHERE address=?1";
const char* stmt_obtain_target_str = "SELECT blockid, state, power, sessionkey, serial FROM targets WHERE address=?1";
const char* stmt_select_target_str = "SELECT *, strftime('%s', 'now') - strftime('%s', lastcontact) FROM targets";
const char* stmt_rowcnt_target_str = "SELECT COUNT(*) FROM targets";
const char* stmt_workit_target_str = "SELECT *, strftime('%s', 'now') - strftime('%s', lastcontact) FROM targets WHERE lastattempt < DATETIME('now', '-10 seconds') ORDER BY lastattempt"; // -5 minutes is normal
const char* stmt_delete_target_str = "DELETE FROM targets WHERE address=?1 AND lastcontact < DATETIME('now', '-60 seconds')";
const char* stmt_setkey_target_str = "UPDATE targets SET sessionkey=?2 WHERE blockid=?1";
const char* stmt_metaup_target_str = "UPDATE targets SET nextsync=?2 WHERE blockid=?1";
const char* stmt_metadt_target_str = "SELECT blockid, serial FROM targets WHERE blockid > ?1 GROUP BY blockid ORDER BY blockid";

// Temporary queries
const char* stmt_getserial_str = "SELECT serial FROM blocks WHERE blockid=?1";
const char* stmt_setserial_str = "UPDATE targets SET serial=?2 WHERE blockid=?1";
const char* stmt_getbucket_str = "SELECT distance, count(*) FROM targets WHERE state != 2 GROUP BY distance"; // All nodes that are not in Intel AMT mode (State 2) count against buckets.

// Settings Statement Strings
const char* stmt_obtain_setting_str = "SELECT sdata FROM settings WHERE skey=?1";
const char* stmt_delete_setting_str = "DELETE FROM settings WHERE skey=?1";
const char* stmt_update_setting_str = "REPLACE INTO settings VALUES (?1, ?2)";

// Events Statement Strings
const char* stmt_obtain_event_str = "SELECT * FROM events ORDER BY id DESC";
const char* stmt_insert_event_str = "INSERT INTO events VALUES (NULL, DATETIME('now'), ?1)";

// Database creation Strings
const char* stmt_create_event_str = "INSERT INTO events VALUES (NULL, DATETIME('now'), ?1)";

unsigned int mdb_getsynccounter() 
{
    return synccounter;
}
unsigned int mdb_addsynccounter() 
{
    return ++synccounter;
}
/*
** CAPI3REF: One-Step Query Execution Interface
** METHOD: sqlite3
**
** The sqlite3_exec() interface is a convenience wrapper around
** [sqlite3_prepare_v2()], [sqlite3_step()], and [sqlite3_finalize()],
** that allows an application to run multiple statements of SQL
** without having to use a lot of C code.
**
** ^The sqlite3_exec() interface runs zero or more UTF-8 encoded,
** semicolon-separate SQL statements passed into its 2nd argument,
** in the context of the [database connection] passed in as its 1st
** argument.  ^If the callback function of the 3rd argument to
** sqlite3_exec() is not NULL, then it is invoked for each result row
** coming out of the evaluated SQL statements.  ^The 4th argument to
** sqlite3_exec() is relayed through to the 1st argument of each
** callback invocation.  ^If the callback pointer to sqlite3_exec()
** is NULL, then no callback is ever invoked and result rows are
** ignored.
**
** ^If an error occurs while evaluating the SQL statements passed into
** sqlite3_exec(), then execution of the current statement stops and
** subsequent statements are skipped.  ^If the 5th parameter to sqlite3_exec()
** is not NULL then any error message is written into memory obtained
** from [sqlite3_malloc()] and passed back through the 5th parameter.
** To avoid memory leaks, the application should invoke [sqlite3_free()]
** on error message strings returned through the 5th parameter of
** sqlite3_exec() after the error message string is no longer needed.
** ^If the 5th parameter to sqlite3_exec() is not NULL and no errors
** occur, then sqlite3_exec() sets the pointer in its 5th parameter to
** NULL before returning.
**
** ^If an sqlite3_exec() callback returns non-zero, the sqlite3_exec()
** routine returns SQLITE_ABORT without invoking the callback again and
** without running any subsequent SQL statements.
**
** ^The 2nd argument to the sqlite3_exec() callback function is the
** number of columns in the result.  ^The 3rd argument to the sqlite3_exec()
** callback is an array of pointers to strings obtained as if from
** [sqlite3_column_text()], one for each column.  ^If an element of a
** result row is NULL then the corresponding string pointer for the
** sqlite3_exec() callback is a NULL pointer.  ^The 4th argument to the
** sqlite3_exec() callback is an array of pointers to strings where each
** entry represents the name of corresponding result column as obtained
** from [sqlite3_column_name()].
**
** ^If the 2nd parameter to sqlite3_exec() is a NULL pointer, a pointer
** to an empty string, or a pointer that contains only whitespace and/or
** SQL comments, then no SQL statements are evaluated and the database
** is not changed.
**
** Restrictions:
**
** <ul>
** <li> The application must ensure that the 1st parameter to sqlite3_exec()
**      is a valid and open [database connection].
** <li> The application must not close the [database connection] specified by
**      the 1st parameter to sqlite3_exec() while sqlite3_exec() is running.
** <li> The application must not modify the SQL statement text passed into
**      the 2nd parameter of sqlite3_exec() while sqlite3_exec() is running.
** </ul>
*/
// typedef int (*sqlite3_callback)(void*,int,char**, char**);

//int print_yes(void* a, int b, char**c, char**d)
//{
//	printf("command returned b= %d\n", b);
//}
//sqlite3_callback print_stuff = print_yes;
//! \fn mdb_create start run create commands on the database file
int   mdb_create( char * filename )
{
    ///sqlite3_stmt *stmt;
    sqlite3_stmt *stmt;
    const char *tail;
    char *buf;
    unsigned int i;
    int r = 0;
    char random[64];
    char* szPathPtr = "mesh.db";
    
    
    // specify the database filename if not default.
    if (filename == NULL);
    else  szPathPtr =  filename;
        
    // creates the table in the database
    
    //! \note 
    //SQLITE_API int sqlite3_exec(
	//sqlite3*,                                  /* An open database */
	//const char *sql,                           /* SQL to be evaluated */
	//int (*callback)(void*,int,char**,char**),  /* Callback function */
	//void *,                                    /* 1st argument to callback */
	//char **errmsg                              /* Error msg written here */
	//);
    //rc = sqlite3_exec(db, "CREATE TABLE settings (skey TEXT PRIMARY KEY, sdata BLOB);", NULL, 0, NULL);
    rc = sqlite3_exec(db, "CREATE TABLE settings (skey TEXT PRIMARY KEY, sdata BLOB);", NULL, 0, "Create settings Table Failed \n");
    if (rc == 0)
    {
		// inserts tables into database
        r = 2; // Database requires setup
        rc = sqlite3_exec(db, "CREATE TABLE blocks  (blockid BOOLEAN(32) PRIMARY KEY, serial INTEGER, data BLOB, schange DATE, synccount INTEGER, blocktype INTEGER);", NULL, 0, "Create blocks Table Failed \n");
        rc = sqlite3_exec(db, "CREATE TABLE revoked (blockid BINARY(32) PRIMARY KEY, meshid BINARY(32));", NULL, 0, "Create revoked Table Failed \n");
        rc = sqlite3_exec(db, "CREATE TABLE events  (id INTEGER PRIMARY KEY, time DATE, message TEXT);", NULL, 0, "Create events Table Failed \n"); // This is for debug, but we keep it in release for compatiblity with debug build.
    }    
    // insert some valid yet dummy records to start the database off
    rc = sqlite3_exec(db, "INSERT INTO settings  (skey TEXT PRIMARY KEY, sdata BLOB) USING VALUES ( 'California', 045FFFF );", NULL, 0,  "INSERT INTO settings Failed \n");
    rc = sqlite3_exec(db, "INSERT INTO settings  (skey TEXT PRIMARY KEY, sdata BLOB)  USING VALUES ( 'Texas', 885FFFF);", NULL, 0, "INSERT INTO settings Failed \n");
    rc = sqlite3_exec(db, "INSERT INTO settings  (skey TEXT PRIMARY KEY, sdata BLOB)  USING VALUES ( 'Montana', FFFF777 );", NULL, 0, "INSERT INTO settings Failed \n");
    // insert into blocks nominal values that aren't realistic but recognizable...
    rc = sqlite3_exec(db, "INSERT INTO blocks  (blockid, serial, data, schange, synccount, blocktype) VALUES ( 0x045FFFF, 1021,  'California', 12/12/1200, 042, 99);", NULL, 0, "INSERT INTO blocks Failed \n");
    // good statement : INSERT INTO blocks  (blockid, serial, data, schange, synccount, blocktype) VALUES ( 0x045FFFF, 1022,  'California', 12/12/1200, 042, 99);
    rc = sqlite3_exec(db, "INSERT INTO blocks  (blockid, serial, data, schange, synccount, blocktype)   USING VALUES ( 0x045FFFF, 1022,  'Texas', 12/12/1200, 042, 99 );", NULL, 0, "INSERT INTO blocks Failed \n");
    rc = sqlite3_exec(db, "INSERT INTO blocks  (blockid, serial, data, schange, synccount, blocktype)   USING VALUES (  0x045FFFF, 1023,  'Montana', 12/12/1200, 042, 99 );", NULL, 0, "INSERT INTO blocks Failed \n");
    // revoked blocks
	rc = sqlite3_exec(db, "INSERT INTO revoked (blockid, meshid) USING VALUES ( 0x045FFFF,  042);", NULL, 0, "INSERT INTO revoked Failed \n");    
	rc = sqlite3_exec(db, "INSERT INTO revoked (blockid, meshid) USING VALUES ( 0x045FFFF,  042);", NULL, 0, "INSERT INTO revoked Failed \n");    
	rc = sqlite3_exec(db, "INSERT INTO revoked (blockid, meshid) USING VALUES ( 0x045FFFF,  042);", NULL, 0, "INSERT INTO revoked Failed \n");    
    // last entry 
	rc = sqlite3_exec(db, "INSERT INTO events (id INTEGER PRIMARY KEY, time DATE, message TEXT) USING VALUES ( 0x045FFFF, 12/12/1200,  'Montana');", NULL, 0, "INSERT INTO events Failed \n");    
	rc = sqlite3_exec(db, "INSERT INTO events (id INTEGER PRIMARY KEY, time DATE, message TEXT) USING VALUES ( 0x045FFFF, 12/12/1200,  'California');", NULL, 0, "INSERT INTO events Failed \n");    
	rc = sqlite3_exec(db, "INSERT INTO events (id INTEGER PRIMARY KEY, time DATE, message TEXT) USING VALUES ( 0x045FFFF, 12/12/1200,  'Texas');", NULL, 0, "INSERT INTO events Failed \n");        
    
       
}



//! \fn mdb_open start sql and use local version if var local ==0
int   mdb_open( int local )
{
    sqlite3_stmt *stmt;
    const char *tail;
    char *buf;
    unsigned int i;
    int r = 0;
    char random[64];
    char* szPathPtr = "mesh.db";

    // Fetch the database folder (Windows version)
    // When running as a service, the database will be stored in:
    // C:\Windows\system32\config\systemprofile\AppData\Roaming\MeshAgent\mesh.db
#ifdef WIN32
    char szPath[MAX_PATH];
    if (SHGetFolderPathA(NULL, CSIDL_APPDATA | CSIDL_FLAG_CREATE, NULL, SHGFP_TYPE_CURRENT, szPath) != S_FALSE)
    {
        size_t len = strlen(szPath);
        if (len + 19 <= MAX_PATH)
        {
            memcpy(szPath + len, "\\MeshAgent\\", 12);
            CreateDirectoryA(szPath, NULL); // We don't care about the error code, path may already exist.
            memcpy(szPath + len + 11, "mesh.db", 8);
            szPathPtr = szPath;
        }
    }
#endif

    // Fetch the database folder (Linux version)
#ifdef _POSIX
    //! the path to 
    char szPath[PATH_MAX];
    char* homepath;
    size_t len;
    if ( !local) // find filesystem mesh database
    {
		homepath = getenv("HOME");
		len = strlen(homepath);

		// We check "/tmp/" so not to use that folder on embedded devices (DD-WRT).
		if (len + 20 <= PATH_MAX && memcmp(homepath, "/tmp/", 5) != 0)
		{
			memcpy(szPath, homepath, len);
			memcpy(szPath + len, "/.meshagent/", 13);
			if (mkdir(szPath, S_IRWXU) == 0 || errno == EEXIST)
			{
				memcpy(szPath + len + 12, "mesh.db", 8);
				szPathPtr = szPath;
			}
		}
	}
	else // select local database
	{
		memcpy(szPath, "mesh.db", strlen("mesh.db"));
		szPathPtr = strlen("mesh.db");		
	}
#endif

    // Setup the on disk database (Used for storing signed blocks)
    if (db != NULL) return 1;
    rc = sqlite3_open_v2(szPathPtr, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL);
    if (db == NULL) return 1;
    if (rc != 0) 
    {
        mdb_checkerror();
        return 1;
    }

    // Check the database version, this is important for future proofing.
    rc = sqlite3_prepare(db, stmt_obtain_setting_str, (int)strlen(stmt_obtain_setting_str), &stmt_obtain_setting, &tail);
    if (mdb_get_i("dbversion") != DB_VERSION)
    {
        // This database has the wrong signature, delete it.
        sqlite3_finalize(stmt_obtain_setting);
        sqlite3_close(db);
        remove(szPathPtr);
        rc = sqlite3_open_v2(szPathPtr, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL);
        if (db == NULL) return 1;
        if (rc != 0) 
        {
            mdb_checkerror();
            return 1;
        }
    }
    else sqlite3_finalize(stmt_obtain_setting);

    // Lets see if the proper tables are created already
    rc = sqlite3_exec(db, "CREATE TABLE settings (skey TEXT PRIMARY KEY, sdata BLOB);", NULL, 0, NULL);
    if (rc == 0)
    {
        r = 2; // Database requires setup
        rc = sqlite3_exec(db, "CREATE TABLE blocks  (blockid BINARY(32) PRIMARY KEY, serial INTEGER, data BLOB, schange DATE, synccount INTEGER, blocktype INTEGER);", NULL, 0, NULL);
        rc = sqlite3_exec(db, "CREATE TABLE revoked (blockid BINARY(32) PRIMARY KEY, meshid BINARY(32));", NULL, 0, NULL);
        rc = sqlite3_exec(db, "CREATE TABLE events  (id INTEGER PRIMARY KEY, time DATE, message TEXT);", NULL, 0, NULL); // This is for debug, but we keep it in release for compatiblity with debug build.
    }

    // Setup the in-memory database (Used for storing dynamic node information)
#ifdef _DEBUG
    // In debug mode, we store this on disk so we can use debug tools.
    rc = sqlite3_open_v2(":memory:", &mdb, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL);
    //rc = sqlite3_open_v2("meshm.db", &mdb, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL);
    if (rc != 0) 
    {
        sqlite3_close(db);
        mdb_checkerror();
        return 1;
    }
    if (mdb == NULL) 
    {
        sqlite3_close(db);
        return 1;
    }
    rc = sqlite3_exec(mdb, "DROP TABLE nodes;", NULL, 0, NULL);
#else
    rc = sqlite3_open_v2(":memory:", &mdb, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL);
    if (rc != 0) 
    {
        mdb_checkerror();
        return 1;
    }
#endif
    rc = sqlite3_exec(mdb, "CREATE TABLE targets (address TEXT PRIMARY KEY, blockid BINARY(32), state INTEGER, lastattempt DATE, lastcontact DATE, power INTEGER, sessionkey BINARY(36), iv INTEGER, nextsync BINARY(32), serial INTEGER, distance INTEGER);", NULL, 0, NULL);

    // Prepare block statements
    rc = sqlite3_prepare(db, stmt_obtain_block_str, (int)strlen(stmt_obtain_block_str), &stmt_obtain_block, &tail);
    rc = sqlite3_prepare(db, stmt_delete_block_str, (int)strlen(stmt_delete_block_str), &stmt_delete_block, &tail);
    rc = sqlite3_prepare(db, stmt_insert_block_str, (int)strlen(stmt_insert_block_str), &stmt_insert_block, &tail);
    rc = sqlite3_prepare(db, stmt_update_block_str, (int)strlen(stmt_update_block_str), &stmt_update_block, &tail);
    rc = sqlite3_prepare(db, stmt_metadt_block_str, (int)strlen(stmt_metadt_block_str), &stmt_metadt_block, &tail);

    // Prepare node statements
    rc = sqlite3_prepare(mdb, stmt_insert_target_str, (int)strlen(stmt_insert_target_str), &stmt_insert_target, &tail);
    rc = sqlite3_prepare(mdb, stmt_atempt_target_str, (int)strlen(stmt_atempt_target_str), &stmt_atempt_target, &tail);
    rc = sqlite3_prepare(mdb, stmt_update_target_str, (int)strlen(stmt_update_target_str), &stmt_update_target, &tail);
    rc = sqlite3_prepare(mdb, stmt_obtain_target_str, (int)strlen(stmt_obtain_target_str), &stmt_obtain_target, &tail);
    rc = sqlite3_prepare(mdb, stmt_select_target_str, (int)strlen(stmt_select_target_str), &stmt_select_target, &tail);
    rc = sqlite3_prepare(mdb, stmt_rowcnt_target_str, (int)strlen(stmt_rowcnt_target_str), &stmt_rowcnt_target, &tail);
    rc = sqlite3_prepare(mdb, stmt_workit_target_str, (int)strlen(stmt_workit_target_str), &stmt_workit_target, &tail);
    rc = sqlite3_prepare(mdb, stmt_delete_target_str, (int)strlen(stmt_delete_target_str), &stmt_delete_target, &tail);
    rc = sqlite3_prepare(mdb, stmt_setkey_target_str, (int)strlen(stmt_setkey_target_str), &stmt_setkey_target, &tail);
    rc = sqlite3_prepare(mdb, stmt_metaup_target_str, (int)strlen(stmt_metaup_target_str), &stmt_metaup_target, &tail);
    rc = sqlite3_prepare(mdb, stmt_metadt_target_str, (int)strlen(stmt_metadt_target_str), &stmt_metadt_target, &tail);

    // Prepare settings statements
    rc = sqlite3_prepare(db, stmt_obtain_setting_str, (int)strlen(stmt_obtain_setting_str), &stmt_obtain_setting, &tail);
    rc = sqlite3_prepare(db, stmt_delete_setting_str, (int)strlen(stmt_delete_setting_str), &stmt_delete_setting, &tail);
    rc = sqlite3_prepare(db, stmt_update_setting_str, (int)strlen(stmt_update_setting_str), &stmt_update_setting, &tail);

    // Prepare events statements
    rc = sqlite3_prepare(db, stmt_obtain_event_str, (int)strlen(stmt_obtain_event_str), &stmt_obtain_events, &tail);
    rc = sqlite3_prepare(db, stmt_insert_event_str, (int)strlen(stmt_insert_event_str), &stmt_insert_events, &tail);

    // Setup Sync Counter & Fetch the MAX sync counter
    rc = sqlite3_prepare(db, "SELECT MAX(synccount) FROM blocks;", -1, &stmt, &tail);
    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) synccounter = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);
    i = mdb_get_i("signedblocksynccounter");
    if (i > synccounter) synccounter = i;

    // Add more random seeding and save new random for next time.
    rc = mdb_get("random", &buf);
    if (rc != 0) 
    {
		/// old code
        //RAND_add(buf, rc, rc);
        int j;
        
        /// new code a temporary set in to remove need for OpenSSL
        for (j = 0; j < sizeof(buf) - 1; j++) 
        {
			rc += (unsigned short)buf[j];
        }
        free(buf);
    }
    util_random(64, random);
    mdb_set("random", random, 64);

    // Clear the distance buckets
    memset(g_distancebuckets, 0, 32);

    // Set the database version
    mdb_set_i("dbversion", DB_VERSION);

    return r;
}

void mdb_close()
{
    // Cleanup block prepared statements
    sqlite3_finalize(stmt_obtain_block);
    sqlite3_finalize(stmt_delete_block);
    sqlite3_finalize(stmt_insert_block);
    sqlite3_finalize(stmt_update_block);
    sqlite3_finalize(stmt_metadt_block);

    // Cleanup node prepared statements
    sqlite3_finalize(stmt_insert_target);
    sqlite3_finalize(stmt_atempt_target);
    sqlite3_finalize(stmt_update_target);
    sqlite3_finalize(stmt_obtain_target);
    sqlite3_finalize(stmt_select_target);
    sqlite3_finalize(stmt_rowcnt_target);
    sqlite3_finalize(stmt_workit_target);
    sqlite3_finalize(stmt_delete_target);
    sqlite3_finalize(stmt_setkey_target);
    sqlite3_finalize(stmt_metaup_target);
    sqlite3_finalize(stmt_metadt_target);

    // Cleanup settings prepared statements
    sqlite3_finalize(stmt_obtain_setting);
    sqlite3_finalize(stmt_delete_setting);
    sqlite3_finalize(stmt_update_setting);

    // Cleanup events prepared statements
    sqlite3_finalize(stmt_obtain_events);
    sqlite3_finalize(stmt_insert_events);

    // Close databases
    if (db != NULL) 
    {
        rc = sqlite3_close(db);
        db = NULL;
    }
    if (mdb != NULL) 
    {
        rc = sqlite3_close(mdb);
        mdb = NULL;
    }
}
//! \fn  mdb_commit read state to db
void mdb_begin()
{
    sqlite3_exec(db, "BEGIN;", NULL, 0, NULL);
}
//! \fn  mdb_commit store state to db
void mdb_commit()
{
    sqlite3_exec(db, "COMMIT;", NULL, 0, NULL);
}

void mdb_checkerror()
{
    zErrMsg = sqlite3_errmsg(db);
    zErrMsg = sqlite3_errmsg(mdb);
}

// Set a key and value pair in the settings database
void mdb_set(char* key, char* value, int length)
{
    // "REPLACE INTO settings VALUES (?1, ?2)"
    rc = sqlite3_bind_text(stmt_update_setting, 1, key, (int)strlen(key), SQLITE_STATIC); // Key
    rc = sqlite3_bind_blob(stmt_update_setting, 2, value, length, SQLITE_STATIC); // Value
    rc = sqlite3_step(stmt_update_setting);
    if (rc < SQLITE_ROW) 
    {
        mdb_checkerror();
    }
    rc = sqlite3_reset(stmt_update_setting);
}

// Get a blob value from a key in the settings database
int mdb_get(char* key, char** value)
{
    int len = 0;
    *value = NULL;
    // "SELECT sdata FROM settings WHERE skey=?1";
    rc = sqlite3_bind_text(stmt_obtain_setting, 1, key, (int)strlen(key), SQLITE_STATIC); // Key
    rc = sqlite3_step(stmt_obtain_setting);
    if (rc == SQLITE_ROW && (len = sqlite3_column_bytes(stmt_obtain_setting, 0)) != 0)
    {
        if ((*value = malloc(len+1)) == NULL) ILIBCRITICALEXIT(254);
        (*value)[len] = 0;
        memcpy(*value, sqlite3_column_blob(stmt_obtain_setting, 0), len);
    }
    if (rc < SQLITE_ROW) 
    {
        mdb_checkerror();
    }
    rc = sqlite3_reset(stmt_obtain_setting);
    return len;
}

// Set an int value to a key in the settings database
void mdb_set_i(char* key, int value)
{
    int len;
    len = snprintf(ILibScratchPad, sizeof(ILibScratchPad), "%d", value);
    mdb_set(key, ILibScratchPad, len);
}

// Get a blob value from a key in the settings database
int mdb_get_i(char* key)
{
    int len;
    char* value;
    int val;
    len = mdb_get(key, &value);
    if (len == 0) return 0;
    val = atoi(value);
    mdb_free(value);
    return val;
}

// Clear a setting from the database
void mdb_remove(char* key)
{
    // "DELETE FROM settings WHERE skey=?1";
    rc = sqlite3_bind_text(stmt_delete_setting, 1, key, (int)strlen(key), SQLITE_STATIC); // Key
    rc = sqlite3_step(stmt_delete_setting);
    if (rc < SQLITE_ROW) 
    {
        mdb_checkerror();
    }
    rc = sqlite3_reset(stmt_delete_setting);
}

// Frees a block of memory returned from this module.
void mdb_free(char* ptr)
{
    free(ptr);
    ptr = NULL;
}

// Checks the existance of a nodeid in the database. Returns 1 if it is present and 0 if not.
int mdb_blockexist(char* blockid)
{
    // "SELECT blockid FROM blocks WHERE nodeid=?1";
    int r = 0;
    rc = sqlite3_bind_blob(stmt_obtain_block, 1, blockid, UTIL_HASHSIZE, SQLITE_STATIC); // Block ID
    rc = sqlite3_step(stmt_obtain_block);
    if (rc == SQLITE_ROW) r = 1;
    if (rc < SQLITE_ROW) 
    {
        mdb_checkerror();
    }
    rc = sqlite3_reset(stmt_obtain_block);
    return r;
}

// Fetch a block using the block id
int mdb_blockget(char* blockid, char** block)
{
    // "SELECT * FROM blocks WHERE blockid=?1"
    int r = 0;
    *block = NULL;
    rc = sqlite3_bind_blob(stmt_obtain_block, 1, blockid, UTIL_HASHSIZE, SQLITE_STATIC); // Block ID
    rc = sqlite3_step(stmt_obtain_block);
    if (rc == SQLITE_ROW)
    {
        r = sqlite3_column_bytes(stmt_obtain_block, 2);
        if ((*block = malloc(r)) == NULL) ILIBCRITICALEXIT(254);
        memcpy(*block, sqlite3_column_blob(stmt_obtain_block, 2), r);
    }
    else *block = NULL;
    if (rc < SQLITE_ROW) 
    {
        mdb_checkerror();
    }
    rc = sqlite3_reset(stmt_obtain_block);
    return r;
}

// Removes a node from the database, ignored if the node is not present.
void mdb_blockclear(char* blockid)
{
    // "DELETE FROM blocks WHERE blockid=?1";
    rc = sqlite3_bind_blob(stmt_delete_block, 1, blockid, UTIL_HASHSIZE, SQLITE_STATIC); // Block ID
    rc = sqlite3_step(stmt_delete_block);
    if (rc < SQLITE_ROW) 
    {
        mdb_checkerror();
    }
    rc = sqlite3_reset(stmt_delete_block);
}

// Removes all nodes and blocks from the databases
void  mdb_clearall()
{
    // "DELETE FROM nodes";
    rc = sqlite3_exec(db, "DELETE FROM nodes;", NULL, 0, NULL);
    // "DELETE FROM blocks";
    rc = sqlite3_exec(db, "DELETE FROM blocks;", NULL, 0, NULL);
}

// Get the current serial number for a given node
unsigned int mdb_getserial(char* nodeid)
{
    // const char* stmt_getserial_str = "SELECT serial FROM blocks WHERE blockid=?1";
    sqlite3_stmt *tmp;
    unsigned int serial = 0;
    rc = sqlite3_prepare(db, stmt_getserial_str, (int)strlen(stmt_getserial_str), &tmp, NULL);
    rc = sqlite3_bind_blob(tmp, 1, nodeid, UTIL_HASHSIZE, SQLITE_STATIC);	// Block ID
    rc = sqlite3_step(tmp);
    if (rc == SQLITE_ROW) 
    {
        serial = sqlite3_column_int(tmp, 0);
    }
    sqlite3_finalize(tmp);
    return serial;
}

// Set a new serial number for a push block in the target table
void mdb_setserial(char* nodeid, unsigned int serial)
{
    // const char* stmt_setserial_str = "UPDATE targets SET serial=?2 WHERE blockid=?1";
    sqlite3_stmt *tmp;
    rc = sqlite3_prepare(mdb, stmt_setserial_str, (int)strlen(stmt_setserial_str), &tmp, NULL);
    rc = sqlite3_bind_blob(tmp, 1, nodeid, UTIL_HASHSIZE, SQLITE_STATIC);	// Block ID
    rc = sqlite3_bind_int(tmp, 2, serial);									// Serial
    rc = sqlite3_step(tmp);
    sqlite3_finalize(tmp);
}

// Updated a node in the database if the information is more recent. Adds the node if it's missing.
int mdb_blockset(char* blockid, int serial, char* node, int nodelen)
{
    // Get the existing node serial number
    int t_serial = 0;
    int t_exists = 0;

    // "SELECT * FROM blocks WHERE blockid=?1";
    rc = sqlite3_bind_blob(stmt_obtain_block, 1, blockid, UTIL_HASHSIZE, SQLITE_STATIC); // Block ID
    rc = sqlite3_step(stmt_obtain_block);
    if (rc == SQLITE_ROW)
    {
        t_serial = sqlite3_column_int(stmt_obtain_block, 1);
        t_exists = 1;
    }
    if (rc < SQLITE_ROW) 
    {
        mdb_checkerror();
    }
    rc = sqlite3_reset(stmt_obtain_block);

    if (t_exists == 0)
    {
        // "INSERT INTO blocks VALUES (?1, ?2, ?3, DATETIME('now'), ?4, ?5, 0, ?6)";
        rc = sqlite3_bind_blob(stmt_insert_block, 1, blockid, UTIL_HASHSIZE, SQLITE_TRANSIENT); // Block ID
        rc = sqlite3_bind_int(stmt_insert_block, 2, serial); // Block Serial
        rc = sqlite3_bind_blob(stmt_insert_block, 3, node, nodelen, SQLITE_TRANSIENT); // Block
        rc = sqlite3_bind_int(stmt_insert_block, 4, ++synccounter); // Sync Counter
        rc = sqlite3_bind_int(stmt_insert_block, 5, ((unsigned short*)node)[0]); // Block Type (first 2 bytes of block)
        rc = sqlite3_step(stmt_insert_block);
        if (rc < SQLITE_ROW) 
        {
            mdb_checkerror();
        }
        rc = sqlite3_reset(stmt_insert_block);
        mdb_setserial(blockid, serial);

        // Send this block as a local event
        //! commented out until network testing...
        /// ctrl_SendSubscriptionEvent(node, nodelen);

        return 1; // Node was added
    }
    else if (t_serial < serial)
    {
        // "UPDATE blocks SET serial=?2, data=?3, schange=DATE('now') WHERE blockid=?1";
        rc = sqlite3_bind_blob(stmt_update_block, 1, blockid, UTIL_HASHSIZE, SQLITE_TRANSIENT); // Block ID
        rc = sqlite3_bind_int(stmt_update_block, 2, serial); // Block Serial
        rc = sqlite3_bind_blob(stmt_update_block, 3, node, nodelen, SQLITE_TRANSIENT); // Node Block
        rc = sqlite3_bind_int(stmt_update_block, 4, ++synccounter); // Sync Counter
        rc = sqlite3_step(stmt_update_block);
        if (rc < SQLITE_ROW) 
        {
            mdb_checkerror();
        }
        rc = sqlite3_reset(stmt_update_block);
        mdb_setserial(blockid, serial);

        // Send this block as a local event
      ////  ctrl_SendSubscriptionEvent(node, nodelen);

        return 2; // Node was updated
    }
    return 0; // Node was ignored
}

// Private callback to send all push blocks
void mdb_sendallpushblocksasync_sendok(struct ILibWebServer_Session *sender)
{
    int sendcount = 0;
    unsigned short nodelen;
    char* node;
    int status = 0;
    sqlite3_stmt* query;
    query = (sqlite3_stmt*)sender->User3;
    if (query == NULL) return;

    mdb_begin();
    while ((rc = sqlite3_step(query)) == SQLITE_ROW)
    {
        // If this node is the skip node, skip it
        if (sender->User2 != NULL)
        {
            node = (char*)sqlite3_column_blob(query, 0);
            // Boost speed by comparing first 4 bytes most of the time
            if (((int*)sender->User2)[0] == ((int*)node)[0] && memcmp(sender->User2, node, 32) == 0) continue;
        }

        // Fetch the push block
        nodelen = (unsigned short)sqlite3_column_bytes(query, 2);
        node = (char*)sqlite3_column_blob(query, 2);

        // Send the header & block
        ///status = ILibWebServer_StreamBody(sender, node, nodelen, ILibAsyncSocket_MemoryOwnership_USER,0);
        sendcount++;

        // If the socket is full, break out
        if (status != ILibWebServer_ALL_DATA_SENT) break;
    }
    mdb_commit();

    if (rc != SQLITE_ROW || status < 0)
    {
        // We are done, clean up and close the session.
        if (sender->User2 != NULL) 
        {
            free(sender->User2);
        }
        sqlite3_finalize(query);
        sender->User2 = NULL;
        sender->User3 = NULL;

        // Chain the requests
        mdb_sendasync(sender, sender->User4, NULL, sender->User5);
    }
    else
    {
        //MSG2("Async sent %d nodes...\r\n", sendcount);
    }
}


// Send all event in text format to the HTTP session. Skip node will be de-allocated by this method.
void mdb_sendallpushblocksasync(struct ILibWebServer_Session *sender, unsigned int syncounter, char* skipnode, unsigned int mask)
{
    char* snode = NULL;
    const char *tail;
    sqlite3_stmt* query;

    if (skipnode != NULL)
    {
        if ((snode = malloc(UTIL_HASHSIZE)) == NULL) ILIBCRITICALEXIT(254);
        memcpy(snode, skipnode, UTIL_HASHSIZE);
    }
    rc = sqlite3_prepare(db, stmt_getall_block_str, (int)strlen(stmt_getall_block_str), &query, &tail);
    rc = sqlite3_bind_int(query, 1, syncounter); // Bind the sync counter
    sender->OnSendOK = mdb_sendallpushblocksasync_sendok;
    sender->User2 = (void*)snode;
    sender->User3 = (void*)query;
    sender->User4 = synccounter;
    sender->User5 = mask;
    mdb_sendallpushblocksasync_sendok(sender);
}

// Called when an attempt to connect to a target is made
void mdb_attempttarget(struct sockaddr *addr)
{
    char* addrptr;
    int addrlen = ILibGetAddrBlob(addr, &addrptr);

    // "UPDATE targets SET lastattempt=DATETIME('now') WHERE address=?1";
    sqlite3_bind_blob(stmt_atempt_target, 1, addrptr, addrlen, SQLITE_TRANSIENT);				// Address
    rc = sqlite3_step(stmt_atempt_target);
    sqlite3_reset(stmt_atempt_target);
    return;
}

// Add or update state information about a node
void mdb_updatetarget(char* nodeid, struct sockaddr *addr, unsigned char state, unsigned char power)
{
    unsigned char tstate = -1;
    unsigned char tpower = -1;
    char tempid[UTIL_HASHSIZE];
    char *addrptr;
    int addrlen = ILibGetAddrBlob(addr, &addrptr);
    int distance;

    // If this is an unknown know our own node, delete it.
    if (state == MDB_UNKNOWN || memcmp(nodeid, g_selfid, 32) == 0)
    {
        // "DELETE FROM targets WHERE address=?1"
        sqlite3_bind_blob(stmt_delete_target, 1, addrptr, addrlen, SQLITE_TRANSIENT);			// Address
        rc = sqlite3_step(stmt_delete_target);
        sqlite3_reset(stmt_delete_target);
        if (ctrl_SubscriptionChainCount > 0 && sqlite3_changes(mdb) > 0)
        {
            // Event that this target was removed
            info_event_updatetarget(NULL, addrptr, addrlen, 0, 0);
        }
        return;
    }

    // Fetch the previous state
    tstate = mdb_gettargetstate(addr, tempid, &tpower, NULL, NULL);
    distance = ctrl_Distance(nodeid);

    if (tstate != 0)
    {
        // If we already have an equal or better state with same NodeID, drop this change request
        if (state == MDB_GOTMULTICAST && memcmp(nodeid, tempid, UTIL_HASHSIZE) == 0) return;

        // Lets update the database, we do this even if the entry in the database is missing
        sqlite3_bind_blob(stmt_update_target, 1, addrptr, addrlen, SQLITE_TRANSIENT);			// Address
        sqlite3_bind_blob(stmt_update_target, 2, nodeid, UTIL_HASHSIZE, SQLITE_TRANSIENT);		// Block ID
        sqlite3_bind_int(stmt_update_target, 3, state);											// State
        sqlite3_bind_int(stmt_update_target, 4, power);											// Power
        sqlite3_bind_int(stmt_update_target, 5, distance);										// XOR Distance
        rc = sqlite3_step(stmt_update_target);
        sqlite3_reset(stmt_update_target);
    }
    else
    {
        mdb_refreshbuckets();																	// TODO: OPTIMIZE: find a way to reduce the number of times this function is called.
        if (g_distancebuckets[distance] >= MESH_MAX_TARGETS_IN_BUCKET) return;

        // We need to insert the node and the bucket is not filled up, lets insert it.
        // "INSERT INTO targets VALUES (?1, ?2, ?3, DATETIME('now'), ?4)";
        sqlite3_bind_blob(stmt_insert_target, 1, addrptr, addrlen, SQLITE_TRANSIENT);			// IP Address
        sqlite3_bind_blob(stmt_insert_target, 2, nodeid, UTIL_HASHSIZE, SQLITE_TRANSIENT);		// NodeID
        sqlite3_bind_int(stmt_insert_target, 3, state);											// Connectivity state
        sqlite3_bind_int(stmt_insert_target, 4, power);											// Power state
        sqlite3_bind_blob(stmt_insert_target, 5, NullNodeId, 32, SQLITE_TRANSIENT);				// NextSyncID
        sqlite3_bind_int(stmt_insert_target, 6, mdb_getserial(nodeid));							// Push block serial number - TODO: OPTIMIZE THIS
        sqlite3_bind_int(stmt_insert_target, 7, distance);										// XOR Distance
        rc = sqlite3_step(stmt_insert_target);
        sqlite3_reset(stmt_insert_target);
        g_distancebuckets[distance]++;
    }

    if (ctrl_SubscriptionChainCount > 0 && rc != SQLITE_ERROR)// && (tstate != state || tpower != power || memcmp(tempid, nodeid, UTIL_HASHSIZE) != 0))
    {
        // Event that this target was updated
        // TODO: Send this only when there is a real update!
        info_event_updatetarget(nodeid, addrptr, addrlen, state, power);
    }
}


// Add or update state information about a node (NodeID & Key must be pre-allocated or NULL)
unsigned char mdb_gettargetstate(struct sockaddr *addr, char* nodeid, unsigned char* power, char* key, unsigned int* serial)
{
    unsigned char state = 0;
    char* addrptr;
    int addrlen = ILibGetAddrBlob(addr, &addrptr);

    // "SELECT blockid, state, power, sessionkey, serial FROM targets WHERE address=?1";
    sqlite3_bind_blob(stmt_obtain_target, 1, addrptr, addrlen, SQLITE_TRANSIENT);		// Address
    if (sqlite3_step(stmt_obtain_target) == SQLITE_ROW)
    {
        if (nodeid != NULL) memcpy(nodeid, sqlite3_column_blob(stmt_obtain_target, 0), UTIL_HASHSIZE);
        state = (unsigned char)sqlite3_column_int(stmt_obtain_target, 1);
        if (power != NULL) *power = sqlite3_column_int(stmt_obtain_target, 2);
        if (key != NULL && sqlite3_column_bytes(stmt_obtain_target, 3) == 36) memcpy(key, sqlite3_column_blob(stmt_obtain_target, 3), 36);	// Session Key
        if (serial != NULL) *serial = sqlite3_column_int(stmt_obtain_target, 4);
    }

    sqlite3_reset(stmt_obtain_target);
    return state;
}


// Fetch the next target in the rotation that should be sync'ed against (NodeID must be pre-allocated or NULL, address must be freed by user)
void mdb_synctargets()
{
    struct sockaddr_in6 addr;
    char nodeid[32];
    unsigned char power;
    char key[36];
    char* keyptr = NULL;
    char nextsyncblock[36];
    unsigned int lastcontact;
    unsigned int serial;
    int state;
    int len;

    //! \todo make sure int sendresponsekey is the right
    //!  \var sendresponsekey - do we send the response key?
    int sendresponsekey = 1;

    // "SELECT *, strftime('%s', 'now') - strftime('%s', lastcontact) FROM targets WHERE lastattempt < DATETIME('now', '-10 seconds') ORDER BY lastattempt"; // -5 minutes is normal
    // address TEXT PRIMARY KEY, blockid BINARY(32), state INTEGER, lastattempt DATE, lastcontact DATE, power INTEGER, sessionkey BINARY(36), iv INTEGER, nextsync BINARY(32), serial INTEGER, distance INTEGER
    while (sqlite3_step(stmt_workit_target) == SQLITE_ROW)
    {
        // Fetch the last contect
        lastcontact = sqlite3_column_int(stmt_workit_target, 11);																			// Seconds since last contact

        // Perform sync if last contact was recent or we have no outstanding
        if (lastcontact < MESH_TLS_FALLBACK_TIMEOUT || g_outstanding_outbound_requests == 0)
        {
            // If this is an Intel AMT computer, wait the full timeout
            state = (unsigned char)sqlite3_column_int(stmt_workit_target, 2);
            if (lastcontact < MESH_TLS_FALLBACK_TIMEOUT && state == MDB_AMTONLY) return;

            // Fetch the IP address
            len = sqlite3_column_bytes(stmt_workit_target, 0);
            memset(&addr, 0, sizeof(struct sockaddr_in6));
            if (len == 4)
            {
                // IPv4 address
                addr.sin6_family = AF_INET;
                ((struct sockaddr_in*)&addr)->sin_port = htons(MESH_AGENT_PORT);
                memcpy(&(((struct sockaddr_in*)&addr)->sin_addr), sqlite3_column_blob(stmt_workit_target, 0), 4);
            }
            else if (len == 16 || len == 20)
            {
                // IPv6 address, or IPv6 + Scope
                memset(&addr, 0, sizeof(struct sockaddr_in6));
                addr.sin6_family = AF_INET6;
                addr.sin6_port = htons(MESH_AGENT_PORT);
                memcpy(&(addr.sin6_addr), sqlite3_column_blob(stmt_workit_target, 0), len);
            }

            // Fetch the rest of the fields
            memcpy(nodeid, sqlite3_column_blob(stmt_workit_target, 1), UTIL_HASHSIZE);															// Node ID
            power = (unsigned char)sqlite3_column_int(stmt_workit_target, 5);																	// Power
            memcpy(nextsyncblock + 4, sqlite3_column_blob(stmt_workit_target, 8), 32);																	// NextSyncID
            serial = sqlite3_column_int(stmt_workit_target, 9);																					// Serial number
            if (sqlite3_column_bytes(stmt_workit_target, 6) == 36)
            {
                memcpy(key, sqlite3_column_blob(stmt_workit_target, 6), 36);					// Session Key
                keyptr = key;
            }

            // Perform the sync
            if (lastcontact < MESH_TLS_FALLBACK_TIMEOUT && keyptr != NULL)
            {
                // Complete building the Sync Start packet
                ((unsigned short*)nextsyncblock)[0] = PB_SYNCSTART;
                ((unsigned short*)nextsyncblock)[1] = 36;

                // Send UDP Syncronization Request
                //SendCryptoUdpToTarget((struct sockaddr*)&addr, nodeid, key, nextsyncblock, 36, sendresponsekey); // Send the SYNCSTART block using UDP
            }
            else
            {
                // Initiate TCP Syncronization Request
                /// commented out until comms fixed
                //ctrl_SyncToNodeTCP((struct sockaddr*)&addr, nodeid, state, keyptr, NULL, lastcontact, serial);
            }
        }
    }

    sqlite3_reset(stmt_workit_target);
}

// Private callback to send all push blocks
void mdb_sendalltargetsasync_sendok(struct ILibWebServer_Session *sender)
{
    int len = 0;
    int status = 0;
    int ptr = 0;
    sqlite3_stmt* query;
    char* packet = ILibScratchPad;

    query = (sqlite3_stmt*)sender->User3;
    if (query == NULL) return;

    mdb_begin();
    // "SELECT * FROM targets" | address TEXT PRIMARY KEY, blockid BINARY(32), state INTEGER, lastattempt DATE, lastcontact DATE, power INTEGER, sessionkey BINARY(36), iv INTEGER, nextsync BINARY(32)
    while ((rc = sqlite3_step(query)) == SQLITE_ROW)
    {
        // This method is optimize to send groups of many targets at once to reduce the number of SSL records sent.
        // The speed up is quite significant for large amounts of small records like this.

        // Fetch the address length
        len = sqlite3_column_bytes(query, 0);

        // Setup the block header
        ((unsigned short*)(packet + ptr))[0] = PB_TARGETSTATUS;
        ((unsigned short*)(packet + ptr))[1] = (unsigned short)(len + 43);

        // Setup BlockID
        memcpy(packet + ptr + 4, (char*)sqlite3_column_blob(query, 1), UTIL_HASHSIZE);

        // Setup state & power
        packet[36 + ptr] = (char)sqlite3_column_int(query, 2);
        packet[37 + ptr] = (char)sqlite3_column_int(query, 5);

        // Setup seconds since last contact. This is an SQL query computation of the number of seconds since the last contact.
        // Since no two clocks in the mesh are assumed to be set correctly, time since now is the only way to go.
        ((unsigned int*)(packet + 38 + ptr))[0] = htonl(sqlite3_column_int(query, 11));

        // Setup the address length
        packet[42 + ptr] = (char)len;

        // Setup the IP address
        memcpy(packet + 43 + ptr, (char*)sqlite3_column_blob(query, 0), len);

        // Add to the pointer
        ptr += len + 43;

        // If we filled 4k worth of data, go ahead and send it out
        if (ptr > 4000)
        {
            // Send the data
            if (ptr > 4096) ILIBCRITICALEXIT(253);
            ///status = ILibWebServer_StreamBody(sender, packet, ptr, ILibAsyncSocket_MemoryOwnership_USER, 0);
            ptr = 0;

            // If the socket is full, break out
            if (status != ILibWebServer_ALL_DATA_SENT) break;
        }
    }
    mdb_commit();

    // If we have something left, this is almost always the case, send it out.
    if (ptr > 0)
    {
        // Send the data
        ///status = ILibWebServer_StreamBody(sender, packet, ptr, ILibAsyncSocket_MemoryOwnership_USER, 0);
    }

    if (rc != SQLITE_ROW || status < 0)
    {
        // We are done, clean up and close the session.
        sqlite3_finalize(query);
        sender->User3 = NULL;

        // Chain the requests
        mdb_sendasync(sender, sender->User4, NULL, sender->User5);
    }
}

// Send all event in text format to the HTTP session. Skip node will be de-allocated by this method.
void mdb_sendalltargetsasync(struct ILibWebServer_Session *sender, unsigned int syncounter, unsigned int mask)
{
    const char *tail;
    sqlite3_stmt* query;

    rc = sqlite3_prepare(mdb, stmt_select_target_str, (int)strlen(stmt_select_target_str), &query, &tail);
    sender->OnSendOK = mdb_sendalltargetsasync_sendok;
    sender->User3 = (void*)query;
    sender->User4 = syncounter;
    sender->User5 = mask;
    mdb_sendalltargetsasync_sendok(sender);
}

// Send a set of async enumerations, the mask indicates what information to send out
void mdb_sendasync(struct ILibWebServer_Session *sender, unsigned int syncounter, char* skipnode, unsigned int mask)
{
    // If mask is empty, close the HTTP session
    if (mask == 0) ;///ILibWebServer_StreamBody(sender, NULL, 0, ILibAsyncSocket_MemoryOwnership_STATIC, 1);
    else if (mask & MDB_SELFNODE)
    {
        // Send self push block
        int l;
        char* str;
        //l = ctrl_GetCurrentSignedNodeInfoBlock(&str);
        ///ILibWebServer_StreamBody(sender, str, l, ILibAsyncSocket_MemoryOwnership_USER, 0);
        mdb_sendasync(sender, syncounter, skipnode, mask & ~((unsigned int)MDB_SELFNODE));
    }
    else if (mask & MDB_AGENTID)
    {
        // Send self agent information
        char str[10];
        ((unsigned short*)str)[0] = PB_AGENTID;
        ((unsigned short*)str)[1] = 10;
        ((unsigned int*)str)[1] = htonl(MESH_AGENT_VERSION);
        ((unsigned short*)str)[4] = htons(g_agentid);
        //ILibWebServer_StreamBody(sender, str, 10, ILibAsyncSocket_MemoryOwnership_USER, 0);
        mdb_sendasync(sender, syncounter, skipnode, mask & ~((unsigned int)MDB_AGENTID));
    }
    else if (mask & MDB_SESSIONKEY)
    {
        // Send private session key, used for UDP
        if (sender->CertificateHashPtr != NULL)
        {
            // Compute private session key for this target node, add session key header
            char key[40];
            /// commented out for now.
            ///util_nodesessionkey(sender->CertificateHashPtr, key + 4);
            ((unsigned short*)key)[0] = PB_SESSIONKEY;
            ((unsigned short*)key)[1] = 40;
            ///ILibWebServer_StreamBody(sender, key, 40, ILibAsyncSocket_MemoryOwnership_USER, 0);
        }
        mdb_sendasync(sender, syncounter, skipnode, mask & ~((unsigned int)MDB_SESSIONKEY));
    }
    else if (mask & MDB_PUSHBLOCKS)
    {
        mdb_sendallpushblocksasync(sender, syncounter, skipnode, mask & ~((unsigned int)MDB_PUSHBLOCKS));	// Send push blocks
    }
    else if (mask & MDB_TARGETS) mdb_sendalltargetsasync(sender, syncounter, mask & ~((unsigned int)MDB_TARGETS));						// Send target information
}

// Save the session key to the target database
void  mdb_setsessionkey(char* nodeid, char* key)
{
    // "UPDATE targets SET sessionkey=?2 WHERE blockid=?1";
    rc = sqlite3_bind_blob(stmt_setkey_target, 1, nodeid, UTIL_HASHSIZE, SQLITE_TRANSIENT); // Node ID
    rc = sqlite3_bind_blob(stmt_setkey_target, 2, key, 4 + UTIL_HASHSIZE, SQLITE_TRANSIENT); // Key Identifier + Session Key
    rc = sqlite3_step(stmt_setkey_target);
    if (rc < SQLITE_ROW) {
        mdb_checkerror();
    }
    rc = sqlite3_reset(stmt_setkey_target);
}

// Runs thru the node block database and generates a metadata block of a given length.
// The block starts with the standard header, then the startnodeid followed by an
// long set of nodeid/serial. If we get to the end of the database, we terminate with
// a nodeid/serial of all zeros.
int mdb_getmetadatablock(char* startnodeid, int maxsize, char** result, char* skipnodeid)
{
    int ptr = 40;

    // Allocate the block
    if (maxsize < 512) {
        *result = NULL;
        return 0;
    }
    if ((*result = malloc(maxsize)) == NULL) ILIBCRITICALEXIT(254);

    // Run thru the database, ordered by NodeID starting at but excluding startnodeid
    // "SELECT blockid, serial FROM targets WHERE blockid > ?1 GROUP BY blockid ORDER BY blockid"
    //! SQLITE_API int sqlite3_blob_read(sqlite3_blob *, void *Z, int N, int iOffset);
    rc = sqlite3_bind_blob(stmt_metadt_target, 1, startnodeid, UTIL_HASHSIZE, SQLITE_TRANSIENT); // Start Node ID
    while (ptr + 36 < maxsize)
    {
        // If this is the last record, make the end and exit.
        //if ((rc = sqlite3_step(stmt_metadt_target)) != SQLITE_ROW) { memset(*result + ptr, 0, 36); ptr += 36; break; }
        if ((rc = sqlite3_step(stmt_metadt_target)) != SQLITE_ROW) 
        {
            memset(*result + ptr, 0, 1);
            ptr += 1;
            break;
        }

        // If this is the skipped node, skip it.
        if (skipnodeid != NULL && memcmp(skipnodeid, sqlite3_column_blob(stmt_metadt_target, 0), UTIL_HASHSIZE) == 0) continue;

        // Copy the nodeid & serial.
        memcpy((*result) + ptr, sqlite3_column_blob(stmt_metadt_target, 0), UTIL_HASHSIZE);
        ((unsigned int*)((*result) + ptr))[8] = htonl(sqlite3_column_int(stmt_metadt_target, 1));
        ptr += 36;
    }
    if (rc < SQLITE_ROW) 
    {
        mdb_checkerror();
    }
    rc = sqlite3_reset(stmt_metadt_target);

    // Add the header and startnodeid
    ((unsigned short*)(*result))[0] = PB_SYNCMETADATA;
    ((unsigned short*)(*result))[1] = ptr;
    memcpy(*result + 4, startnodeid, 32);				// The start NodeID, same as the one requested.
    ((unsigned int*)(*result))[9] = htonl(g_serial);	// Our own current serial number

    return ptr;
}

// This is the tricky task of comparing our own data against a metadata block sent by a peer.
// We got to do this really efficiently and send back UDP packets as we detect differences.
// We will accumulate the push block requests so to minimize the number of UDP packets going out.
void mdb_performsync(char* meta, int metalen, char* nodeid, struct sockaddr *addr, char* key, unsigned int nodeidserial)
{
    int ptr = 0;
    char *snode = NullNodeId;
    char *rnode = NullNodeId;
    unsigned int sserial = 0;
    unsigned int rserial = 0;
    int delta;
    int moveforward = 0;
    int done_local = 0;
    int done_remote = 0;
    char *requests = ILibScratchPad; // Used to hold a block size of node requests
    int requestsPtr = 4;

    //! \todo make sure int sendresponsekey is the right
    //!  \var sendresponsekey - do we send the response key?
    int sendresponsekey = 1;

    // First, lets extract the current serial number of the remote node
    rserial = ntohl(((unsigned int*)meta)[8]);
    if (nodeidserial < rserial)
    {
        // If it's higher than the block we currently have, add it to the request.
        memcpy(requests + requestsPtr, nodeid, UTIL_HASHSIZE);
        requestsPtr += UTIL_HASHSIZE;
    }
    rserial = 0;

    // Run thru the database, ordered by NodeID starting at but excluding startnodeid
    rc = sqlite3_bind_blob(stmt_metadt_block, 1, meta, UTIL_HASHSIZE, SQLITE_TRANSIENT); // Start Node ID
    moveforward = 3;
    goto startpoint;

    while (1)
    {
        // Compare both nodes
        delta = memcmp(snode, rnode, UTIL_HASHSIZE);
        if (delta < 0)
        {
            // SNode < RNode. We conclude that the remote peer does not have SNode, just skip it.
            moveforward = 1;
        }
        else if (delta > 0)
        {
            // SNode > RNode. We conclude that we don't have RNode, we have to request it.
            memcpy(requests + requestsPtr, rnode, UTIL_HASHSIZE);
            requestsPtr += UTIL_HASHSIZE;
            moveforward = 2;
        }
        else if (delta == 0)
        {
            // SNode == RNode. We both have this node, check the serial numbers
            rserial = ntohl(((unsigned int*)(meta + ptr))[8]);
            sserial = sqlite3_column_int(stmt_metadt_block, 1);
            if (sserial < rserial)
            {
                // Request RNode
                memcpy(requests + requestsPtr, rnode, UTIL_HASHSIZE);
                requestsPtr += UTIL_HASHSIZE;
            }
            moveforward = 3;
        }

startpoint:

        // Move the nodes forward
        if (moveforward & 1)
        {
            // Move to the next SNode
            if ((rc = sqlite3_step(stmt_metadt_block)) != SQLITE_ROW) 
            {
                done_local = 1;
            }
            else {
                snode = (char*)sqlite3_column_blob(stmt_metadt_block, 0);
            }
        }
        if (moveforward & 2)
        {
            // Move to the next RNode
            if (ptr + 72 > metalen) 
            {
                done_remote = 1;
            }
            else
            {
                ptr += 36;
                rnode = meta + ptr;
            }
        }

        // If the requests have filled up, send them out
        if (requestsPtr + 32 >= 1024)
        {
            ((unsigned short*)requests)[0] = PB_SYNCREQUEST;
            ((unsigned short*)requests)[1] = requestsPtr;
            //! \note added sendresponsekey
            //SendCryptoUdpToTarget(addr, nodeid, key, requests, requestsPtr, sendresponsekey);
            requestsPtr = 4;
        }

        // Local or remote is done, let exit the loop
        if ( done_local != 0 || done_remote != 0) break;
    }

    if (done_local == 1 && done_remote == 0)
    {
        // We only have remote nodes to request
        while (1)
        {
            // Request RNode
            memcpy(requests + requestsPtr, rnode, UTIL_HASHSIZE);
            requestsPtr += UTIL_HASHSIZE;

            // If the requests have filled up, send them out
            if (requestsPtr + 32 >= 1024)
            {
                ((unsigned short*)requests)[0] = PB_SYNCREQUEST;
                ((unsigned short*)requests)[1] = requestsPtr;
                //! \note added sendresponsekey
                //SendCryptoUdpToTarget(addr, nodeid, key, requests, requestsPtr, sendresponsekey);
                requestsPtr = 4;
            }

            // Move to the next RNode
            if (ptr + 72 > metalen) break;
            ptr += 36;
            rnode = meta + ptr;
        }
    }

    // Clean up the Sql query
    if (rc < SQLITE_ROW) 
    {
        mdb_checkerror();
    }
    rc = sqlite3_reset(stmt_metadt_block);

    // If the metadata has an end marker, we got all of the metadata of the remote node and we have to restart at NodeID null for the next request.
    if (metalen == ptr + 37 && meta[ptr + 36] == 0) {
        rnode = NullNodeId;
    }

    // Save the last metadata index
    rc = sqlite3_bind_blob(stmt_metaup_target, 1, nodeid, UTIL_HASHSIZE, SQLITE_TRANSIENT); // Node ID
    rc = sqlite3_bind_blob(stmt_metaup_target, 2, rnode, UTIL_HASHSIZE, SQLITE_TRANSIENT);  // Next Sync Node ID
    rc = sqlite3_step(stmt_metaup_target);
    if (rc < SQLITE_ROW) 
    {
        mdb_checkerror();
    }
    rc = sqlite3_reset(stmt_metaup_target);

    // If there are any requests, send them out
    if (requestsPtr > 4)
    {
        ((unsigned short*)requests)[0] = PB_SYNCREQUEST;
        ((unsigned short*)requests)[1] = requestsPtr;
        //! \note added sendresponsekey
        //! commented out for now
        //SendCryptoUdpToTarget(addr, nodeid, key, requests, requestsPtr, sendresponsekey);
        requestsPtr = 4;
    }
}

// Recomputes the latest counts in each bucket.
void mdb_refreshbuckets()
{
    sqlite3_stmt *tmp;
    unsigned char newbuckets[32];
    unsigned int distance;

    memset(newbuckets, 0, 32);
    rc = sqlite3_prepare(mdb, stmt_getbucket_str, (int)strlen(stmt_getbucket_str), &tmp, NULL);
    while (sqlite3_step(tmp) == SQLITE_ROW)
    {
        distance = (unsigned int)sqlite3_column_int(tmp, 0);
        if (distance < 32) newbuckets[distance] = (unsigned char)sqlite3_column_int(tmp, 1);
    }
    sqlite3_finalize(tmp);
    memcpy(g_distancebuckets, newbuckets, 32);
}

// If added is 0, removes a node from the distance(nodeid) bucket, otherwise, add the node to the bucket.
void mdb_changebuckets(char* nodeid, int added)
{
    int d = ctrl_Distance(nodeid);
    if (added) g_distancebuckets[d]++;
    else if (g_distancebuckets[d] != 0) g_distancebuckets[d]--;
}

// Add an event to the event log
void mdb_addevent(char* msg, int msglen)
{
    UNREFERENCED_PARAMETER( msg );
    UNREFERENCED_PARAMETER( msglen );
    /*
    if (db == NULL) return;
    rc = sqlite3_bind_text(stmt_insert_events, 1, msg, msglen, SQLITE_TRANSIENT);
    rc = sqlite3_step(stmt_insert_events);
    if (rc < SQLITE_ROW) {mdb_checkerror();}
    rc = sqlite3_reset(stmt_insert_events);
    */
}

// Delete all events from the event log
void mdb_deleteevents()
{
    rc = sqlite3_exec(db, "DELETE FROM events;", NULL, 0, NULL);
    if (rc < SQLITE_ROW) 
    {
        mdb_checkerror();
    }
}

// Send all event in text format to the HTTP session
void mdb_sendevents(struct ILibWebServer_Session *sender)
{
    int len, v;
    char* msg1;
    char* msg2;

    while ((rc = sqlite3_step(stmt_obtain_events)) == SQLITE_ROW)
    {
        // Send event counter
        v = sqlite3_column_int(stmt_obtain_events, 0);
        //len = snprintf(spareBuffer, spareBufferLen, "%d - ", v);
        //ILibWebServer_StreamBody(sender, spareBuffer, len, ILibAsyncSocket_MemoryOwnership_USER,0);

        // Send event date & time
        //len = sqlite3_column_bytes(stmt_obtain_events, 1);
        msg1 = (char*)sqlite3_column_text(stmt_obtain_events, 1);
        //ILibWebServer_StreamBody(sender, msg, len, ILibAsyncSocket_MemoryOwnership_USER,0);

        // Send spacer
        //ILibWebServer_StreamBody(sender, " - ", 3, ILibAsyncSocket_MemoryOwnership_STATIC,0);

        // Send event log message
        //len = sqlite3_column_bytes(stmt_obtain_events, 2);
        msg2 = (char*)sqlite3_column_text(stmt_obtain_events, 2);
        //ILibWebServer_StreamBody(sender, msg, len, ILibAsyncSocket_MemoryOwnership_USER,0);

        // Send end of line
        //ILibWebServer_StreamBody(sender, "<br>", 4, ILibAsyncSocket_MemoryOwnership_STATIC,0);

        len = snprintf(ILibScratchPad, sizeof(ILibScratchPad), "%d - %s - %s<br>", v, msg1, msg2);
        ///ILibWebServer_StreamBody(sender, ILibScratchPad, len, ILibAsyncSocket_MemoryOwnership_USER, 0);

    }
    if (rc < SQLITE_ROW) 
    {
        mdb_checkerror();
    }
    rc = sqlite3_reset(stmt_obtain_events);
}

// blockid BINARY(32) PRIMARY KEY, serial INTEGER, data BLOB, schange DATE, synccount INTEGER, syncnode INTEGER, blocktype INTEGER
char* DEBUG_BLOCK_TABLE_HEADER = "<table border=\"1\"><tr><th>blockid</th><th>serial</th><th>data</th><th>schange</th><th>synccount</th><th>blocktype</th></tr>";
char* DEBUG_BLOCK_TABLE_ITEMBK = "<tr><td>%s</td><td>%d</td><td>%d</td><td>%s</td><td>%d</td><td>%d</td></tr>";
char* DEBUG_BLOCK_TABLE_FOOTER = "</table><br><br>";

// address TEXT PRIMARY KEY, blockid BINARY(32), state INTEGER, lastcontact DATE, power INTEGER
char* DEBUG_TARGET_TABLE_HEADER = "<table border=\"1\"><tr><th>address</th><th>blockid</th><th>state</th><th>lastAttempt</th><th>lastContact</th><th>power</th><th>SK</th><th>IV</th><th>NextSync</th><th>Serial</th><th>Dist</th></tr>";
char* DEBUG_TARGET_TABLE_ITEMBK1 = "<tr><td><a href=\"https://%s:16990/db\">%s</a></td><td>%s</td><td>%d</td><td>%s</td><td>%s</td><td>%d</td><td>%d</td><td>%d</td><td>%s</td><td>%d</td><td>%d</td></tr>";
char* DEBUG_TARGET_TABLE_ITEMBK2 = "<tr><td><a href=\"https://[%s]:16990/db\">%s</a></td><td>%s</td><td>%d</td><td>%s</td><td>%s</td><td>%d</td><td>%d</td><td>%d</td><td>%s</td><td>%d</td><td>%d</td></tr>";
char* DEBUG_TARGET_TABLE_ITEMBK3 = "<tr><td><a href=\"https://[%s]:16990/db\">%s%%%d</a></td><td>%s</td><td>%d</td><td>%s</td><td>%s</td><td>%d</td><td>%d</td><td>%d</td><td>%s</td><td>%d</td><td>%d</td></tr>";

// Private callback to send all push blocks
void mdb_sendallblocksdebugasync_sendok(struct ILibWebServer_Session *sender)
{
    int len;
    int status = 0;
    sqlite3_stmt* query;
    int sendcount = 0;
    char nodeIdStr[18];

    query = (sqlite3_stmt*)sender->User3;
    if (query == NULL) return;

    mdb_begin();
    while ((rc = sqlite3_step(query)) == SQLITE_ROW)
    {
        // Send the data
        util_tohex((char*)sqlite3_column_blob(query, 0), 8, nodeIdStr);
        len = snprintf(ILibScratchPad, sizeof(ILibScratchPad), DEBUG_BLOCK_TABLE_ITEMBK, nodeIdStr, sqlite3_column_int(query, 1), sqlite3_column_bytes(query, 2), sqlite3_column_text(query, 3), sqlite3_column_int(query, 4), sqlite3_column_int(query, 5), sqlite3_column_int(query, 6));
        ///status = ILibWebServer_StreamBody(sender, ILibScratchPad, len, ILibAsyncSocket_MemoryOwnership_USER, 0);
        sendcount++;

        // If the socket is full, break out
        if (status != ILibWebServer_ALL_DATA_SENT) break;
    }
    mdb_commit();

    if (rc != SQLITE_ROW || status < 0)
    {
        // We are done, clean up and close the session.
        sqlite3_finalize(query);
        sender->User3 = NULL;
        ///ILibWebServer_StreamBody(sender, DEBUG_BLOCK_TABLE_FOOTER, (int)strlen(DEBUG_BLOCK_TABLE_FOOTER), ILibAsyncSocket_MemoryOwnership_STATIC, 1);
    }
}

// Send all event in text format to the HTTP session. Skip node will be de-allocated by this method.
void mdb_sendallblocksdebugasync(struct ILibWebServer_Session *sender)
{
    const char *tail;
    sqlite3_stmt* query;

    rc = sqlite3_prepare(db, stmt_getall_block_str, (int)strlen(stmt_getall_block_str), &query, &tail);
    rc = sqlite3_bind_int(query, 1, 0); // Bind the sync counter
    sender->OnSendOK = mdb_sendallblocksdebugasync_sendok;
    sender->User3 = (void*)query;
    ///ILibWebServer_StreamBody(sender, DEBUG_BLOCK_TABLE_HEADER, (int)strlen(DEBUG_BLOCK_TABLE_HEADER), ILibAsyncSocket_MemoryOwnership_STATIC, 0);
    mdb_sendallblocksdebugasync_sendok(sender);
}

// Private callback to send all push blocks
void mdb_sendalltargetsdebugasync_sendok(struct ILibWebServer_Session *sender)
{
    int len = 0;
    int status = 0;
    int scope;
    sqlite3_stmt* query;
    int sendcount = 0;
    char addrstr[200];
    char nodeIdStr[18];
    char nextsync[18];

    query = (sqlite3_stmt*)sender->User3;
    if (query == NULL) return;

    mdb_begin();
    while ((rc = sqlite3_step(query)) == SQLITE_ROW)
    {
        // Fetch BlockID
        util_tohex((char*)sqlite3_column_blob(query, 1), 8, nodeIdStr);

        // Fetch NextSyncNodeID
        util_tohex((char*)sqlite3_column_blob(query, 8), 8, nextsync);

        // Fetch the address
        if (sqlite3_column_bytes(query, 0) == 4)
        {
            // IPv4 Address
            ILibInet_ntop(AF_INET, (char*)sqlite3_column_blob(query, 0), addrstr, 200);
            len = snprintf(ILibScratchPad, sizeof(ILibScratchPad),  DEBUG_TARGET_TABLE_ITEMBK1, addrstr, addrstr, nodeIdStr, sqlite3_column_int(query, 2), sqlite3_column_text(query, 3), sqlite3_column_text(query, 4), sqlite3_column_int(query, 5), sqlite3_column_bytes(query, 6), sqlite3_column_int(query, 7), nextsync, sqlite3_column_int(query, 9), sqlite3_column_int(query, 10));
        }
        else if (sqlite3_column_bytes(query, 0) == 16)
        {
            // IPv6 Address
            ILibInet_ntop(AF_INET6, (char*)sqlite3_column_blob(query, 0), addrstr, 200);
            len = snprintf(ILibScratchPad, sizeof(ILibScratchPad),  DEBUG_TARGET_TABLE_ITEMBK2, addrstr, addrstr, nodeIdStr, sqlite3_column_int(query, 2), sqlite3_column_text(query, 3), sqlite3_column_text(query, 4), sqlite3_column_int(query, 5), sqlite3_column_bytes(query, 6), sqlite3_column_int(query, 7), nextsync, sqlite3_column_int(query, 9), sqlite3_column_int(query, 10));
        }
        else if (sqlite3_column_bytes(query, 0) == 20)
        {
            // IPv6 Address + Scope
            ILibInet_ntop(AF_INET6, (char*)sqlite3_column_blob(query, 0), addrstr, 200);
            scope = ((int*)sqlite3_column_blob(query, 0))[4];
            len = snprintf(ILibScratchPad, sizeof(ILibScratchPad), DEBUG_TARGET_TABLE_ITEMBK3, addrstr, addrstr, scope, nodeIdStr, sqlite3_column_int(query, 2), sqlite3_column_text(query, 3), sqlite3_column_text(query, 4), sqlite3_column_int(query, 5), sqlite3_column_bytes(query, 6), sqlite3_column_int(query, 7), nextsync, sqlite3_column_int(query, 9), sqlite3_column_int(query, 10));
        }

        if (len > 0 && len < sizeof(ILibScratchPad))
        {
            // Format & send the string
            ///status = ILibWebServer_StreamBody(sender, ILibScratchPad, len, ILibAsyncSocket_MemoryOwnership_USER, 0);
            sendcount++;

            // If the socket is full, break out
            if (status != ILibWebServer_ALL_DATA_SENT) break;
        }
    }
    mdb_commit();

    if (rc != SQLITE_ROW || status < 0)
    {
        // We are done, clean up and close the session.
        sqlite3_finalize(query);
        sender->User3 = NULL;

        ///ILibWebServer_StreamBody(sender, DEBUG_BLOCK_TABLE_FOOTER, (int)strlen(DEBUG_BLOCK_TABLE_FOOTER), ILibAsyncSocket_MemoryOwnership_STATIC, 0);
        mdb_sendallblocksdebugasync(sender);
    }
}

// Send all event in text format to the HTTP session. Skip node will be de-allocated by this method.
void mdb_sendalltargetsdebugasync(struct ILibWebServer_Session *sender)
{
    const char *tail;
    sqlite3_stmt* query;

    rc = sqlite3_prepare(mdb, stmt_select_target_str, (int)strlen(stmt_select_target_str), &query, &tail);
    sender->OnSendOK = mdb_sendalltargetsdebugasync_sendok;
    sender->User3 = (void*)query;
    /// \note all ILibWebServer_StreamBody commented out until fixed
    ///ILibWebServer_StreamBody(sender, DEBUG_TARGET_TABLE_HEADER, (int)strlen(DEBUG_TARGET_TABLE_HEADER), ILibAsyncSocket_MemoryOwnership_STATIC, 0);
    mdb_sendalltargetsdebugasync_sendok(sender);
}

