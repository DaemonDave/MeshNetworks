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
#define __MeshInfo_h__

// DRE 2022
#define _POSIX	1

// DRE 2022


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

#ifndef __ILibParsers__
#include "ILibParsers.h"
#endif

#ifndef _NOHECI
#ifdef WIN32
    #include "heciwin.h"
#endif
#ifdef _POSIX
#ifndef __HECI_LINUX_H__
#include "HECILinux.h"
#endif
#endif
#include "PTHICommand.h"
#endif

//! Meshinfo has been limited to non SSL functionality as the name of meshconfig.h
///
// DRE 2022 transfered over from meshinfo.c
///



#ifndef MeshGlobals_h
#include "globals.h"
#endif



#endif

