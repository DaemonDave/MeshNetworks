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
 * $Workfile: ILibSSDPClient.h
 * $Revision: #1.0.1775.28223
 * $Author:   Intel Corporation, Intel Device Builder
 * $Date:     Thursday, November 11, 2004
 *
 *
 *
 */

#ifndef __ILibSSDPClient__
#define __ILibSSDPClient__
#if defined(WIN32) || defined(_WIN32_WCE)
	#ifndef MICROSTACK_NO_STDAFX
	#include "stdafx.h"
	#endif
	#define _CRTDBG_MAP_ALLOC
	#include <math.h>
	#include <winerror.h>
#else
	#include <fcntl.h>
	#include <sys/types.h>
	#include <sys/socket.h>
	#include <netinet/in.h>
	#include <arpa/inet.h>
	#include <sys/time.h>
	#include <netdb.h>
	#include <sys/ioctl.h>
	#include <net/if.h>
	#include <sys/utsname.h>
	#include <netinet/in.h>
	#include <unistd.h>
	#include <errno.h>
	#include <semaphore.h>
	#include <malloc.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <string.h>

#if defined(WINSOCK2)
	#include <winsock2.h>
	#include <ws2tcpip.h>
#elif defined(WINSOCK1)
	#include <winsock.h>
	#include <wininet.h>
#endif

#ifdef WIN32
	#include <windows.h>
	#include <winioctl.h>
	#include <winbase.h>
	#ifndef _WIN32_WCE
		#include <crtdbg.h>
	#endif
#endif

#ifndef _WIN32_WCE
#include <time.h>
#endif

#ifndef __ILibParsers__
#include "ILibParsers.h"
#endif

#ifndef __UPNP_CONTROLPOINT_STRUCTS__
#include "UPnPControlPointStructs.h"
#endif


void* ILibCreateSSDPClientModule(void *chain, char* DeviceURN, int DeviceURNLength, void (*FunctionCallback)(void *sender, char* UDN, int Alive, char* LocationURL, int Timeout, UPnPSSDP_MESSAGE m, void *user),void *user);
void ILibSSDP_IPAddressListChanged(void *SSDPToken);

#endif
