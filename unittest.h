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

//#ifdef _DEBUG

#ifndef __UNITTEST_H__
#define __UNITTEST_H__



#ifdef WINSOCK1
#include <winsock.h>
#elif WINSOCK2
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#endif


#ifndef __MeshInfo_h__
#include "meshinfo.h"
#endif

#ifndef intel_mdb
#include "meshdb.h"
#endif

#ifndef __MeshCore_h__
#include "meshcore.h"
#endif

#ifndef __MeshCtrl_h__
#include "meshctrl.h"
#endif

#ifndef __ILibParsers__
#include "ILibParsers.h"
#endif

#ifndef __ILibWebClient__
#include "ILibWebClient.h"
#endif

#ifndef __ILibWebServer__
#include "ILibWebServer.h"
#endif

#ifndef ___ILibAsyncSocket___
#include "ILibAsyncSocket.h"
#endif

#ifndef ___ILibAsyncServerSocket___
#include "ILibAsyncServerSocket.h"
#endif

#ifndef ___ILibAsyncUDPSocket___
#include "ILibAsyncUDPSocket.h"
#endif


// Perform all of the unit tests
int ut_PerformAllUnitTests(int argc, char **argv);

// Basic set of compression and crypto tests that should have not problem working well.
int ut_StaticTestsuite1(char* exename);

// Tests the realiability of crypto checks, this suite is difficult to pass, OpenSSL currently fails it.
int ut_StaticTestsuite2();

// Tests system information gathering
int ut_StaticTestsuite3();

// Test of the HECI interface
int ut_StaticTestsuite4();

// Test node identity challenge, anti-flooding
int ut_StaticTestsuite5();

// Test symetric crypto
int ut_StaticTestsuite6();

// Generates count number of bogus nodes for testing purposes, storing nodes in the database
void ut_GenerateTestNodes(int count);

// Tests asyncsockets on loopback interface
int ut_DynamicTestsuite1();

#endif
