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
#ifndef __MeshComms__
#define __MeshComms__

//! localized OpenSSL apart from system 
// DRE 2022
//#include <openssl/ssl.h>
//#include <openssl/err.h>
//#include <openssl/core.h>
// DRE 2022
// DRE 2022
#include "ssl.h"
#include "err.h"
#include "core.h"
 
 
 #ifndef __ILibParsers__
#include "ILibParsers.h"
#endif

#ifndef __ILibWebClient__
#include "ILibWebClient.h"
#endif

#ifndef __ILibWebServer__
#include "ILibWebServer.h"
#endif





#endif
