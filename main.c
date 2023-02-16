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

// \note configure shortcuts for testing...
#define _POSIX 		1
#define _CONSOLE	1
#define _DEBUG		1



#if defined(WIN32) || defined (_WIN32_WCE)
#ifndef MICROSTACK_NO_STDAFX
#include "stdafx.h"
#endif
#endif

#if defined(WIN32)
#define _CRTDBG_MAP_ALLOC
#endif

#if defined(WIN32) & !defined(_CONSOLE)
#include "resource.h"
#endif

#if defined(WIN32) && defined (_DEBUG)
#include <crtdbg.h>
#endif

#include <signal.h>

#ifndef __UNITTEST_H__
#include "unittest.h"
#endif

#ifndef intel_mdb
#include "meshdb.h"
#endif

#ifndef __MeshInfo_h__
#include "meshinfo.h"
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


#ifdef WIN32
int SetupWindowsFirewall(wchar_t* friendlyname, wchar_t* processname);
#endif

extern unsigned short g_agentid;

// The following macros set and clear, respectively, given bits
// of the C runtime library debug flag, as specified by a bitmask.
#ifdef   _DEBUG
#define  SET_CRT_DEBUG_FIELD(a) \
	_CrtSetDbgFlag((a) | _CrtSetDbgFlag(_CRTDBG_REPORT_FLAG))
#define  CLEAR_CRT_DEBUG_FIELD(a) \
	_CrtSetDbgFlag(~(a) & _CrtSetDbgFlag(_CRTDBG_REPORT_FLAG))
#else
#define  SET_CRT_DEBUG_FIELD(a)   ((void) 0)
#define  CLEAR_CRT_DEBUG_FIELD(a) ((void) 0)
#endif

#ifdef MEMORY_CHECK
#ifdef WIN32
// This routine place comments at the head of a section of debug output
void OutputHeading( const char * explanation )
{
    _RPT1( _CRT_WARN, "\n\n%s:\n**************************************************************************\n", explanation );
}
#endif
#endif

#ifndef fdatasync
int fdatasync(int fildes) 
{
    UNREFERENCED_PARAMETER( fildes );
    return 0;
}
#endif

extern void ctrl_SendSubscriptionEvent(char *data, int datalen);
void BreakSink(int s)
{
    UNREFERENCED_PARAMETER( s );

    signal(SIGINT, SIG_IGN);	/* To ignore any more ctrl c interrupts */

    //Get the Console instance and see if its there still..
    //CleanupConsole();

    StopMesh();
}

#ifdef WIN32
void closeMenu(void)
{
    wchar_t buf[256];
    HWND hwnd = NULL;
    HMENU hmenu;
    wsprintf(buf, TEXT("Mesh Agent"));
    SetConsoleTitle(buf);
    while (hwnd == NULL) hwnd = FindWindowEx(NULL, NULL, NULL, (LPCTSTR)buf);
    hmenu = GetSystemMenu(hwnd, FALSE);
    DeleteMenu(hmenu, SC_CLOSE, MF_BYCOMMAND);
    SetWindowPos(hwnd, NULL, 0, 0, 0, 0, SWP_NOSIZE | SWP_NOMOVE | SWP_NOZORDER | SWP_DRAWFRAME);
}
#endif

#if defined(_POSIX) || defined (_CONSOLE)
int main(int argc, char **argv)
#else
DWORD WINAPI GPMain(LPVOID lpParameter)
#endif
{
#ifdef WIN32
    closeMenu();
#endif

//Shutdown on Ctrl + C
    signal(SIGINT, BreakSink);

#ifdef _POSIX
    signal(SIGPIPE, SIG_IGN);
#ifdef _DEBUG
    //mtrace();
#endif
#endif

#ifdef MEMORY_CHECK
#ifdef WIN32
    //SET_CRT_DEBUG_FIELD( _CRTDBG_DELAY_FREE_MEM_DF );
    _CrtSetDbgFlag( _CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF | _CRTDBG_CHECK_ALWAYS_DF);
#endif
#endif

// Setup the AgentID
#ifdef WIN32
    if (sizeof(void*) == 4) g_agentid = AGENTID_WIN32_CONSOLE;
    if (sizeof(void*) == 8) g_agentid = AGENTID_WIN64_CONSOLE;
#endif

// If this console app is run with "-t", run all the unit tests and quit.
#ifdef _DEBUG
#if defined(_POSIX) || defined (_CONSOLE)
    if (argc == 2 && memcmp(argv[1], "-update:", 3) == 0)
    {
        ctrl_PerformSelfUpdate(argv[0], argv[1] + 8);
        return 0;
    }
    if (argc == 2 && memcmp(argv[1], "-ts", 3) == 0)
    {
        util_openssl_init();
        ut_PerformAllUnitTests(argc, argv);
        util_openssl_uninit();

#ifdef MEMORY_CHECK
#ifdef WIN32
        OutputHeading("Generating the final memory leak list\r\n");
        _CrtCheckMemory();
        _CrtDumpMemoryLeaks();
#endif
#endif
        return 0;
    }
    else if (argc == 2 && memcmp(argv[1], "-t1", 3) == 0)
    {
        util_openssl_init();
        ut_DynamicTestsuite1();
        util_openssl_uninit();

#ifdef MEMORY_CHECK
#ifdef WIN32
        OutputHeading("Generating the final memory leak list\r\n");
        _CrtCheckMemory();
        _CrtDumpMemoryLeaks();
#endif
#endif
        return 0;
    }

#endif
#endif

#ifdef WIN32
    {
        size_t len2 = 0, len = 0;
        wchar_t* str = NULL;

        len = strlen(argv[0]);
        if (len > 5)
        {
            MSG("Firewall setup.\r\n");
            str = (wchar_t*)malloc((len * 2) + 2);
            mbstowcs_s(&len2, str, len + 1, argv[0], len);
            if (len2 > 5) SetupWindowsFirewall(TEXT("Mesh Agent console application"), str);
            free(str);
        }
    }
#endif

#ifdef WIN32
    StartMesh(NULL);
#else
    StartMesh(argv[0]);
#endif

#if defined(WIN32) & !defined(_CONSOLE)
    PostMessage((HWND)lpParameter, WM_COMMAND, ID_MENU_SHUTDOWN, 0);
#endif

    MSG("Shutting down.\r\n");

#ifdef MEMORY_CHECK
#ifdef WIN32
    OutputHeading( "Generating the Final memory leak\r\n");
    _CrtCheckMemory();
    _CrtDumpMemoryLeaks();
#endif
#endif

#ifdef _POSIX
#ifdef _DEBUG
    //muntrace();
#endif
#endif

    return 0;
}

