/*
Copyright (c) 2009, Intel Corporation
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice,
this list of conditions and the following disclaimer.
* Redistributions in binary form must reproduce the above copyright
notice, this list of conditions and the following disclaimer in the
documentation and/or other materials provided with the distribution.
* Neither the name of Intel Corporation nor the names of its contributors
may be used to endorse or promote products derived from this software
without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <stdio.h>
#include <string.h>

//! \todo fix Windows headers if necessary
//#include <windows.h>
//#include <tchar.h>
//#include <direct.h>
//#include <shlobj.h>



#ifndef __MeshCore_h__
#include "meshcore.h"
#endif

#ifndef __MeshCtrl_h__
#include "meshctrl.h"
#endif

#ifndef __ILibParsers__
#include "LibParsers.h"
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

/*

int SetupWindowsFirewall(wchar_t* friendlyname, wchar_t* processname);
int ClearWindowsFirewall(wchar_t* processname);

TCHAR* serviceFile = TEXT("Mesh Agent");
TCHAR* serviceName = TEXT("Mesh Agent background service");
TCHAR* serviceDesc = TEXT("Reliable peer-to-peer remote monitoring and management service.");
SERVICE_STATUS serviceStatus;
SERVICE_STATUS_HANDLE serviceStatusHandle = 0;
extern unsigned short g_agentid;

void WINAPI ServiceControlHandler( DWORD controlCode )
{
	switch (controlCode)
	{
		case SERVICE_CONTROL_INTERROGATE:
			break;
		case SERVICE_CONTROL_SHUTDOWN:
		case SERVICE_CONTROL_STOP:
			serviceStatus.dwCurrentState = SERVICE_STOP_PENDING;
			SetServiceStatus( serviceStatusHandle, &serviceStatus );
			StopMesh();
			return;
		default:
			break;
	}

	SetServiceStatus( serviceStatusHandle, &serviceStatus );
}


void WINAPI ServiceMain(DWORD argc, LPTSTR *argv)
{
	size_t len = 0;
	TCHAR str[_MAX_PATH];
	char selfexe[_MAX_PATH];
	char *selfexe_ptr = NULL;

	// Initialise service status
	serviceStatus.dwServiceType = SERVICE_WIN32;
	serviceStatus.dwCurrentState = SERVICE_STOPPED;
	serviceStatus.dwControlsAccepted = 0;
	serviceStatus.dwWin32ExitCode = NO_ERROR;
	serviceStatus.dwServiceSpecificExitCode = NO_ERROR;
	serviceStatus.dwCheckPoint = 0;
	serviceStatus.dwWaitHint = 0;
	serviceStatusHandle = RegisterServiceCtrlHandler(serviceName, ServiceControlHandler);

	if (serviceStatusHandle)
	{
		// Service is starting
		serviceStatus.dwCurrentState = SERVICE_START_PENDING;
		SetServiceStatus(serviceStatusHandle, &serviceStatus);

		// Service running
		serviceStatus.dwControlsAccepted |= (SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN);
		serviceStatus.dwCurrentState = SERVICE_RUNNING;
		SetServiceStatus( serviceStatusHandle, &serviceStatus);

		// Get our own executable name
		if (GetModuleFileName(NULL, str, _MAX_PATH) > 5)
		{
			wcstombs_s(&len, selfexe, _MAX_PATH, str, _MAX_PATH);
			selfexe_ptr = selfexe;
		}

		// Run the mesh agent
		StartMesh(selfexe_ptr);

		// Service was stopped
		serviceStatus.dwCurrentState = SERVICE_STOP_PENDING;
		SetServiceStatus(serviceStatusHandle, &serviceStatus);

		// Service is now stopped
		serviceStatus.dwControlsAccepted &= ~(SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN);
		serviceStatus.dwCurrentState = SERVICE_STOPPED;
		SetServiceStatus(serviceStatusHandle, &serviceStatus);
	}
}

void RunService()
{
	SERVICE_TABLE_ENTRY serviceTable[] =
	{
		{ serviceName, (LPSERVICE_MAIN_FUNCTION)ServiceMain },
		{ 0, 0 }
	};

	StartServiceCtrlDispatcher( serviceTable );
}

void InstallService()
{
	SC_HANDLE serviceControlManager = OpenSCManager( 0, 0, SC_MANAGER_CREATE_SERVICE );
	SERVICE_DESCRIPTION sd;
	SERVICE_DELAYED_AUTO_START_INFO as;
	SERVICE_FAILURE_ACTIONS fa;
	SC_ACTION failactions[3];
	BOOL r;

	if ( serviceControlManager )
	{
		char path[1024];
		if (GetModuleFileName( 0, (LPTSTR)path, 1024) > 0)
		{
			// Install the service
			SC_HANDLE service = CreateService(
				serviceControlManager,
				serviceFile,
				serviceName,
				SERVICE_ALL_ACCESS,
				SERVICE_WIN32_OWN_PROCESS | SERVICE_INTERACTIVE_PROCESS,
				SERVICE_AUTO_START,
				SERVICE_ERROR_IGNORE,
				(LPCTSTR)path,
				0, 0, 0, 0, 0 );

			if (service)
			{
				// Update the service description
				sd.lpDescription = serviceDesc;
				ChangeServiceConfig2(service, SERVICE_CONFIG_DESCRIPTION, &sd);

				// Update the service auto-start
				as.fDelayedAutostart = TRUE;
				ChangeServiceConfig2(service, SERVICE_CONFIG_DELAYED_AUTO_START_INFO, &as);

				// Update the faliure action
				failactions[0].Type = SC_ACTION_RESTART;
				failactions[0].Delay = 120000;				// Wait 2 minutes before faliure restart (milliseconds)
				failactions[1].Type = SC_ACTION_RESTART;
				failactions[1].Delay = 120000;				// Wait 2 minutes before faliure restart (milliseconds)
				failactions[2].Type = SC_ACTION_NONE;
				failactions[2].Delay = 120000;
				memset(&fa, 0, sizeof(SERVICE_FAILURE_ACTIONS));
				fa.dwResetPeriod = 86400;					// After 1 days, reset the faliure counters (seconds)
				fa.cActions = 3;
				fa.lpsaActions = failactions;
				r = ChangeServiceConfig2(service, SERVICE_CONFIG_FAILURE_ACTIONS, &fa);

				// Cleanup
				CloseServiceHandle( service );
				#ifdef _DEBUG
				printf("Mesh service installed successfully\n");
				#endif
			}
			else
			{
				#ifdef _DEBUG
				if(GetLastError() == ERROR_SERVICE_EXISTS)
					printf("Mesh service already exists.\n");
				else
					printf("Mesh service was not Installed Successfully. Error Code %d\n", GetLastError());
				#endif
			}
		}

		CloseServiceHandle( serviceControlManager );
	}
}

void UninstallService()
{
	SC_HANDLE serviceControlManager = OpenSCManager( 0, 0, SC_MANAGER_CONNECT);

	if (serviceControlManager)
	{
		SC_HANDLE service = OpenService( serviceControlManager, serviceFile, SERVICE_QUERY_STATUS | DELETE );
		if (service)
		{
			SERVICE_STATUS serviceStatus;
			if ( QueryServiceStatus( service, &serviceStatus ) )
			{
				if ( serviceStatus.dwCurrentState == SERVICE_STOPPED )
				{
					if(DeleteService(service))
					{
						#ifdef _DEBUG
						printf("Mesh service removed successfully\n");
						#endif
					}
					else
					{
						#ifdef _DEBUG
						DWORD dwError = GetLastError();
						if(dwError == ERROR_ACCESS_DENIED)
							printf("Access denied while trying to remove mesh service \n");
						else if(dwError == ERROR_INVALID_HANDLE)
							printf("Handle invalid while trying to remove mesh service \n");
						else if(dwError == ERROR_SERVICE_MARKED_FOR_DELETE)
							printf("Mesh service already marked for deletion\n");
						#endif
					}
				}
				else
				{
					#ifdef _DEBUG
					printf("Mesh service is still running.\n");
					#endif
				}
			}
			CloseServiceHandle( service );
		}
		CloseServiceHandle( serviceControlManager );
	}
}

void LaunchService()
{
	SC_HANDLE serviceControlManager = OpenSCManager( 0, 0, SERVICE_QUERY_STATUS | SERVICE_START);

	if (serviceControlManager)
	{
		SC_HANDLE service = OpenService( serviceControlManager, serviceFile, SERVICE_QUERY_STATUS | SERVICE_START );
		if (service)
		{
			SERVICE_STATUS serviceStatus;
			if ( QueryServiceStatus( service, &serviceStatus ) )
			{
				if ( serviceStatus.dwCurrentState == SERVICE_STOPPED )
				{
					if (StartService(service, 0, NULL) == FALSE)
					{
						// TODO: Failed to start service
					}
				}
				else
				{
					#ifdef _DEBUG
					printf("Mesh service is running.\n");
					#endif
				}
			}
			CloseServiceHandle( service );
		}
		CloseServiceHandle( serviceControlManager );
	}
}

void StopService()
{
	SERVICE_STATUS ServiceStatus;
	SC_HANDLE serviceControlManager = OpenSCManager( 0, 0, SERVICE_QUERY_STATUS | SERVICE_STOP);

	if (serviceControlManager)
	{
		SC_HANDLE service = OpenService( serviceControlManager, serviceFile, SERVICE_QUERY_STATUS | SERVICE_STOP );
		if (service)
		{
			SERVICE_STATUS serviceStatus;
			if ( QueryServiceStatus( service, &serviceStatus ) )
			{
				if ( serviceStatus.dwCurrentState != SERVICE_STOPPED )
				{
					if (ControlService(service, SERVICE_CONTROL_STOP, &ServiceStatus) == FALSE)
					{
						// TODO: Unable to stop service
					}
					else
					{
						Sleep(3000);
					}
				}
			}
			CloseServiceHandle( service );
		}
		CloseServiceHandle( serviceControlManager );
	}
}

int _tmain( int argc, TCHAR* argv[] )
{
	TCHAR str[_MAX_PATH];

	// Setup the AgentID
	#ifdef WIN32
		if (sizeof(void*) == 4) g_agentid = AGENTID_WIN32_SERVICE;
		if (sizeof(void*) == 8) g_agentid = AGENTID_WIN64_SERVICE;
	#endif

	if ( argc > 1 && lstrcmpi( argv[1], TEXT("-start") ) == 0 )
	{
		// Ask the service manager to launch the service
		LaunchService();
	}
	else if ( argc > 1 && lstrcmpi( argv[1], TEXT("-stop") ) == 0 )
	{
		// Ask the service manager to stop the service
		StopService();
	}
	else if ( argc > 1 && lstrcmpi( argv[1], TEXT("-install") ) == 0 )
	{
		// Setup the service
		StopService();
		UninstallService();
		InstallService();

		// Setup the Windows firewall
		if (GetModuleFileName(NULL, str, _MAX_PATH) > 5)
		{
			ClearWindowsFirewall(str);
			if (SetupWindowsFirewall(serviceName, str) != 0)
			{
				#ifdef _DEBUG
				printf("Firewall rules added successfully.\n");
				#endif
			}
			else
			{
				#ifdef _DEBUG
				printf("Unable to add firewall rules.\n");
				#endif
			}
		}
	}
	else if ( argc > 1 && (lstrcmpi( argv[1], TEXT("-remove") ) == 0) ||  (lstrcmpi( argv[1], TEXT("-uninstall") ) == 0))
	{
		// Ask the service manager to stop the service
		StopService();

		// Remove the service
		UninstallService();

		// Cleanup the firewall rules
		if (GetModuleFileName(NULL, str, _MAX_PATH) > 5)
		{
			if (ClearWindowsFirewall(str) != 0)
			{
				#ifdef _DEBUG
				printf("Firewall rules removed successfully.\n");
				#endif
			}
			else
			{
				#ifdef _DEBUG
				printf("Unable to remove firewall rules.\n");
				#endif
			}
		}

	}
	else if ( argc > 1 && memcmp( argv[1], TEXT("-update:"), 16 ) == 0 )
	{
		size_t len1;
		size_t len2;
		char targetexe[_MAX_PATH];
		char selfexe[_MAX_PATH];

		// Get the target executable for update
		wcstombs_s(&len1, targetexe, _MAX_PATH, argv[1], _MAX_PATH);

		// Get out own executable
		wcstombs_s(&len2, selfexe, _MAX_PATH, argv[0], _MAX_PATH);

		// Wait a little to give time for the calling process to exit
		Sleep(5000);

		// Attempt to copy our own exe over the target
		remove(targetexe + 8);
		if (CopyFileA(selfexe, targetexe + 8, FALSE) == FALSE)
		{
			// TODO: Copy failed
		}

		// Attempt to start the updated service up again
		LaunchService();
	}
	else if (argc > 1 && memcmp( argv[1], TEXT("-fullinstall"), 12 ) == 0 )
	{
		size_t len;
		size_t len2;
		char targetexe2[_MAX_PATH];
		char *targetexe = targetexe2 + 1;
		char selfexe[_MAX_PATH];

		// Remove the older service
		StopService();
		UninstallService();

		// Get the target executable, create folders if needed
		if (SHGetFolderPathA(NULL, CSIDL_PROGRAM_FILES | CSIDL_FLAG_CREATE, NULL, SHGFP_TYPE_CURRENT, targetexe) != S_FALSE)
		{
			len = strlen(targetexe);
			if (len + 19 <= MAX_PATH)
			{
				memcpy(targetexe + len, "\\Mesh Agent\\", 13);
				CreateDirectoryA(targetexe, NULL); // We don't care about the error code, path may already exist.
				memcpy(targetexe + len + 12, "MeshAgent.exe", 14);
			}
		}

		// Get out own executable
		wcstombs_s(&len2, selfexe, _MAX_PATH, argv[0], _MAX_PATH);

		// Attempt to copy our own exe over the target
		remove(targetexe + 8);
		if (CopyFileA(selfexe, targetexe, FALSE) == FALSE)
		{
			// TODO: Copy failed
		}

		// Attempt to start the updated service up again
		targetexe2[0] = '\"';
		memcpy(targetexe + len + 12 + 13, "\" -install", 11);
		system(targetexe2);
		memcpy(targetexe + len + 12 + 13, "\" -start", 9);
		system(targetexe2);
	}
	else if (argc > 1 && memcmp( argv[1], TEXT("-fulluninstall"), 14 ) == 0 )
	{
		size_t len;
		char targetexe2[_MAX_PATH];
		char *targetexe = targetexe2 + 1;
		targetexe2[0] = '\"';

		// Stop and remove the service
		StopService();
		UninstallService();

		// Call uninstall, this will remove the firewall rules.
		if (SHGetFolderPathA(NULL, CSIDL_PROGRAM_FILES | CSIDL_FLAG_CREATE, NULL, SHGFP_TYPE_CURRENT, targetexe) != S_FALSE)
		{
			len = strlen(targetexe);
			if (len + 19 <= MAX_PATH)
			{
				memcpy(targetexe + len, "\\Mesh Agent\\", 13);
				memcpy(targetexe + len + 12, "MeshAgent.exe\" -uninstall", 26);
				system(targetexe2);
			}
		}

		// Remove the target executable.
		if (SHGetFolderPathA(NULL, CSIDL_PROGRAM_FILES | CSIDL_FLAG_CREATE, NULL, SHGFP_TYPE_CURRENT, targetexe) != S_FALSE)
		{
			len = strlen(targetexe);
			if (len + 19 <= MAX_PATH)
			{
				memcpy(targetexe + len, "\\Mesh Agent\\", 13);
				memcpy(targetexe + len + 12, "MeshAgent.exe", 14);
				remove(targetexe);
			}
		}

		// Remove the folder.
		if (SHGetFolderPathA(NULL, CSIDL_PROGRAM_FILES | CSIDL_FLAG_CREATE, NULL, SHGFP_TYPE_CURRENT, targetexe) != S_FALSE)
		{
			len = strlen(targetexe);
			if (len + 19 <= MAX_PATH)
			{
				memcpy(targetexe + len, "\\Mesh Agent\\", 13);
				RemoveDirectoryA(targetexe);
			}
		}
	}
	else
	{
		RunService();
	}
	return 0;
}
*/
