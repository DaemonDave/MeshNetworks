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

#ifdef WIN32

#include <windows.h>
#include <crtdbg.h>
#include <netfw.h>
#include <objbase.h>
#include <oleauto.h>
#include <stdio.h>

extern "C"
{

int SetupWindowsFirewall(wchar_t* friendlyname, wchar_t* processname)
{
    HRESULT h = S_OK;
    BSTR fwBstr1 = NULL;
    BSTR fwBstr2 = NULL;
    INetFwMgr* fwMgr = NULL;
    INetFwPolicy* fwPolicy = NULL;
    INetFwProfile* fwProfile = NULL;
    INetFwAuthorizedApplication* fwApp = NULL;
    INetFwAuthorizedApplications* fwApps = NULL;
	int len = 0;
	int ret = 0;
	const IID x1 = __uuidof(INetFwMgr);

	// Setup COM calls & firewall interface
    h = CoInitializeEx(0, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
    if (h != RPC_E_CHANGED_MODE && FAILED(h)) return 0;
    if (FAILED(CoCreateInstance(__uuidof(NetFwMgr), NULL, CLSCTX_INPROC_SERVER, __uuidof(INetFwMgr), (void**)&fwMgr))) goto error;

	// Get firewall policy, profile, apps
    if (FAILED(fwMgr->get_LocalPolicy(&fwPolicy))) goto error;
	if (FAILED(fwPolicy->get_CurrentProfile(&fwProfile))) goto error;
    if (FAILED(fwProfile->get_AuthorizedApplications(&fwApps))) goto error;

	// Add an application to the Microsoft Windows XP firewall
	{
		// Create an instance of an authorized application.
		if (FAILED(CoCreateInstance(__uuidof(NetFwAuthorizedApplication), NULL, CLSCTX_INPROC_SERVER, __uuidof(INetFwAuthorizedApplication), (void**)&fwApp))) goto error;

		// Set the process image file name.
		fwBstr1 = SysAllocString(processname);
		if (fwBstr1 == NULL) goto error;
		h = fwApp->put_ProcessImageFileName(fwBstr1);
		if (FAILED(h)) goto error;

		// Set the application friendly name.
		fwBstr2 = SysAllocString(friendlyname);
		if (SysStringLen(fwBstr2) == 0) goto error;
		h = fwApp->put_Name(fwBstr2);
		if (FAILED(h)) goto error;

		// Add the application to the collection.
		h = fwApps->Add(fwApp);
		if (FAILED(h)) goto error;
	}
	ret = 1;

error:

	// Clean up
    if (fwBstr1 != NULL) SysFreeString(fwBstr1);
    if (fwBstr2 != NULL) SysFreeString(fwBstr2);
    if (fwApp != NULL) fwApp->Release();
    if (fwApps != NULL) fwApps->Release();
    if (fwProfile != NULL) fwProfile->Release();
    if (fwPolicy != NULL) fwPolicy->Release();
    if (fwMgr != NULL) fwMgr->Release();
	CoUninitialize();

	return ret;
}


int ClearWindowsFirewall(wchar_t* processname)
{
	HRESULT h = S_OK;
    BSTR fwBstr = NULL;
	INetFwMgr* fwMgr = NULL;
	INetFwPolicy* fwPolicy = NULL;
    INetFwProfile* fwProfile = NULL;
    INetFwAuthorizedApplications* fwApps = NULL;
	int ret = 0;

	// Setup COM calls & firewall interface
    h = CoInitializeEx(0, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
    if (h != RPC_E_CHANGED_MODE && FAILED(h)) return 0;
    if (FAILED(CoCreateInstance(__uuidof(NetFwMgr), NULL, CLSCTX_INPROC_SERVER, __uuidof(INetFwMgr), (void**)&fwMgr))) goto error;

	// Get firewall policy, profile, apps
    if (FAILED(fwMgr->get_LocalPolicy(&fwPolicy))) goto error;
	if (FAILED(fwPolicy->get_CurrentProfile(&fwProfile))) goto error;
    if (FAILED(fwProfile->get_AuthorizedApplications(&fwApps))) goto error;

    // Remove the firewall rules
    fwBstr = SysAllocString(processname);
    if (fwBstr == NULL) goto error;
	if (FAILED(fwApps->Remove(fwBstr))) goto error;
	ret = 1;

error:

    // Cleanup
    if (fwBstr != NULL) SysFreeString(fwBstr);
    if (fwApps != NULL) fwApps->Release();
	if (fwProfile != NULL) fwProfile->Release();
    if (fwPolicy != NULL) fwPolicy->Release();
	if (fwMgr != NULL) fwMgr->Release();
	CoUninitialize();

    return ret;
}


}

#endif