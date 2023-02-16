/*******************************************************************************
 * Copyright (C) 2004-2008 Intel Corp. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   - Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *
 *   - Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *
 *   - Neither the name of Intel Corp. nor the names of its
 *     contributors may be used to endorse or promote products derived from this
 *     software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS ``AS IS''
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL Intel Corp. OR THE CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *******************************************************************************/

#include <windows.h>
#include <stdio.h>
#include <process.h>
#include <commctrl.h>
#include <setupapi.h>
#include <initguid.h>
#include <tchar.h>
#include <winioctl.h>
#include <errno.h>
#include "HECIWin.h"
#include "heci_if.h"

#define false 0
#define true 1
#define HECI_MAX_LINE_LEN 300

DEFINE_GUID(GUID_DEVINTERFACE_HECI, 0xE2D1FF34, 0x3458, 0x49A9, 0x88, 0xDA, 0x8E, 0x69, 0x15, 0xCE, 0x9B, 0xE5);
DEFINE_GUID(HECI_PTHI_GUID, 0x12F80028,0xB4B7,0x4b2d,0xAC,0xA8,0x46,0xE0,0xFF,0x65,0x81,0x4c);

bool _initialized;
bool _verbose;
unsigned int  _bufSize;
unsigned char _protocolVersion;

int _fd;
bool m_haveHeciVersion;
HECI_VERSION m_heciVersion;
HANDLE _handle;

//VOID _displayHECIError(UINT32 errorCode,DWORD lastError);
//VOID _displayHECIData(UINT32 messageId);
int heci_doIoctl(DWORD code, void *inbuf, int inlen, void *outbuf, int outlen);


/***************************** public functions *****************************/

unsigned int heci_GetBufferSize() {
    return _bufSize;
}
unsigned char heci_GetProtocolVersion() {
    return _protocolVersion;
}
bool heci_IsInitialized() {
    return _initialized;
}

bool heci_GetHeciVersion(HECI_VERSION *version)
{
    if (m_haveHeciVersion) {
        memcpy(version, &m_heciVersion, sizeof(HECI_VERSION));
        return true;
    }
    return false;
}

bool heci_Init()
{
    PSP_DEVICE_INTERFACE_DETAIL_DATA deviceDetail = NULL;
    HDEVINFO hDeviceInfo;
    DWORD bufferSize;
    SP_DEVICE_INTERFACE_DATA interfaceData;
    LONG ii = 0;
    int result;
    HECI_CLIENT properties;

    _verbose = false;

    if (_initialized) {
        heci_Deinit();
    }

    // Find all devices that have our interface
    hDeviceInfo = SetupDiGetClassDevs((LPGUID)&GUID_DEVINTERFACE_HECI, NULL, NULL, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
    if (hDeviceInfo == INVALID_HANDLE_VALUE) {
        if (_verbose) {
            //_displayHECIError(GET_CLASS_DEVS,GetLastError());
        }
        return false; //GET_CLASS_DEVS;
    }

    // Setup the interface data struct
    interfaceData.cbSize = sizeof(interfaceData);
    for (ii = 0;
            SetupDiEnumDeviceInterfaces(hDeviceInfo, NULL, (LPGUID)&GUID_DEVINTERFACE_HECI, ii, &interfaceData);
            ++ii) {
        // Found our device instance
        if (!SetupDiGetDeviceInterfaceDetail(hDeviceInfo, &interfaceData, NULL,  0, &bufferSize, NULL)) {
            DWORD err = GetLastError();
            if (err != ERROR_INSUFFICIENT_BUFFER) {
                if (_verbose) {
                    //_displayHECIError(GET_INTERFACE_DETAIL,err);
                }
                continue;
            }
        }

        // Allocate a big enough buffer to get detail data
        deviceDetail = (PSP_DEVICE_INTERFACE_DETAIL_DATA) malloc(bufferSize);
        if (deviceDetail == NULL) {
            if (_verbose) {
                //_displayHECIError(ALLOCATE_MEMORY_ERROR,0);
            }
            continue;
        }

        // Setup the device interface struct
        deviceDetail->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA);

        // Try again to get the device interface detail info
        if (!SetupDiGetDeviceInterfaceDetail(hDeviceInfo, &interfaceData, deviceDetail, bufferSize, NULL, NULL))
        {
            if (_verbose) {
                DWORD err = GetLastError();
                //_displayHECIError(GET_INTERFACE_DETAIL,err);
            }
            free(deviceDetail);
            deviceDetail = NULL;
            continue;
        }

        break;
    }
    SetupDiDestroyDeviceInfoList(hDeviceInfo);

    if (deviceDetail == NULL) {
        if (_verbose) {
            //_displayHECIError(FIND_HECI_FAILURE,0);
        }
        return false; //FIND_HECI_FAILURE;
    }

    _handle = CreateFile(deviceDetail->DevicePath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
    free(deviceDetail);

    if (_handle == INVALID_HANDLE_VALUE) {
        if (_verbose) {
            //_displayHECIError(CREATE_HECI_FILE_FAILURE,GetLastError());
        }
        return false; //CREATE_HECI_FILE_FAILURE;
    }
    _initialized = true;

    result = heci_doIoctl(IOCTL_HECI_GET_VERSION, NULL, 0, &m_heciVersion, sizeof(HECI_VERSION));
    if (result != sizeof(HECI_VERSION)) {
        if (_verbose) {
            //_displayHECIError(GET_HECI_DRIVER_VERSION_FAILURE,0);
        }
        heci_Deinit();
        return false; //GET_HECI_DRIVER_VERSION_FAILURE;
    }
    m_haveHeciVersion = true;

    if (_verbose) {
        //_displayHECIData(HECI_DRIVER_VERSION);
        //_ftprintf(stdout,_T("%d.%d.%d.%d\n"), (m_heciVersion).major, (m_heciVersion).minor, (m_heciVersion).hotfix, (m_heciVersion).build);
    }

    result = heci_doIoctl(IOCTL_HECI_CONNECT_CLIENT, (void*)(&HECI_PTHI_GUID), sizeof(GUID), &properties, sizeof(properties));
    if (result != sizeof(properties))
    {
        if (_verbose) {
            //_displayHECIError(HECI_CONNECT_TO_PTHI_CLIENT_FAILURE,0);
        }
        //Deinit();
        return false; //HECI_CONNECT_TO_PTHI_CLIENT_FAILURE;
    }
    _bufSize = properties.MaxMessageLength;

    return true;
}

void heci_Deinit()
{
    if (_handle != INVALID_HANDLE_VALUE) {
        CloseHandle(_handle);
        _handle = INVALID_HANDLE_VALUE;
    }

    _bufSize = 0;
    _initialized = false;

    if (_handle != INVALID_HANDLE_VALUE) {
        CloseHandle(_handle);
    }
}

int heci_ReceiveMessage(unsigned char *buffer, int len, unsigned long timeout) // Timeout default is 2000
{
    DWORD bytesRead = 0;
    int res;
    HANDLE h_event = NULL;
    OVERLAPPED overlapped;
    DWORD error;
    DWORD eventRes;

    if ((h_event = CreateEvent(NULL, FALSE, FALSE, NULL)) == 0) goto out;
    overlapped.hEvent = h_event;
    overlapped.Offset = 0;
    overlapped.OffsetHigh = 0;

    res = ReadFile(_handle, buffer, len, &bytesRead, &overlapped);
    error = GetLastError();
    if ((0 == res) && (ERROR_IO_PENDING != error)) {
        if (_verbose) {
            //_displayHECIError(READ_FILE,GetLastError());
        }
        bytesRead = -1;
        goto out;
    }

    eventRes = WaitForSingleObject(h_event, timeout);
    if (eventRes == WAIT_TIMEOUT) {
        bytesRead = 0;
        goto out;
    }

    res = GetOverlappedResult(_handle, &overlapped, &bytesRead, true);

    if (res == 0) {
        if (_verbose) {
            //_displayHECIError(READ_FILE,GetLastError());
        }
        bytesRead = -1;
        goto out;
    }

out:
    if (h_event != NULL) CloseHandle(h_event);
    if (bytesRead <= 0) heci_Deinit();

    return bytesRead;
}

int heci_SendMessage(const unsigned char *buffer, int len, unsigned long timeout)  // Timeout default is 2000
{
    DWORD bytesWritten = 0;
    int res;
    HANDLE h_event = NULL;
    OVERLAPPED overlapped;
    DWORD lastError;
    DWORD eventRes;

    if ((h_event = CreateEvent(NULL, FALSE, FALSE, NULL)) == 0) goto out;
    overlapped.hEvent = h_event;
    overlapped.Offset = 0;
    overlapped.OffsetHigh = 0;

    res = WriteFile(_handle, buffer, len, &bytesWritten, &overlapped);

    lastError = GetLastError();
    if ((0 == res) && (ERROR_IO_PENDING !=lastError )) {
        if (_verbose) {
            //_displayHECIError(WRITE_FILE,GetLastError());
        }
        bytesWritten = -1;
        goto out;
    }

    eventRes = WaitForSingleObject(h_event, timeout);
    if (eventRes == WAIT_TIMEOUT) {
        if (_verbose) {
            //_displayHECIError(WRITE_FILE_TIME_OUT,0);
        }
        bytesWritten = 0;
        goto out;
    }

    res = GetOverlappedResult(_handle, &overlapped, &bytesWritten, false);

    if (res == 0) {
        if (_verbose) {
            //_displayHECIError(WRITE_FILE,GetLastError());
        }
        bytesWritten = -1;
        goto out;
    }

out:
    if (h_event != NULL) CloseHandle(h_event);
    if (bytesWritten <= 0) heci_Deinit();

    return bytesWritten;
}

int heci_doIoctl(DWORD code, void *inbuf, int inlen, void *outbuf, int outlen)
{
    int res;
    DWORD bytesRead = 0;
    HANDLE h_event = NULL;
    OVERLAPPED overlapped;

    if (!_initialized) return -1;

    if ((h_event = CreateEvent(NULL, FALSE, FALSE, NULL)) == 0) goto out;
    overlapped.hEvent = h_event;
    overlapped.Offset = 0;
    overlapped.OffsetHigh = 0;

    res = DeviceIoControl(_handle, code, inbuf, inlen, outbuf, outlen, &bytesRead, &overlapped);

    if ((0 == res) && (ERROR_IO_PENDING != GetLastError())) {
        if (_verbose) {
            //_displayHECIError(IOCTL_COMMAND,GetLastError());
        }
        bytesRead = -1;
        goto out;
    }

    WaitForSingleObject(h_event, INFINITE);

    res = GetOverlappedResult(_handle, &overlapped, &bytesRead, true);
    if (res == 0) {
        if (_verbose) {
            //_displayHECIError(IOCTL_COMMAND,GetLastError());
        }
        bytesRead = -1;
        goto out;
    }

out:
    if (h_event != NULL) CloseHandle(h_event);
    if (bytesRead < 0) heci_Deinit();

    return bytesRead;
}

TCHAR *_getErrMsg(DWORD err)
{
    static TCHAR buffer[1024];
    FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM,
                  NULL,
                  err,
                  0,
                  buffer,
                  sizeof(buffer) - 1,
                  0);

    return buffer;
}

HANDLE heci_GetHandle() {
    return _handle;
}

/*
// Display a HECI error message
void _displayHECIError(UINT32 errorCode, DWORD lastError)
{
    TCHAR str[HECI_MAX_LINE_LEN];
    TCHAR *msg;
    LoadString(GetModuleHandle(NULL), HECI_ERROR_MESSAGE, str, sizeof(str)/sizeof(TCHAR));
    _ftprintf(stderr, _T("%s"), str);
	_ftprintf(stderr, _T("%s"), L" ");
	LoadString(GetModuleHandle(NULL), errorCode , str, sizeof(str)/sizeof(TCHAR));
    if(0!= lastError)
    {
         msg = _getErrMsg(lastError);
	    _ftprintf(stderr, _T("%s (%d): %s\n"),str, lastError, msg);
    }
    else
    {
        _ftprintf(stderr, _T("%s\n"),str);
    }
}

// Display a HECI data message
void _displayHECIData(UINT32 messageId)
{
    TCHAR str[HECI_MAX_LINE_LEN];
    LoadString(GetModuleHandle(NULL), messageId , str, sizeof(str)/sizeof(TCHAR));
    _ftprintf(stdout,_T("%s"),str);
	_ftprintf(stdout,_T("%s"),L" ");
}
*/

