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


#ifndef __HECI_LINUX_H__
#include "HECILinux.h"
#endif

#pragma pack(1)

typedef struct heci_ioctl_data
{
    uint32_t size;
    char *data;
} heci_ioctl_data_t;

/* IOCTL commands */
#undef HECI_IOCTL
#undef IOCTL_HECI_GET_VERSION
#undef IOCTL_HECI_CONNECT_CLIENT
#undef IOCTL_HECI_WD
#define HECI_IOCTL_TYPE 0x48
#define IOCTL_HECI_GET_VERSION \
    _IOWR(HECI_IOCTL_TYPE, 0x0, heci_ioctl_data_t)
#define IOCTL_HECI_CONNECT_CLIENT \
    _IOWR(HECI_IOCTL_TYPE, 0x01, heci_ioctl_data_t)
#define IOCTL_HECI_WD \
    _IOWR(HECI_IOCTL_TYPE, 0x02, heci_ioctl_data_t)
#define IAMT_HECI_GET_RECEIVED_MESSAGE_DATA \
    _IOW(HECI_IOCTL_TYPE, 0x03, heci_ioctl_data_t)

#pragma pack(0)

const char HECI_PTHI_GUID[16] = {0x12, 0xf8, 0x00, 0x28, 0xb4, 0xb7, 0x4b, 0x2d, 0xac, 0xa8, 0x46, 0xe0, 0xff, 0x65, 0x81, 0x4c};

int _fd;
bool m_haveHeciVersion;
HECI_VERSION m_heciVersion;

bool _initialized;
bool _verbose;
unsigned int  _bufSize;
unsigned char _protocolVersion;

#define false 0
#define true 1

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
    int result;
    HECI_CLIENT *heci_client;
    bool return_result = true;
    heci_ioctl_data_t version_response;
    heci_ioctl_data_t client_connect;

    m_haveHeciVersion = false;
    if (_initialized) {
        heci_Deinit();
    }

    _fd = open("/dev/heci", O_RDWR);

    if (_fd == -1 ) {
        if (_verbose) {
            fprintf(stderr, "Error: Cannot establish a handle to the HECI driver\n");
        }
        return false;
    }
    _initialized = true;
    version_response.size = sizeof(HECI_VERSION);
    version_response.data = (char *)malloc(version_response.size);
    if (!version_response.data) {
        if (_verbose) {
            fprintf(stderr, "malloc failure.\n");
        }
        return_result = false;
        heci_Deinit();
        goto heci_free;
    }

    result = ioctl(_fd, IOCTL_HECI_GET_VERSION, &version_response);
    if (result) {
        if (_verbose) {
            fprintf(stderr, "error in IOCTL_HECI_GET_VERSION recieve message. err=%d\n", result);
        }
        return_result = false;
        heci_Deinit();
        goto heci_free;
    }
    memcpy(&m_heciVersion, version_response.data, sizeof(HECI_VERSION));
    m_haveHeciVersion = true;
    if (_verbose) {
        fprintf(stdout, "Connected to HECI driver, version: %d.%d.%d.%d\n",
                m_heciVersion.major, m_heciVersion.minor, m_heciVersion.hotfix, m_heciVersion.build);
        fprintf(stdout, "Size of guid = %lu\n", (unsigned long)sizeof(HECI_PTHI_GUID));
    }
    client_connect.size = sizeof(HECI_PTHI_GUID);
    client_connect.data = (char *)malloc(client_connect.size);
    if (!client_connect.data) {
        if (_verbose) {
            fprintf(stderr, "malloc failure.\n");
        }
        return_result = false;
        heci_Deinit();
        goto heci_free;
    }
    memcpy(client_connect.data, &HECI_PTHI_GUID, sizeof(HECI_PTHI_GUID));
    result = ioctl(_fd, IOCTL_HECI_CONNECT_CLIENT, &client_connect);
    if (result) {
        if (_verbose) {
            fprintf(stderr, "error in IOCTL_HECI_CONNECT_CLIENT recieve message. err=%d\n", result);
        }
        return_result = false;
        heci_Deinit();
        goto heci_free;
    }
    heci_client = (HECI_CLIENT *) client_connect.data;
    if (_verbose) {
        fprintf(stdout, "max_message_length %d \n", (heci_client->MaxMessageLength));
        fprintf(stdout, "protocol_version %d \n", (heci_client->ProtocolVersion));
    }

    /*
    	if ((reqProtocolVersion > 0) && (heci_client->ProtocolVersion != reqProtocolVersion)) {
    		if (_verbose) {
    			fprintf(stderr, "Error: MEI protocol version not supported\n");
    		}
    		return_result = false;
    		heci_Deinit();
    		goto heci_free;
    	}
    */
    _protocolVersion = heci_client->ProtocolVersion;
    _bufSize = heci_client->MaxMessageLength;

heci_free:
    if (NULL != version_response.data) {
        free(version_response.data);
    }
    if (NULL != client_connect.data) {
        free(client_connect.data);
    }
    return return_result;
}

void heci_Deinit()
{
    if (_fd != -1) {
        close(_fd);
        _fd = -1;
    }

    _bufSize = 0;
    _protocolVersion = 0;
    _initialized = false;
}

int heci_ReceiveMessage(unsigned char *buffer, int len, unsigned long timeout)
{
    int rv = 0;
    int error = 0;

    if (_verbose) {
        fprintf(stdout, "call read length = %d\n", len);
    }
    rv = read(_fd, (void*)buffer, len);
    if (rv < 0) {
        error = errno;
        if (_verbose) {
            fprintf(stderr, "read failed with status %d %d\n", rv, error);
        }
        heci_Deinit();
    } else {
        if (_verbose) {
            fprintf(stderr, "read succeded with result %d\n", rv);
        }
    }
    return rv;
}

int heci_SendMessage(const unsigned char *buffer, int len, unsigned long timeout)
{
    int rv = 0;
    int return_length =0;
    int error = 0;
    fd_set set;
    struct timeval tv;

    tv.tv_sec =  timeout / 1000;
    tv.tv_usec =(timeout % 1000) * 1000000;

    if (_verbose) {
        fprintf(stdout, "call write length = %d\n", len);
    }
    rv = write(_fd, (void *)buffer, len);
    if (rv < 0) {
        error = errno;
        if (_verbose) {
            fprintf(stderr,"write failed with status %d %d\n", rv, error);
        }
        goto out;
    }

    return_length = rv;

    FD_ZERO(&set);
    FD_SET(_fd, &set);
    rv = select(_fd+1,&set, NULL, NULL, &tv);
    if (rv > 0 && FD_ISSET(_fd, &set)) {
        if (_verbose) {
            fprintf(stderr, "write success\n");
        }
    }
    else if (rv == 0) {
        if (_verbose) {
            fprintf(stderr, "write failed on timeout with status\n");
        }
        goto out;
    }
    else { //rv<0
        if (_verbose) {
            fprintf(stderr, "write failed on select with status %d\n", rv);
        }
        goto out;
    }

    rv = return_length;

out:
    if (rv < 0) {
        heci_Deinit();
    }

    return rv;
}

