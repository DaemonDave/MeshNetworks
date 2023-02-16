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


//! \note DRE 2022

/**
 * DRE notes:
 *
 * Unsure what the version of OpenSSL that this meshnetworks source uses.
 *
 * Tried OpenSSL 1.1.0
 * Tried OpenSSL 3.0
 * Tried OpenSSL SSLeay
 *
 * And there was no immediate match across the board.
 *
 * Rather than the arduous attempt I was making at converting over all the OpenSSL functionality, I will port into this mesh-werk the needed
 * OpenSSL functions from the original source.  That makes this a contained source code with the specific encrypted / decrypted functions needed herein.
 *
 * This is a reuse cannibalize in reverse: it takes outside source into the code base to complete it without altering the internal function.
 *
 * This makes the amount of code that needs to be searched and understood down to a minimum.
 *
 * I changed my mind overnight: I am going to comment out for now and the reason is below:
 *
 * NOTE: I have commented out the cipher / decipher
 * 	                              certify / decertify
 *                                encrypt / decrypt functions in order to get the mesh working without encryption.
 *
 * At a later date, I will reintroduce encryption from the better OpenSSL examples.
 *
 *
 * The meshnetwork pulled out a couple of certification, decertification, cipher and decipher, encrypt and decrypt methods when OpenSSL comes ready to do all at once for any kind of traffic.
 *
 * The s_client.c demos really show how to make one client work on many which could be useful.
 *
 * I think rather than trying to find the right source code to get a partial cipher system working it would be better
 * to invest some time later on within the OpenSSL versions I have to make the mesh work with many encryption types so that the
 * system can use any kind of traffic.
 *
 * For now, the goal is open in the clear mesh communication for many servers / clients as mesh members.
 *
 * Later improvement or other improvement is secured comms.
 *
 * The network is one level of latency.
 *
 * Secured comms is another level of latency.
 *
 * */




#ifndef __MeshUtils__
#include "utils.h"
#endif


char g_selfid_mcast[4 + UTIL_HASHSIZE];
char g_selfid[UTIL_HASHSIZE];

struct NodeInfoBlock* g_nodeblock = NULL;
char* g_signedblock = NULL;
int g_signedblocklen = 0;
char* g_signedblockhash = NULL;
unsigned int g_signedblocksynccounter = 0;
unsigned int g_serial = 0;
unsigned int g_SessionRandomId;
unsigned int g_nextiv = 0;
char g_SessionRandom[32];
unsigned short g_agentid = AGENTID_UNKNOWN;
int g_PerformingSelfUpdate = 0;

//! \var time_local 
struct timespec time_local;
// Convert a block of data to HEX
// The "out" must have (len*2)+1 free space.
char utils_HexTable[16] = { '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f' };


// moved from meshconfig
// Local event subscription list
int ctrl_SubscriptionChainCount = 0; // Keeps an approximate (equal or above) count of subscribers. Useful for event optimization.

char NullNodeId[32] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };


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

#ifdef _POSIX
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
#endif
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


