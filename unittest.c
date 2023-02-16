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


#ifndef __UNITTEST_H__
#include "unittest.h"
#endif

// We need these as the master key for most of the symetric crypto methods
extern unsigned int g_SessionRandomId;
extern char g_SessionRandom[32];
extern unsigned int g_nextiv;

extern char g_selfid[UTIL_HASHSIZE];
extern char g_selfid_mcast[4 + UTIL_HASHSIZE];


extern void* Chain;

//! \note "gut_" I believe means global unit test as an extension to variable names. 

void *gut_Chain = NULL;
void *gut_Timer = NULL;
int   gut_IPv6Support;
void *gut_AsyncSocket = NULL;
void *gut_AsyncServer = NULL;
int   gut_TestNumber = 0;
struct sockaddr_in6 gut_localInterface;
struct sockaddr_in6 gut_remoteInterface1;
struct sockaddr_in6 gut_remoteInterface2;
struct sockaddr_in6 gut_serverInterface;




// Perform all of the unit tests in a row
int ut_PerformAllUnitTests(int argc, char **argv)
{
    if (argc > 0) ut_StaticTestsuite1(argv[0]);
    //ut_StaticTestsuite2();
    ut_StaticTestsuite3();
    ut_StaticTestsuite4();
    ut_StaticTestsuite5();
    return 0;
}

// Basic set crypto tests that should have not problem working well.
int ut_StaticTestsuite1(char* exename)
{
    int l, s1, s2, t;
    char* str1;
    char* str2;
    char* str3;
    char hash[UTIL_HASHSIZE];
    char random[1024];
    struct util_cert cert1;
    struct util_cert cert2;
    struct util_cert cert3;
    STACK_OF(X509) *encerts = NULL;

    //MSG("Unit testing - StaticTestsuite1()\r\n");

    MSG("Testing - Node Distance");
    util_random(UTIL_HASHSIZE, g_selfid);
    for (t = 0; t < 31; t++)
    {
        unsigned int d;

        memcpy(hash, g_selfid, UTIL_HASHSIZE);
        d = ntohl(((unsigned int*)hash)[0]);
        d = (d ^ (1 << t));
        ((unsigned int*)hash)[0] = ntohl(d);

        l = ctrl_Distance(hash);
        if (t % 2 == 0) MSG(".");
    }
    MSG("Done.\r\n");

    // Packet crypto
    MSG("Testing - UDP packet AES-256 crypto");
    util_startChronometer();
    for (t = 1; t < 800; t++)
    {
        char RemoteNode[32];
        char key[36];
        char *data, *coded, *data2;
        int len, len2;

        // Setup Node1
        g_SessionRandomId = 55;
        g_nextiv = 66;
        memset(g_SessionRandom, 0x67, UTIL_HASHSIZE);
        memset(g_selfid, 0x55, UTIL_HASHSIZE);
        memset(RemoteNode, 0x44, UTIL_HASHSIZE);

        // Compute Node2 key given by Node1
        util_nodesessionkey(RemoteNode, key);

        // Setup Node2
        g_SessionRandomId = 555;
        g_nextiv = 666;
        memset(g_SessionRandom, 0x61, UTIL_HASHSIZE);
        memset(g_selfid, 0x44, UTIL_HASHSIZE);
        memset(RemoteNode, 0x55, UTIL_HASHSIZE);

        // Encrypt some data from Node2 to Node1
        if ((data = malloc(t*10)) == NULL) ILIBCRITICALEXIT(254);
        memset(data, 0x11, t*10);
        len = util_cipher(key, RemoteNode, data, t*10, &coded, 0);
        if (len == 0) MSG("FAILED! util_cipher");

        // Setup Node1
        g_SessionRandomId = 55;
        g_nextiv = 66;
        memset(g_SessionRandom, 0x67, UTIL_HASHSIZE);
        memset(g_selfid, 0x55, UTIL_HASHSIZE);
        memset(RemoteNode, 0x44, UTIL_HASHSIZE);

        // Decrypt data from Node2 on Node1
        len2 = util_decipher(coded, len, &data2, NULL);

        // Check the result
        if (len2 == 0) MSG("FAILED! util_decipher");
        if (len2 != t*10) MSG("FAILED! Length Check");
        if (data2 != NULL)
        {
            if (memcmp(data, data2, t*10) != 0) MSG("FAILED! Data Check");
            free(data2);
        }

        free(data);
        free(coded);

        if (t % 40 == 0) MSG(".");
    }
    MSG2("Done (%ld ms).\r\n", util_readChronometer());

    MSG("Testing - HEX to INT Conversion");
    util_startChronometer();
    for (t = 1; t < 200000; t++)
    {
        s1 = util_hexToint("FEFE", 4);
        if (t % 10000 == 0) MSG(".");
    }
    MSG2("Done (%ld ms).\r\n", util_readChronometer());

    /*
    // Random Compression Testing
    MSG("Testing - String to HEX Conversion");
    util_startChronometer();
    for (t = 1;t < 100;t++)
    {
    	l = t * 10;
    	if ((str1 = malloc(l)) == NULL) ILIBCRITICALEXIT(254);
    	if ((str2 = malloc((l * 2) + 2)) == NULL) ILIBCRITICALEXIT(254);
    	util_random(l, str1);
    	util_tohex(str1, l, str2);
    	util_free(str2);
    	util_free(str1);
        if (t % 10 == 0) MSG(".");
    }
    MSG2("Done (%ld ms).\r\n", util_readChronometer());

    // Random Compression Testing
    MSG("Testing - Random Compression");
    util_startChronometer();
    for (t = 1;t < 200;t++)
    {
    	l = t * 10;
    	if ((str1 = malloc(l)) == NULL) ILIBCRITICALEXIT(254);
    	util_random(l, str1);
    	str2 = NULL;
    	str3 = NULL;
    	s2 = util_compress(str1, l, &str2, 0);
    	if (str2 != NULL)
    	{
    		s1 = util_decompress(str2, s2, &str3, 0);
    		if (str3 != NULL)
    		{
    			if (s1 != l) MSG("ERROR - Length Error.");
    			if (s2 > l + 4) MSG("ERROR - Bad compression.");
    			if (memcmp(str1, str3, l) != 0) MSG("ERROR - Compression error.");
    			util_free(str3);
    		} else MSG("ERROR - Failed decompression.");
    		util_free(str2);
    	} else MSG("ERROR - Failed compression.");
    	util_free(str1);
        if (t % 10 == 0) MSG(".");
    }
    MSG2("Done (%ld ms).\r\n", util_readChronometer());

    // Easy Compression Testing
    MSG("Testing - Easy Compression");
    util_startChronometer();
    for (t = 1;t < 200;t++)
    {
    	l = t * 10;
    	if ((str1 = malloc(l)) == NULL) ILIBCRITICALEXIT(254);
    	memset(str1, 'a', l);
    	str2 = NULL;
    	str3 = NULL;
    	s2 = util_compress(str1, l, &str2, 0);
    	if (str2 != NULL)
    	{
    		s1 = util_decompress(str2, s2, &str3, 0);
    		if (str3 != NULL)
    		{
    			if (s1 != l) MSG("ERROR - Length Error.");
    			if (s2 > l + 4) MSG("ERROR - Bad compression.");
    			if (memcmp(str1, str3, l) != 0) MSG("ERROR - Compression error.");
    			util_free(str3);
    		} else MSG("ERROR - Failed decompression.");
    		util_free(str2);
    	} else MSG("ERROR - Failed compression.");
    	util_free(str1);
        if (t % 10 == 0) MSG(".");
    }
    MSG2("Done (%ld ms).\r\n", util_readChronometer());

    // Random Compression with header testing
    MSG("Testing - Random Compression with header");
    util_startChronometer();
    for (t=40;t<200;t++)
    {
    	l = (t * 10);
    	if ((str1 = malloc(l + 8)) == NULL) ILIBCRITICALEXIT(254);
    	memset(str1, 'A', 8);
    	util_random(l, str1 + 8);
    	s2 = util_compress(str1, l, &str2, 8);
    	if (str2 != NULL)
    	{
    		s1 = util_decompress(str2, s2, &str3, 8);
    		if (str3 != NULL)
    		{
    			if (s1 != l) MSG("ERROR - Length Error.");
    			if (s2 > l + 4) MSG("ERROR - Bad compression.");
    			if (memcmp(str1, str3, l) != 0) MSG("ERROR - Compression error.");
    			util_free(str3);
    		} else MSG("ERROR - Failed decompression.");
    		util_free(str2);
    	} else MSG("ERROR - Failed compression.");
    	util_free(str1);
        if (t % 10 == 0) MSG(".");
    }
    MSG2("Done (%ld ms).\r\n", util_readChronometer());

    // Easy Compression with header testing
    MSG("Testing - Easy Compression with header");
    util_startChronometer();
    for (t=40;t<200;t++)
    {
    	l = (t * 10);
    	if ((str1 = malloc(l + 8)) == NULL) ILIBCRITICALEXIT(254);
    	memset(str1, 'A', 8);
    	memset(str1 + 8, 'B', l);
    	s2 = util_compress(str1, l, &str2, 8);
    	if (str2 != NULL)
    	{
    		s1 = util_decompress(str2, s2, &str3, 8);
    		if (str3 != NULL)
    		{
    			if (s1 != l) MSG("ERROR - Length Error.");
    			if (s2 > l + 4) MSG("ERROR - Bad compression.");
    			if (memcmp(str1, str3, l) != 0) MSG("ERROR - Compression error.");
    			util_free(str3);
    		} else MSG("ERROR - Failed decompression.");
    		util_free(str2);
    	} else MSG("ERROR - Failed compression.");
    	util_free(str1);
        if (t % 10 == 0) MSG(".");
    }
    MSG2("Done (%ld ms).\r\n", util_readChronometer());
    */

    // SHA256 Hashing Test
    MSG("Testing - SHA256 Testing");
    util_startChronometer();
    for (t=1; t<1000; t++)
    {
        l = t * 10;
        if ((str1 = malloc(l)) == NULL) ILIBCRITICALEXIT(254);
        util_random(l, str1);
        util_sha256(str1, l, hash);
        util_free(str1);
        if (t % 50 == 0) MSG(".");
    }
    MSG2("Done (%ld ms).\r\n", util_readChronometer());

    // SHA256 file hash
    MSG("Testing - SHA256 File Hash");
    util_startChronometer();
    for (t=1; t<200; t++)
    {
        util_sha256file(exename, hash);
        if (t % 10 == 0) MSG(".");
    }
    MSG2("Done (%ld ms).\r\n", util_readChronometer());

    // Random string generation
    MSG("Testing - Random numbers");
    util_startChronometer();
    for (t=1; t<200; t++)
    {
        util_random(1024, random);
        if (t % 10 == 0) MSG(".");
    }
    MSG2("Done (%ld ms).\r\n", util_readChronometer());

    // Certificate Creation
    MSG("Testing - 1024 bit Root RSA Certificate Creation.");
    util_startChronometer();
    for (t=1; t<10; t++)
    {
        l = util_mkCert(NULL, &cert1, 1024, 10000, "test", CERTIFICATE_ROOT);
        util_freecert(&cert1);
        MSG(".");
    }
    MSG2("Done (%ld ms).\r\n", util_readChronometer());

    // Certificate Creation
    MSG("Testing - 2048 bit Root RSA Certificate Creation.");
    util_startChronometer();
    for (t=1; t<3; t++)
    {
        l = util_mkCert(NULL, &cert1, 2048, 10000, "test", CERTIFICATE_ROOT);
        util_freecert(&cert1);
        MSG(".");
    }
    MSG2("Done (%ld ms).\r\n", util_readChronometer());

    // 1024bit RSA Sign & Verify Test
    MSG("Testing - RSA 1024 bit Sign & Verify");
    l = util_mkCert(NULL, &cert1, 1024, 10000, "test", CERTIFICATE_ROOT);
    util_startChronometer();
    for (t=1; t<50; t++)
    {
        l = (t * 10) + 32; // We need to reserve 32 bytes at start for signing hash
        if ((str1 = malloc(l)) == NULL) ILIBCRITICALEXIT(254);
        util_random(l, str1);
        s1 = util_sign(cert1, str1, l, &str2);
        if (s1 == 0) MSG("\r\nERROR: Empty signature.\r\n");
        s2 = util_verify(str2, s1, &cert2, &str3);
        if (s2 != l) {
            MSG("ERROR - PKCS#7 data length error.");
        }
        else if (memcmp(str1, str3, l) != 0) MSG("ERROR - PKCS#7 data error.");
        util_freecert(&cert2);
        util_free(str1);
        util_free(str2);
        util_free(str3);
        if (t % 10 == 0) MSG(".");
    }
    MSG2("Done (%ld ms).\r\n", util_readChronometer());
    util_freecert(&cert1);

    // 2048bit RSA Sign & Verify Test
    MSG("Testing - RSA 2048 bit Sign & Verify");
    l = util_mkCert(NULL, &cert1, 2048, 10000, "test", CERTIFICATE_ROOT);
    util_startChronometer();
    for (t=1; t<10; t++)
    {
        l = (t * 10) + 32; // We need to reserve 32 bytes at start for signing hash
        if ((str1 = malloc(l)) == NULL) ILIBCRITICALEXIT(254);
        util_random(l, str1);
        s1 = util_sign(cert1, str1, l, &str2);
        if (s1 == 0) MSG("\r\nERROR: Empty signature.\r\n");
        s2 = util_verify(str2, s1, &cert2, &str3);
        if (s2 != l) {
            MSG("ERROR - PKCS#7 data length error.");
        }
        else if (memcmp(str1, str3, l) != 0) MSG("ERROR - PKCS#7 data error.");
        util_freecert(&cert2);
        util_free(str1);
        util_free(str2);
        util_free(str3);
        if (t % 2 == 0) MSG(".");
    }
    MSG2("Done (%ld ms).\r\n", util_readChronometer());
    util_freecert(&cert1);

    // 1024bit RSA Encryption and Decryption Test
    MSG("Testing - RSA 1024 bit Encryption and Decryption");
    l = util_mkCert(NULL, &cert1, 1024, 10000, NULL, CERTIFICATE_ROOT);
    util_startChronometer();
    for (t=10; t<100; t++)
    {
        l = t * 10;
        if ((str1 = malloc(l)) == NULL) ILIBCRITICALEXIT(254);
        util_random(l, str1);
        s1 = util_encrypt(cert1, str1, l, &str2);
        if (s1 == 0) MSG("\r\nERROR: Empty signature.\r\n");
        s2 = util_decrypt(str2, s1, cert1, &str3);
        if (s2 != l || str3 == NULL) {
            MSG("ERROR - PKCS#7 data length error.");
        }
        else if (memcmp(str1, str3, l) != 0) MSG("ERROR - PKCS#7 data error.");
        util_free(str1);
        util_free(str2);
        util_free(str3);
        if (t % 10 == 0) MSG(".");
    }
    MSG2("Done (%ld ms).\r\n", util_readChronometer());
    util_freecert(&cert1);

    // 1024bit RSA Multi-Encryption and Decryption Test
    MSG("Testing - RSA 1024 bit Multi-Encryption and Decryption");
    l = util_mkCert(NULL, &cert1, 1024, 10000, NULL, CERTIFICATE_ROOT);
    l = util_mkCert(NULL, &cert2, 1024, 10000, NULL, CERTIFICATE_ROOT);
    l = util_mkCert(NULL, &cert3, 1024, 10000, NULL, CERTIFICATE_ROOT);
    encerts = sk_X509_new_null();
    sk_X509_push(encerts, cert1.x509);
    sk_X509_push(encerts, cert2.x509);
    sk_X509_push(encerts, cert3.x509);
    util_startChronometer();
    for (t=10; t<100; t++)
    {
        l = t * 10;
        if ((str1 = malloc(l)) == NULL) ILIBCRITICALEXIT(254);
        util_random(l, str1);
        s1 = util_encrypt2(encerts, str1, l, &str2);
        if (s1 == 0) MSG("\r\nERROR: Empty signature.\r\n");

        // Cert 1 decrypt
        s2 = util_decrypt(str2, s1, cert1, &str3);
        if (s2 != l || str3 == NULL) {
            MSG("ERROR - PKCS#7 data length error.");
        }
        else if (memcmp(str1, str3, l) != 0) MSG("ERROR - PKCS#7 data error.");
        util_free(str3);

        // Cert 2 decrypt
        s2 = util_decrypt(str2, s1, cert2, &str3);
        if (s2 != l || str3 == NULL) {
            MSG("ERROR - PKCS#7 data length error.");
        }
        else if (memcmp(str1, str3, l) != 0) MSG("ERROR - PKCS#7 data error.");
        util_free(str3);

        // Cert 3 decrypt
        s2 = util_decrypt(str2, s1, cert3, &str3);
        if (s2 != l || str3 == NULL) {
            MSG("ERROR - PKCS#7 data length error.");
        }
        else if (memcmp(str1, str3, l) != 0) MSG("ERROR - PKCS#7 data error.");
        util_free(str3);

        util_free(str1);
        util_free(str2);
        if (t % 10 == 0) MSG(".");
    }
    MSG2("Done (%ld ms).\r\n", util_readChronometer());
    sk_X509_free(encerts);
    util_freecert(&cert1);
    util_freecert(&cert2);
    util_freecert(&cert3);

    //MSG("Testing completed.\r\n");
    return 0;
}


// Tests the realiability of crypto checks, this suite is difficult to pass, OpenSSL currently fails it.
int ut_StaticTestsuite2()
{
    int l,s1,s2,t;
    char* str1;
    char* str2;
    char* str3;
    struct util_cert cert1;
    struct util_cert cert2;

    //MSG("Unit testing - StaticTestsuite2()\r\n");

    // 1024bit RSA Sign & Verify Curruption Test
    MSG("Testing - RSA 1024 bit Sign & Verify Curruption");
    util_mkCert(NULL, &cert1, 1024, 10000, "test", CERTIFICATE_ROOT);
    if ((str1 = malloc(500)) == NULL) return 1;
    memset(str1,'z',500);
    s1 = util_sign(cert1, str1, 500, &str2); // Sign it
    util_free(str1);
    str1 = str2;
    if ((str2 = malloc(s1)) == NULL) return 1;
    l = 0;
    for (t=0; t<s1; t++) // 1198 causes a leak
    {
        if (t % 80 == 0) MSG(".");
        memcpy(str2, str1, s1);
        str2[t] = str2[t] + 1; // Corrupt it (rand() % s1)

        // Verify it
        s2 = util_verify(str2, s1, &cert2, &str3);
        if (s2 != 0)
        {
            // Everything worked, which is not expected
            l++;
            util_freecert(&cert2);
            util_free(str3);
        }
    }
    MSG2("(%d failed).\r\n", l);
    util_free(str2);
    util_free(str1);
    util_freecert(&cert1);

    //MSG("Testing completed.\r\n");
    return 0;
}

// Tests system information gathering
int ut_StaticTestsuite3()
{
    int t, l, l2;
    char* c;
    char* c2;
    unsigned short includes[] = { 0x01, 0x02, 0x03, 0x00 };
    struct util_cert cert1;
    struct util_cert cert2;
    struct LocalInterfaceStruct* ifs = NULL;
    struct ComputerInformationStruct* cinf = NULL;
    struct MeInformationStruct* info = NULL;
    struct NodeInfoBlock* node = NULL;
    struct NodeInfoBlock* node2 = NULL;

    //MSG("Unit testing - StaticTestsuite3()\r\n");

    MSG("Testing - Getting computer information");
    for (t=1; t<200; t++)
    {
        cinf = info_GetComputerInformation();
        if (cinf == NULL) {
            MSG("ERROR - Unable to generate computer information.\r\n");
            break;
        }
        if (info_CheckComputerInformation(cinf, cinf->structsize) == 0) MSG("ERROR - Bad computer information struct.\r\n");
        if (cinf != NULL) free(cinf);
        if (t % 10 == 0) MSG(".");
    }
    MSG("Done.\r\n");

    MSG("Testing - Getting local network information");
    for (t=1; t<200; t++)
    {
        ifs = info_GetLocalInterfaces();
        if (ifs == NULL) {
            MSG("ERROR - Unable to generate local network information.\r\n");
            break;
        }
        if (info_CheckLocalInterfaces(ifs, ifs->structsize) == 0) MSG("ERROR - Bad local interface information struct.\r\n");
        if (ifs != NULL) free(ifs);
        if (t % 10 == 0) MSG(".");
    }
    MSG("Done.\r\n");

    MSG("Testing - Getting Intel(R) AMT information");
    for (t=1; t<200; t++)
    {
        info = info_GetMeInformation();
        if (info != NULL)
        {
            if (info_CheckMeInformation(info, info->structsize) == 0) MSG("ERROR - Bad Intel(R) AMT info struct.\r\n");
            free(info);
        }
        if (t % 10 == 0) MSG(".");
    }
    MSG("Done.\r\n");

    MSG("Testing - Getting Self Info Block");
    for (t=1; t<200; t++)
    {
        // Create our own block
        node = info_CreateInfoBlock(includes, 0);
        if (node == NULL) {
            MSG("ERROR - Unable to generate Self Info Block.\r\n");
            break;
        }
        // Copy it
        if ((c = malloc(node->rawdatasize)) == NULL) ILIBCRITICALEXIT(254);
        memcpy(c, node->rawdata, node->rawdatasize);
        memset(node->rawdata, 0, node->rawdatasize);
        node2 = info_ParseInfoBlock(c, node->rawdatasize, 0); // This is an inplace parse, no copies.
        // Free everything
        info_FreeInfoBlock(node);
        info_FreeInfoBlock(node2);
        if (t % 10 == 0) MSG(".");
    }
    MSG("Done.\r\n");

    MSG("Testing - Full node block creation and check");
    for (t=1; t<20; t++)
    {
        c = NULL;
        c2 = NULL;
        node2 = NULL;
        l = util_mkCert(NULL, &cert1, 1024, 10000, "test", CERTIFICATE_ROOT);

        // Create our own block
        node = info_CreateInfoBlock(includes, 32);
        if (node == NULL) {
            MSG("ERROR - Unable to generate Self Info Block.\r\n");
            break;
        }
        if (node->rawdatasize < 32 || node->rawdatasize > 5000) MSG("ERROR: bad node generation\r\n");

        // Sign it
        l2 = util_sign(cert1, node->rawdata, node->rawdatasize, &c);

        // Check it
        l = util_verify(c, l2, &cert2, &c2);
        if (l == 0) printf("ERROR: Verify failed - Sign: %d, Verify: %d, Data: %d.\r\n", l2, l, (unsigned int)node->rawdatasize);

        // Parse it
        if (l > 0)
        {
            node2 = info_ParseInfoBlock(c2, l, 32); // This is an inplace parse, no copies.
            if (node2 == NULL) printf("ERROR: Parse failed.\r\n");
        }

        // Check everything
        if (node2 != NULL)
        {
            if (node->rawdatasize != node2->rawdatasize) MSG("ERROR: Bad size\r\n");
            if (memcmp(node->compinfo, node2->compinfo, sizeof(struct ComputerInformationStruct)) != 0) MSG("ERROR: Bad computer info block.\r\n");
            if (node->meinfo != NULL && memcmp(node->compinfo, node2->compinfo, sizeof(struct MeInformationStruct)) != 0) MSG("ERROR: Bad Intel(R) ME block.\r\n");
            if (memcmp(node->rawdata + 32, node2->rawdata + 32, node->rawdatasize - 32) != 0) MSG("ERROR: Bad block\r\n");
            info_FreeInfoBlock(node2);
        }

        // Free everything
        if (c != NULL) free(c);
        info_FreeInfoBlock(node);
        util_freecert(&cert2);
        util_freecert(&cert1);
        if (t % 1 == 0) MSG(".");
    }
    MSG("Done.\r\n");

    //MSG("Testing completed.\r\n");

    return 0;
}

int ut_StaticTestsuite4()
{
    int t;
    unsigned short includes[] = { 0x01, 0x02, 0x03, 0x00 };
    struct NodeInfoBlock* node = NULL;
    struct NodeInfoBlock* node2 = NULL;

    //MSG("Unit testing - StaticTestsuite4()\r\n");

    MSG("Testing - Information block generation");
    for (t=1; t<500; t++)
    {
        node = info_CreateInfoBlock(includes, 64);
        if (node == NULL) {
            MSG("ERROR - Can't generate information block\r\n");
            break;
        }
        //info_PrintInfoBlock(node);
        node2 = info_ParseInfoBlock(node->rawdata, node->rawdatasize, 64); // Inline parse
        //info_PrintInfoBlock(node2);
        info_FreeInfoBlock(node);
        free(node2);
        if (t % 20 == 0) MSG(".");
    }
    MSG("Done.\r\n");

    //MSG("Testing completed.\r\n");
    return 0;
}


// Test node identity challenges
int ut_StaticTestsuite5()
{
    int l1, l2, t;
    //int l3;
    //int counter = 1;
    //char secret[32];
    //char* challenge;
    //char* response;
    //char nodeid[UTIL_HASHSIZE];
    //int counter2;
    //struct util_cert cert1;

    // Setup a private secret
    //util_random(32, secret);

    /*
    MSG("Testing - Node identity challenges");
    util_mkCert(NULL, &cert1, 1024, 20000, "test", CERTIFICATE_ROOT);
    for (t=1;t<500;t++)
    {
    	// Compute the challenge
    	l1 = ctrl_GetNodeChallenge(secret, counter, &challenge);

    	// Compute the response
    	l2 = ctrl_PerformNodeChallenge(cert1, challenge, l1, &response);

    	// Check response
    	l3 = ctrl_CheckNodeChallenge(secret, response, l2, nodeid, &counter2);

    	free(challenge);
    	free(response);
    	if (l3 != 1) MSG("Failed!");
    	if (t % 20 == 0) MSG(".");
    }
    util_freecert(&cert1);
    MSG("Done.\r\n");
    */

    MSG("Testing - Anti-Flooding filter");
    l1 = 0;
    l2 = 0;
    for (t=1; t<500; t++)
    {
        if (util_antiflood(20, 60) != 0) l1++;
        else l2++;
        if (t % 20 == 0) MSG(".");
    }
    if (l1 == 20) {
        MSG("Done.\r\n");
    }
    else {
        MSG("Failed.\r\n");
    }

    return 1;
}


// Generates count number of bogus nodes for testing purposes, storing nodes in the database
void ut_GenerateTestNodes(int count)
{
    unsigned short includes[] = { 0x01, 0x02, 0x03, 0x00 };
    int l, t;
    struct util_cert cert;
    struct NodeInfoBlock* node = NULL;
    char nodeid[UTIL_HASHSIZE];
    int signedblocklen;
    char* signedblock;
    char* signedblock2;
    int serial = 0;

    MSG("Testing - Getting Self Info Block");
    mdb_begin();
    node = info_CreateInfoBlock(includes, (UTIL_HASHSIZE * 2) + 4);
    if (node != NULL)
    {
        for (t=1; t<count; t++)
        {
            // Create a certificate & own block
            l = util_mkCert(NULL, &cert, 1024, 10000, NULL, CERTIFICATE_ROOT);
            util_keyhash(cert, nodeid);

            // Randomize the block information
            serial = rand() % 1000;
            snprintf((char*)(node->compinfo->name), 64, "Test%d", t);
            memcpy((node->rawdata)+ (UTIL_HASHSIZE * 2), &serial, 4);		// Copy the serial number in correct spot.
            memcpy((node->rawdata)+ UTIL_HASHSIZE, nodeid, UTIL_HASHSIZE);	// Copy the NodeID in correct spot.

            // Sign it and add header in front
            signedblocklen = util_sign(cert, node->rawdata, node->rawdatasize, &signedblock);
            signedblock2 = malloc(signedblocklen + 4);
            if (signedblock2 != NULL)
            {
                memcpy(signedblock2 + 4, signedblock, signedblocklen);
                ((unsigned short*)(signedblock2))[0] = 0x01;						// Setup block type
                ((unsigned short*)(signedblock2))[1] = (unsigned short)(signedblocklen + 4);			// Setup block length
                free(signedblock);

                // Add to database
                mdb_blockset(nodeid, serial, signedblock2, signedblocklen + 4);

                // Clean up
                free(signedblock2);
            }
            util_freecert(&cert);

            if (t % 10 == 0) MSG(".");
        }
        info_FreeInfoBlock(node);
    }
    mdb_commit();
    MSG("Done.\r\n");
}


void ut1_ILibAsyncSocket_OnData(ILibAsyncSocket_SocketModule socketModule, char* buffer, int *p_beginPointer, int endPointer, ILibAsyncSocket_OnInterrupt* OnInterrupt, void **user, int *PAUSE)
{
    UNREFERENCED_PARAMETER( socketModule );
    UNREFERENCED_PARAMETER( buffer );
    UNREFERENCED_PARAMETER( p_beginPointer );
    UNREFERENCED_PARAMETER( endPointer );
    UNREFERENCED_PARAMETER( OnInterrupt );
    UNREFERENCED_PARAMETER( user );
    UNREFERENCED_PARAMETER( PAUSE );

    //MSG("ut1_ILibAsyncSocket_OnData.\r\n");
}

void ut1_ILibAsyncSocket_OnConnect(ILibAsyncSocket_SocketModule socketModule, int Connected, void *user)
{
    UNREFERENCED_PARAMETER( socketModule );
    UNREFERENCED_PARAMETER( user );

    //MSG2("ut1_ILibAsyncSocket_OnConnect, Connected=%d.\r\n", Connected);

    // Bad port self connection port
    if (gut_TestNumber >= 0 && gut_TestNumber < 10)
    {
        if (gut_TestNumber == 0) MSG("Testing - Connection to bad port");
        if (Connected != 0) MSG("FAILED!");
        if (gut_TestNumber % 1 == 0) MSG(".");
        if (gut_TestNumber == 9) MSG("Done.\r\n");
        if (gut_TestNumber < 10) ILibAsyncSocket_ConnectTo(gut_AsyncSocket, (struct sockaddr*)&gut_localInterface, (struct sockaddr*)&gut_remoteInterface2, NULL, NULL);
        gut_TestNumber++;
    }

    // Connection to self server
    if (gut_TestNumber >= 10 && gut_TestNumber < 30)
    {
        if (gut_TestNumber == 10) MSG("Testing - Connection to self server");
        if (gut_TestNumber > 10 && Connected != -1) {
            MSG("FAILED!");
        }
        if (gut_TestNumber % 1 == 0) MSG(".");
        if (gut_TestNumber == 29) MSG("Done.\r\n");
        if (gut_TestNumber < 30) ILibAsyncSocket_ConnectTo(gut_AsyncSocket, (struct sockaddr*)&gut_localInterface, (struct sockaddr*)&gut_serverInterface, NULL, NULL);
        gut_TestNumber++;
    }

    // Exit testing
    if (gut_TestNumber == 30) ILibStopChain(gut_Chain);
}

void ut1_ILibAsyncSocket_OnDisconnect(ILibAsyncSocket_SocketModule socketModule, void *user)
{
    UNREFERENCED_PARAMETER( socketModule );
    UNREFERENCED_PARAMETER( user );

    //MSG("ut1_ILibAsyncSocket_OnDisconnect.\r\n");
}

void ut1_ILibAsyncSocket_OnSendOK(ILibAsyncSocket_SocketModule socketModule, void *user)
{
    UNREFERENCED_PARAMETER( socketModule );
    UNREFERENCED_PARAMETER( user );

    //MSG("ut1_ILibAsyncSocket_OnSendOK.\r\n");
}

// Called when a master timer is pending and the stack is exitting
void ut1_TimerDestroyed(void *data)
{
    UNREFERENCED_PARAMETER( data );

    //MSG("ut1_TimerDestroyed.\r\n");
}

// Called then the master timer is triggered
void ut1_TimerTriggered(void *data)
{
    UNREFERENCED_PARAMETER( data );

    //MSG2("ut1_TimerTriggered. Count = %d\r\n", (int)ILibLifeTime_Count(gut_Timer));
}

void ut1_server_OnReceive(ILibAsyncServerSocket_ServerModule AsyncServerSocketModule, ILibAsyncServerSocket_ConnectionToken ConnectionToken, char* buffer, int *p_beginPointer, int endPointer, ILibAsyncServerSocket_OnInterrupt *OnInterrupt,void **user, int *PAUSE)
{
    UNREFERENCED_PARAMETER( AsyncServerSocketModule );
    UNREFERENCED_PARAMETER( ConnectionToken );
    UNREFERENCED_PARAMETER( buffer );
    UNREFERENCED_PARAMETER( p_beginPointer );
    UNREFERENCED_PARAMETER( endPointer );
    UNREFERENCED_PARAMETER( OnInterrupt );
    UNREFERENCED_PARAMETER( user );
    UNREFERENCED_PARAMETER( PAUSE );

    //MSG("ut1_server_OnReceive.\r\n");
}

void ut1_server_OnConnect(ILibAsyncServerSocket_ServerModule AsyncServerSocketModule, ILibAsyncServerSocket_ConnectionToken ConnectionToken, void **user)
{
    UNREFERENCED_PARAMETER( AsyncServerSocketModule );
    UNREFERENCED_PARAMETER( ConnectionToken );
    UNREFERENCED_PARAMETER( user );

    //MSG("ut1_server_OnConnect.\r\n");
}

void ut1_server_OnDisconnect(ILibAsyncServerSocket_ServerModule AsyncServerSocketModule, ILibAsyncServerSocket_ConnectionToken ConnectionToken, void *user)
{
    UNREFERENCED_PARAMETER( AsyncServerSocketModule );
    UNREFERENCED_PARAMETER( ConnectionToken );
    UNREFERENCED_PARAMETER( user );

    //MSG("ut1_server_OnDisconnect.\r\n");
}

int ut_DynamicTestsuite1()
{
    unsigned short port;

    srand((unsigned int)time(NULL));
    port = 5555 + (rand() % 3000);

    MSG2("Listening on port %d\r\n", port + 2);

    // Setup Chain. This will also setup Winsock is applicable
    //! \note (modified) Setup Chain. This will also setup Winsock if(?) applicable
    Chain = gut_Chain = ILibCreateChain();
    
    gut_Timer = ILibGetBaseTimer(gut_Chain);

    // IPv6 detection
    gut_IPv6Support = ILibDetectIPv6Support();

    // Cleanup all addresses
    memset(&gut_localInterface, 0, sizeof(struct sockaddr_in6));
    memset(&gut_remoteInterface2, 0, sizeof(struct sockaddr_in6));
    memset(&gut_serverInterface, 0, sizeof(struct sockaddr_in6));

    // Setup addresses
    if (gut_IPv6Support)
    {
        // IPv6 support
        gut_localInterface.sin6_family = AF_INET6;

        gut_remoteInterface2.sin6_family = AF_INET6;
        gut_remoteInterface2.sin6_port = htons(port + 1);
        ILibInet_pton(AF_INET6, "::1", &(gut_remoteInterface2.sin6_addr));

        gut_serverInterface.sin6_family = AF_INET6;
        gut_serverInterface.sin6_port = htons(port + 2);
        ILibInet_pton(AF_INET6, "::1", &(gut_serverInterface.sin6_addr));
    }
    else
    {
        // IPv4 only
        gut_localInterface.sin6_family = AF_INET;

        gut_remoteInterface2.sin6_family = AF_INET;
        ((struct sockaddr_in*)&gut_remoteInterface2)->sin_port = htons(port + 1);
        ILibInet_pton(AF_INET, "127.0.0.1", &((struct sockaddr_in*)&gut_remoteInterface2)->sin_addr);

        gut_serverInterface.sin6_family = AF_INET;
        ((struct sockaddr_in*)&gut_serverInterface)->sin_port = htons(port + 2);
        ILibInet_pton(AF_INET, "127.0.0.1", &((struct sockaddr_in*)&gut_serverInterface)->sin_addr);
    }

    gut_AsyncSocket = ILibCreateAsyncSocketModule(gut_Chain, 3000, &ut1_ILibAsyncSocket_OnData, &ut1_ILibAsyncSocket_OnConnect, &ut1_ILibAsyncSocket_OnDisconnect, &ut1_ILibAsyncSocket_OnSendOK);
    gut_AsyncServer = ILibCreateAsyncServerSocketModule(gut_Chain, 5, port + 2, 3000, 0, &ut1_server_OnConnect, &ut1_server_OnDisconnect, &ut1_server_OnReceive, NULL, NULL);
    //ILibLifeTime_Add(gut_Timer, NULL, 1, ut1_TimerTriggered, &ut1_TimerDestroyed);
    if (gut_AsyncSocket == NULL || gut_AsyncServer == NULL) return 1;

    // Start the first test.
    ILibAsyncSocket_ConnectTo(gut_AsyncSocket, (struct sockaddr*)&gut_localInterface, (struct sockaddr*)&gut_remoteInterface2, NULL, NULL);
    ILibStartChain(gut_Chain);

    return 0;
}

