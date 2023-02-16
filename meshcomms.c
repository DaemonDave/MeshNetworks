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
#include "meshcomms.h"
#endif


#define AUTHORIZATION_FIELDDATA_TEMPLATE "Digest username=\"%s\", realm=\"%s\", nonce=\"%s\", uri=\"%s\", response=\"%s\", qop=%s, nc=%08x, cnonce=\"%s\""




// Starts dropping packets is rate is too high
long util_af_time = 0;
long util_af_count = 0;

//! \fn CreateRSA creates memory and fills it for use elsewhere
RSA_t * CreateRSA()
{
/*
	RSA_t * ret = malloc ( sizeof( RSA_t ));
	ret->primes = 3;
	ret->bits = 4096;
	ret->pctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
	EVP_PKEY_keygen_init(ret->pctx);
	ret->params[0] = OSSL_PARAM_construct_uint("bits", &(ret->bits));
	ret->params[1] = OSSL_PARAM_construct_uint("primes", &(ret->primes));
	ret->params[2] = OSSL_PARAM_construct_end();
	EVP_PKEY_CTX_set_params(pctx, &(ret->params));
	EVP_PKEY_generate(pctx, &(ret->pkey));
	EVP_PKEY_print_private(bio_out, ret->pkey, 0, NULL);
	EVP_PKEY_CTX_free(ret->pctx);	
	
	return ret;
*/
}



int util_antiflood(int rate, int interval)
{
/*
    long seconds;
    struct timeval clock;
    gettimeofday(&clock,NULL);
    seconds = clock.tv_sec;

    if ((seconds - util_af_time) > interval)
    {
        util_af_time = seconds;
        util_af_count = 0;
        return 1;
    }
    util_af_count++;
    return util_af_count < rate;
*/
}


// Extract data from an HTTP Digest authentication request
int util_ExtractWwwAuthenticate(char *wwwAuthenticate, void *request)
{
/*
    struct HttpRequestBlock *hostData = (struct HttpRequestBlock *)request;
    struct parser_result *r = ILibParseString(wwwAuthenticate,0,(int)strlen(wwwAuthenticate), ", ", 2);
    if (hostData == NULL) return -1;

    if (r != NULL)
    {
        struct parser_result *r1;
        struct parser_result_field *prf = NULL;

        char *keyValue = NULL;
        char *key = NULL;

        prf = r->FirstResult;
        while(prf!=NULL)
        {
            keyValue = prf->data;

            r1 = ILibParseString(keyValue,0,prf->datalength,"=\"",2);

            if (r1->NumResults == 1)
            {
                ILibDestructParserResults(r1);
                r1 = ILibParseString(keyValue,0,prf->datalength,"=",1);
            }

            key = r1->FirstResult->data;

            if(strncasecmp(key, "Digest realm", (int)strlen("Digest realm")) == 0)
            {
                hostData->realm = malloc(r1->LastResult->datalength);
                if (hostData->realm == NULL) goto error;
                strncpy(hostData->realm, r1->LastResult->data, r1->LastResult->datalength);
                hostData->realm[r1->LastResult->datalength - 1] = '\0';
            }
            else if(strncasecmp(key, "nonce", (int)strlen("nonce")) == 0)
            {
                hostData->nonce = malloc(r1->LastResult->datalength);
                if (hostData->nonce == NULL) goto error;
                strncpy(hostData->nonce, r1->LastResult->data, r1->LastResult->datalength);
                hostData->nonce[r1->LastResult->datalength - 1] = '\0';
            }
            else if(strncasecmp(key, "qop", (int)strlen("qop")) == 0)
            {
                hostData->qop = malloc(r1->LastResult->datalength + 1);
                if (hostData->qop == NULL) goto error;
                strncpy(hostData->qop, r1->LastResult->data, r1->LastResult->datalength);
                if (hostData->qop[r1->LastResult->datalength - 1] == '\"')
                {
                    hostData->qop[r1->LastResult->datalength - 1] = '\0';
                }
                else
                {
                    hostData->qop[r1->LastResult->datalength] = '\0';
                }
            }

            ILibDestructParserResults(r1);
            prf = prf->NextResult;
        }
        ILibDestructParserResults(r);
    }

    return 0;

error:
    if (hostData->realm != NULL) 
    {
        free(hostData->realm);
        hostData->realm = NULL;
    }
    if (hostData->nonce != NULL) 
    {
        free(hostData->nonce);
        hostData->nonce = NULL;
    }
    if (hostData->qop != NULL) 
    {
        free(hostData->qop);
        hostData->qop = NULL;
    }

    return -1;
*/
}


// Convert a private key into a usage specific key
void util_genusagekey(char* inkey, char* outkey, char usage)
{
/*
    SHA256_CTX c;
    SHA256_Init(&c);
    SHA256_Update(&c, &usage, 1);
    SHA256_Update(&c, inkey, 32);
    SHA256_Update(&c, &usage, 1);
    SHA256_Final((unsigned char*)outkey, &c);
*/
}


void util_GenerateAuthorizationHeader(void *request, char *requestType, char *uri, char *authorization, char* cnonce)
{
 /*
    char a1[MAX_TOKEN_SIZE];
    char a1Digest[MAX_TOKEN_SIZE];
    char a2[MAX_TOKEN_SIZE];
    char a2Digest[MAX_TOKEN_SIZE];
    char a3[MAX_TOKEN_SIZE];
    char a3Digest[MAX_TOKEN_SIZE];
    int tempLen = 0;
    struct HttpRequestBlock *mappingData = (struct HttpRequestBlock *)request;

    // username:realm:password
    tempLen = snprintf(a1, MAX_TOKEN_SIZE, "%s:%s:%s", mappingData->username, mappingData->realm, mappingData->password);
    util_md5hex(a1, tempLen, a1Digest);

    // GET:uri
    tempLen = snprintf(a2, MAX_TOKEN_SIZE, "%s:%s", requestType, uri);
    util_md5hex(a2, tempLen, a2Digest);

    // a1Digest:nonce:nc:cnonce:qop:a2Digest
    tempLen = snprintf(a3, MAX_TOKEN_SIZE, "%s:%s:%08x:%s:%s:%s", a1Digest, mappingData->nonce, ++mappingData->nc, cnonce, mappingData->qop, a2Digest);
    util_md5hex(a3, tempLen, a3Digest);

    snprintf(authorization, 1024, AUTHORIZATION_FIELDDATA_TEMPLATE, mappingData->username, mappingData->realm, mappingData->nonce, uri, a3Digest, mappingData->qop, mappingData->nc, cnonce);
*/
}



// Get the private session key for a given nodeid.
// Nodeid is 32 bytes, key must point to 36 bytes of free space.
void util_nodesessionkey(char* nodeid, char* key)
{
/*
    SHA256_CTX c;
    SHA256_Init(&c);
    SHA256_Update(&c, nodeid, 32);
    SHA256_Update(&c, g_SessionRandom, 32);
    SHA256_Final((unsigned char*)(key + 4), &c);
    ((unsigned int*)key)[0] = g_SessionRandomId; // Here, endianness does not matter, leave as-is for speed.
*/
}


void util_freecert(struct util_cert* cert)
{
/*
    if (cert->x509 != NULL) X509_free(cert->x509);
    if (cert->pkey != NULL) EVP_PKEY_free(cert->pkey);
    cert->x509 = NULL;
    cert->pkey = NULL;
 */   
}

int util_to_cer(struct util_cert cert, char** data)
{
/*
    *data = NULL;
    return i2d_X509(cert.x509, (unsigned char**)data);
*/
}

int util_from_cer(char* data, int datalen, struct util_cert* cert)
{
/*
    cert->x509 = NULL;
    cert->pkey = NULL;
    cert->x509 = d2i_X509(&(cert->x509), (const unsigned char**)&data, datalen);
    cert->pkey = NULL;
    return ((cert->x509) == NULL);
*/
}

int util_to_p12(struct util_cert cert, char *password, char** data)
{
/*
    PKCS12 *p12;
    int len;
    p12 = PKCS12_create(password, "Certificate", cert.pkey, cert.x509, NULL, 0,0,0,0,0);
    *data = NULL;
    len = i2d_PKCS12(p12, (unsigned char**)data);
    PKCS12_free(p12);
    return len;
*/
}

int util_from_p12(char* data, int datalen, char* password, struct util_cert* cert)
{
 /*   
    int r = 0;
    PKCS12 *p12 = NULL;
    if (data == NULL || datalen ==0) return 0;
    cert->x509 = NULL;
    cert->pkey = NULL;
    p12 = d2i_PKCS12(&p12, (const unsigned char**)&data, datalen);
    r = PKCS12_parse(p12, password, &(cert->pkey), &(cert->x509), NULL);
    PKCS12_free(p12);
    return r;
  */
}

// Add extension using V3 code: we can set the config file as NULL because we wont reference any other sections.
int util_add_ext(X509 *cert, int nid, char *value)
{
/*
    X509_EXTENSION *ex;
    X509V3_CTX ctx;
    // This sets the 'context' of the extensions. No configuration database
    X509V3_set_ctx_nodb(&ctx);
    // Issuer and subject certs: both the target since it is self signed, no request and no CRL
    X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);
    ex = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);
    if (!ex) return 0;

    X509_add_ext(cert,ex,-1);
    X509_EXTENSION_free(ex);
    return 1;
*/
}

void util_printcert(struct util_cert cert)
{
/*
    if (cert.x509 == NULL) return;
    X509_print_fp(stdout,cert.x509);
*/
}

void util_printcert_pk(struct util_cert cert)
{
/*
    if (cert.pkey == NULL) return;
    RSA_print_fp(stdout,cert.pkey->pkey.rsa,0);
*/
}

void util_sendcert(struct ILibWebServer_Session *sender, struct util_cert cert)
{
/*
    int l = 0;
    BIO *out = NULL;
    char *data;
    if (cert.x509 == NULL) return;
    out = BIO_new(BIO_s_mem());
    l = X509_print(out,cert.x509);
    l = BIO_get_mem_data(out, &data);
    ILibWebServer_StreamBody(sender, data, l, ILibAsyncSocket_MemoryOwnership_USER,0);
    BIO_free(out);
*/
}


// Creates a X509 certificate, if rootcert is NULL this creates a root (self-signed) certificate.
// Is the name parameter is NULL, the hex value of the hash of the public key will be the subject name.
int util_mkCert(struct util_cert *rootcert, struct util_cert* cert, int bits, int days, char* name, enum CERTIFICATE_TYPES certtype)
{
/*
    X509 *x = NULL;
    X509_EXTENSION *ex = NULL;
    EVP_PKEY *pk = NULL;
    RSA *rsa = NULL;
    X509_NAME *cname=NULL;
    X509 **x509p = NULL;
    EVP_PKEY **pkeyp = NULL;
    char hash[UTIL_HASHSIZE];
    char serial[8];
    char nameStr[(UTIL_HASHSIZE * 2) + 2];

    CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);

    if ((pkeyp == NULL) || (*pkeyp == NULL))
    {
    	if ((pk=EVP_PKEY_new()) == NULL)
    	{
    		abort();
    		return(0);
    	}
    }
    else
    	pk = *pkeyp;

    if ((x509p == NULL) || (*x509p == NULL))
    {
    	if ((x=X509_new()) == NULL) goto err;
    }
    else x = *x509p;

    rsa=RSA_generate_key(bits, RSA_F4, NULL, NULL);
    if (!EVP_PKEY_assign_RSA(pk, rsa))
    {
    	abort();
    	goto err;
    }
    rsa = NULL;

    util_randomtext(8, serial);
    X509_set_version(x,2);
    ASN1_STRING_set(X509_get_serialNumber(x), serial, 8);
    X509_gmtime_adj(X509_get_notBefore(x),0);
    X509_gmtime_adj(X509_get_notAfter(x),(long)60*60*24*days);
    X509_set_pubkey(x,pk);

    // Set the subject name
    cname = X509_get_subject_name(x);

    if (name == NULL)
    {
    	// Computer the hash of the public key
    	util_sha256((char*)x->cert_info->key->public_key->data, x->cert_info->key->public_key->length, hash);
    	util_tohex(hash, UTIL_HASHSIZE, nameStr);
    	X509_NAME_add_entry_by_txt(cname,"CN", MBSTRING_ASC, (unsigned char*)nameStr, -1, -1, 0);
    }
    else
    {
    	// This function creates and adds the entry, working out the correct string type and performing checks on its length. Normally we'd check the return value for errors...
    	X509_NAME_add_entry_by_txt(cname,"CN", MBSTRING_ASC, (unsigned char*)name, -1, -1, 0);
    }

    if (rootcert == NULL)
    {
    	// Its self signed so set the issuer name to be the same as the subject.
    	X509_set_issuer_name(x,cname);

    	// Add various extensions: standard extensions
    	util_add_ext(x, NID_basic_constraints, "critical,CA:TRUE");
    	util_add_ext(x, NID_key_usage, "critical,keyCertSign,cRLSign");

    	util_add_ext(x, NID_subject_key_identifier, "hash");
    	//util_add_ext(x, NID_netscape_cert_type, "sslCA");
    	//util_add_ext(x, NID_netscape_comment, "example comment extension");

    	if (!X509_sign(x,pk,EVP_sha256())) goto err;
    }
    else
    {
    	// This is a sub-certificate
    	cname=X509_get_subject_name(rootcert->x509);
    	X509_set_issuer_name(x,cname);

    	// Add usual cert stuff
    	ex = X509V3_EXT_conf_nid(NULL, NULL, NID_key_usage, "digitalSignature, keyEncipherment, keyAgreement");
    	X509_add_ext(x, ex, -1);
    	X509_EXTENSION_free(ex);

    	// Add usages: TLS server, TLS client, Intel(R) AMT Console
    	//ex = X509V3_EXT_conf_nid(NULL, NULL, NID_ext_key_usage, "TLS Web Server Authentication, TLS Web Client Authentication, 2.16.840.1.113741.1.2.1, 2.16.840.1.113741.1.2.2");
    	if (certtype == CERTIFICATE_TLS_SERVER)
    	{
    		// TLS server
    		ex = X509V3_EXT_conf_nid(NULL, NULL, NID_ext_key_usage, "TLS Web Server Authentication");
    		X509_add_ext(x, ex, -1);
    		X509_EXTENSION_free(ex);
    	}
    	else if (certtype == CERTIFICATE_TLS_CLIENT)
    	{
    		// TLS client
    		ex = X509V3_EXT_conf_nid(NULL, NULL, NID_ext_key_usage, "TLS Web Client Authentication");
    		X509_add_ext(x, ex, -1);
    		X509_EXTENSION_free(ex);
    	}

    	if (!X509_sign(x,rootcert->pkey,EVP_sha256())) goto err;
    }

    cert->x509 = x;
    cert->pkey = pk;

    return(1);
    err:
    return(0);
*/
}

int util_keyhash(struct util_cert cert, char* result)
{
/*
    if (cert.x509 == NULL) return -1;
    util_sha256((char*)(cert.x509->cert_info->key->public_key->data), cert.x509->cert_info->key->public_key->length, result);
    return 0;
*/
}

int util_keyhash2(X509* cert, char* result)
{
/*
    if (cert == NULL) return -1;
    util_sha256((char*)(cert->cert_info->key->public_key->data), cert->cert_info->key->public_key->length, result);
    return 0;
*/
}

// Perform a MD5 hash on the data
void util_md5(char* data, int datalen, char* result)
{
/*
    MD5_CTX c;
    MD5_Init(&c);
    MD5_Update(&c, data, datalen);
    MD5_Final((unsigned char*)result, &c);
*/
}

// Perform a MD5 hash on the data and convert result to HEX and store in output
// This is useful for HTTP Digest
void util_md5hex(char* data, int datalen, char *out)
{
/*
    int i = 0;
    unsigned char *temp = (unsigned char*)out;
    MD5_CTX mdContext;
    unsigned char digest[16];

    MD5_Init(&mdContext);
    MD5_Update(&mdContext, (unsigned char *)data, datalen);
    MD5_Final(digest, &mdContext);

    for(i = 0; i < HALF_NONCE_SIZE; i++)
    {
    	*(temp++) = utils_HexTable[(unsigned char)data[i] >> 4];
    	*(temp++) = utils_HexTable[(unsigned char)data[i] & 0x0F];
    }

    *temp = '\0';
*/
}

// Sign this block of data, the first 32 bytes of the block must be avaialble to add the certificate hash.
int util_sign(struct util_cert cert, char* data, int datalen, char** signature)
{
/*
    int size = 0;
    unsigned int hashsize = UTIL_HASHSIZE;
    BIO *in = NULL;
    PKCS7 *message = NULL;
    *signature = NULL;
    if (datalen <= UTIL_HASHSIZE) return 0;

    // Add hash to start of data
    X509_digest(cert.x509, EVP_sha256(), (unsigned char*)data, &hashsize);

    // Sign the block
    in = BIO_new_mem_buf(data, datalen);
    message = PKCS7_sign(cert.x509, cert.pkey, NULL, in, PKCS7_BINARY);
    if (message == NULL) return 0;
    size = i2d_PKCS7(message, (unsigned char**)signature);
    BIO_free(in);
    PKCS7_free(message);
    return size;
*/
}

// Verify the signed block, the first 32 bytes of the data must be the certificate hash to work.
int util_verify(char* signature, int signlen, struct util_cert* cert, char** data)
{
/*
    unsigned int size, r;
    BIO *out = NULL;
    PKCS7 *message = NULL;
    char* data2 = NULL;
    char hash[UTIL_HASHSIZE];
    STACK_OF(X509) *st = NULL;

    cert->x509 = NULL;
    cert->pkey = NULL;
    *data = NULL;
    message = d2i_PKCS7(NULL, (const unsigned char**)&signature, signlen);
    if (message == NULL) goto error;
    out = BIO_new(BIO_s_mem());

    // Lets rebuild the original message and check the size
    size = i2d_PKCS7(message, NULL);
    if (size < (unsigned int)signlen) goto error;

    // Check the PKCS7 signature, but not the certificate chain.
    r = PKCS7_verify(message, NULL, NULL, NULL, out, PKCS7_NOVERIFY);
    if (r == 0) goto error;

    // If data block contains less than 32 bytes, fail.
    size = BIO_get_mem_data(out, &data2);
    if (size <= UTIL_HASHSIZE) goto error;

    // Copy the data block
    *data = malloc(size+1);
    if (*data == NULL) goto error;
    memcpy(*data, data2, size);
    (*data)[size] = 0;

    // Get the certificate signer
    st = PKCS7_get0_signers(message, NULL, PKCS7_NOVERIFY);
    cert->x509 = X509_dup(sk_X509_value(st, 0));
    sk_X509_free(st);

    // Get a full certificate hash of the signer
    r = UTIL_HASHSIZE;
    X509_digest(cert->x509, EVP_sha256(), (unsigned char*)hash, &r);

    // Check certificate hash with first 32 bytes of data.
    if (memcmp(hash, *data, UTIL_HASHSIZE) != 0) goto error;

    // Approved, cleanup and return.
    BIO_free(out);
    PKCS7_free(message);

    return size;

    error:
    if (out != NULL) BIO_free(out);
    if (message != NULL) PKCS7_free(message);
    if (*data != NULL) free(*data);
    if (cert->x509 != NULL) { X509_free(cert->x509); cert->x509 = NULL; }

    return 0;
*/
}

// Encrypt a block of data for a target certificate
int util_encrypt(struct util_cert cert, char* data, int datalen, char** encdata)
{
/*
    int size = 0;
    BIO *in = NULL;
    PKCS7 *message = NULL;
    STACK_OF(X509) *encerts = NULL;
    *encdata = NULL;
    if (datalen == 0) return 0;

    // Setup certificates
    encerts = sk_X509_new_null();
    sk_X509_push(encerts,cert.x509);

    // Encrypt the block
    *encdata = NULL;
    in = BIO_new_mem_buf(data, datalen);
    message = PKCS7_encrypt(encerts, in, EVP_aes_128_cbc(), PKCS7_BINARY);
    if (message == NULL) return 0;
    size = i2d_PKCS7(message, (unsigned char**)encdata);
    BIO_free(in);
    PKCS7_free(message);
    sk_X509_free(encerts);
    return size;
*/
}

// Encrypt a block of data using multiple target certificates
int util_encrypt2( STACK_OF(X509) *certs, char* data, int datalen, char** encdata)
{
 /*
    int size = 0;
    BIO *in = NULL;
    PKCS7 *message = NULL;
    *encdata = NULL;
    if (datalen == 0) return 0;

    // Encrypt the block
    *encdata = NULL;
    in = BIO_new_mem_buf(data, datalen);
    message = PKCS7_encrypt(certs, in, EVP_aes_128_cbc(), PKCS7_BINARY);
    if (message == NULL) return 0;
    size = i2d_PKCS7(message, (unsigned char**)encdata);
    BIO_free(in);
    PKCS7_free(message);
    return size;
*/
}

// Decrypt a block of data using the specified certificate. The certificate must have a private key.
int util_decrypt(char* encdata, int encdatalen, struct util_cert cert, char** data)
{
/*
    unsigned int size, r;
    BIO *out = NULL;
    PKCS7 *message = NULL;
    char* data2 = NULL;

    *data = NULL;
    if (cert.pkey == NULL) return 0;

    message = d2i_PKCS7(NULL, (const unsigned char**)&encdata, encdatalen);
    if (message == NULL) goto error;
    out = BIO_new(BIO_s_mem());

    // Lets rebuild the original message and check the size
    size = i2d_PKCS7(message, NULL);
    if (size < (unsigned int)encdatalen) goto error;

    // Decrypt the PKCS7
    r = PKCS7_decrypt(message, cert.pkey, cert.x509, out, 0);
    if (r == 0) goto error;

    // If data block contains 0 bytes, fail.
    size = BIO_get_mem_data(out, &data2);
    if (size == 0) goto error;

    // Copy the data block
    *data = malloc(size+1);
    if (*data == NULL) goto error;
    memcpy(*data, data2, size);
    (*data)[size] = 0;

    // Cleanup and return.
    BIO_free(out);
    PKCS7_free(message);

    return size;

    error:
    if (out != NULL) BIO_free(out);
    if (message != NULL) PKCS7_free(message);
    if (*data != NULL) free(*data);
    if (data2 != NULL) free(data2);
    return 0;
*/
}




// Take a block of data and cipher it for a given key.
// The key is expected to be 36 bytes (including key identifier as for 4 bytes).
int util_cipher(char* key, char* nodeid, char* data, int datalen, char** result, int sendresponsekey)
{
/*
    	char* out;
    	int tmplen = 16;
    	int outlen = datalen + 40 + 16; // Worst case, we have to encode they session key (40) and padding (16)
    	int ptr = 44;
    	EVP_CIPHER_CTX ctx;
    	HMAC_CTX hmac;
    	unsigned int iv[4];
    	unsigned int hmaclen = 32;
    	char selfkey[40];
    	char tempkey[32];

    	// Incerement the IV and check for roll over.
    	if (g_nextiv++ == 0xFFFFFFFF)
    	{
    		// In the really rare case this roll over, lets reset our crypto keys.
    		// This may cause packets to be unreadable for a while, but things move back towards being normal.
    		util_random(UTIL_HASHSIZE, g_SessionRandom);
    		g_SessionRandomId++;
    		g_nextiv = 1;
    	}

    	// Allocate header + data + padding and fill in the header
    	if ((*result = out = malloc(44 + datalen + 40 + 16 + 32)) == NULL) return 0;
    	memcpy(out + 4, g_selfid, 32);				// 32 byte NodeID of the source
    	memcpy(out + 36, key, 4);					// 4 byte target session key identifier
    	memcpy(out + 40, &g_nextiv, 4);				// 4 byte IV salt

    	// Setup the IV
    	iv[0] = g_nextiv;
    	iv[1] = ((unsigned int*)nodeid)[0];
    	iv[2] = ((unsigned int*)nodeid)[1];
    	iv[3] = ((unsigned int*)nodeid)[2];

    	// Perform AES-128 crypto
    	EVP_CIPHER_CTX_init(&ctx);
    	util_genusagekey(key + 4, tempkey, 1); // Convert the private key into an encryption key
    	if (!EVP_EncryptInit_ex(&ctx, EVP_aes_128_cbc(), NULL, (const unsigned char *)tempkey, (const unsigned char*)iv)) goto error;

    	// Check if we need to encode the return key, if so, avoid copies and insert it into the crypto stream
    	if (sendresponsekey != 0)
    	{
    		// Computer our own return key for this now.
    		util_nodesessionkey(nodeid, selfkey + 4);
    		((unsigned short*)selfkey)[0] = PB_SESSIONKEY;
    		((unsigned short*)selfkey)[1] = 40;

    		// Encrypt the session key
    		if (!EVP_EncryptUpdate(&ctx, ((unsigned char*)out) + ptr, &outlen, (const unsigned char *)selfkey, 40)) goto error;
    		ptr += outlen;
    		outlen = datalen + 16;
    	}

    	// Finish the crypto operation
    	if (!EVP_EncryptUpdate(&ctx, (unsigned char*)(out + ptr), &outlen, (const unsigned char *)data, (int)datalen)) goto error;
    	if (!EVP_EncryptFinal_ex(&ctx, ((unsigned char*)out) + ptr + outlen, &tmplen)) goto error;
    	if (!EVP_CIPHER_CTX_cleanup(&ctx)) goto error;

    	// Setup the header
    	((unsigned short*)out)[0] = PB_AESCRYPTO;				// AES-128 block type
    	((unsigned short*)out)[1] = ptr + outlen + tmplen + 32;	// block length

    	// Perform HMAC-SHA256
    	util_genusagekey(key + 4, tempkey, 2); // Convert the private key into an integrity checking key
    	HMAC_CTX_init(&hmac);
    	HMAC_Init_ex(&hmac, tempkey, 32, EVP_sha256(), NULL);
    	HMAC_Update(&hmac, (unsigned char*)out, ptr + outlen + tmplen);
    	HMAC_Final(&hmac, (unsigned char*)(out + ptr + outlen + tmplen), &hmaclen);
    	HMAC_CTX_cleanup(&hmac);

    	// Return the total size: header + data + padding + HMAC.
    	return ptr + outlen + tmplen + 32;

    error:
    	EVP_CIPHER_CTX_cleanup(&ctx);
    	free(out);
    	*result = NULL;

    return 0;
*/
}

// Decrypt an incoming block of data
// If this packet is not encrypted correctly or uses an old key, we return zero.
int util_decipher(char* data, int datalen, char** result, char* nodeid)
{
/*
    	char* out = NULL;
    	int outlen = datalen - 44 + 16;
    	int tmplen = 16;
    	EVP_CIPHER_CTX ctx;
    	char key[36];
    	unsigned int iv[4];
    	HMAC_CTX hmac;
    	unsigned int hmaclen = 32;
    	char hmac_result[32];
    	char tempkey[32];

    	// Check pre-conditions
    	*result = NULL;
    	if (datalen < 44 + 16) return 0;									// If the data length is too short, exit.
    	if (((unsigned short*)data)[0] != 8) return 0;						// If this is not the right type, exit
    	if (((unsigned short*)data)[1] != datalen) return 0;				// If this is not the right size, exit
    	if (((unsigned int*)(data + 36))[0] != g_SessionRandomId) return 0;	// If this is not the correct key id, exit

    	// Compute the decryption key & IV
    	util_nodesessionkey(data + 4, key);
    	iv[0] = ((unsigned int*)(data + 40))[0];
    	iv[1] = ((unsigned int*)g_selfid)[0];
    	iv[2] = ((unsigned int*)g_selfid)[1];
    	iv[3] = ((unsigned int*)g_selfid)[2];

    	// Perform HMAC-SHA256 and check
    	util_genusagekey(key + 4, tempkey, 2); // Convert the private key into an integrity checking key
    	HMAC_CTX_init(&hmac);
    	HMAC_Init_ex(&hmac, tempkey, 32, EVP_sha256(), NULL);
    	HMAC_Update(&hmac, (unsigned char*)data, datalen - 32);
    	HMAC_Final(&hmac, (unsigned char*)hmac_result, &hmaclen);
    	HMAC_CTX_cleanup(&hmac);
    	if (memcmp(hmac_result, data + datalen - 32, 32) != 0) goto error;

    	// Allocate the output data buffer
    	if ((*result = out = malloc(datalen - 44 + 16 + 1000)) == NULL) return 0;

    	// Perform AES-128 decrypt
    	util_genusagekey(key + 4, tempkey, 1); // Convert the private key into an encryption key
    	EVP_CIPHER_CTX_init(&ctx);
    	if (!EVP_DecryptInit_ex(&ctx, EVP_aes_128_cbc(), NULL, (const unsigned char*)tempkey, (const unsigned char*)iv)) { EVP_CIPHER_CTX_cleanup(&ctx); goto error; }
    	if (!EVP_DecryptUpdate(&ctx, (unsigned char*)out, &outlen, (unsigned char*)(data + 44), (int)datalen - 44 - 32)) { EVP_CIPHER_CTX_cleanup(&ctx); goto error; }
    	if (!EVP_DecryptFinal_ex(&ctx, ((unsigned char *)out) + outlen, &tmplen)) { EVP_CIPHER_CTX_cleanup(&ctx); goto error; }
    	if (!EVP_CIPHER_CTX_cleanup(&ctx)) goto error;

    	// We know the source of this block
    	if (nodeid != NULL) memcpy(nodeid, data + 4, 32);

    	// Return the total size
    	return outlen + tmplen;

    error:
    	if (out != NULL) free(out);
    	*result = NULL;

    return 0;
*/
}


// Setup OpenSSL
void util_openssl_init()
{
/*
    char* tbuf[64];
#ifdef WIN32
    HMODULE g_hAdvLib = NULL;
    BOOLEAN (APIENTRY *g_CryptGenRandomPtr)(void*, ULONG) = NULL;
#endif
#ifdef _POSIX
    int l;
#endif

//	SSLeay_add_all_algorithms();
//	SSL_library_init(); // TWO LEAKS COMING FROM THIS LINE. Seems to be a well known OpenSSL problem.
//	SSL_load_error_strings();
//	ERR_load_crypto_strings(); // ONE LEAK IN LINUX

    // Add more random seeding in Windows (This is probably useful since OpenSSL in Windows has weaker seeding)
#ifdef WIN32
    RAND_screen(); // On Windows, add more random seeding using a screen dump
    if (g_hAdvLib = LoadLibrary(TEXT("ADVAPI32.DLL"))) g_CryptGenRandomPtr = (BOOLEAN (APIENTRY *)(void*,ULONG))GetProcAddress(g_hAdvLib,"SystemFunction036");
    if (g_CryptGenRandomPtr != 0 && g_CryptGenRandomPtr(tbuf, 64) != 0) RAND_add(tbuf, 64, 64); // Use this high quality random as added seeding
    if (g_hAdvLib != NULL) FreeLibrary(g_hAdvLib);
#endif

    // Add more random seeding in Linux (May be overkill since OpenSSL already uses /dev/urandom)
#ifdef _POSIX
    // Under Linux we use "/dev/urandom" if available. This is the best source of random on Linux & variants
    FILE *pFile = fopen("/dev/urandom","rb");
    if (pFile != NULL)
    {
        l = fread(tbuf, 1, 64, pFile);
        fclose(pFile);
        if (l > 0) RAND_add(tbuf, l, l);
    }
#endif
*/
}

// Cleanup OpenSSL
void util_openssl_uninit()
{
//	RAND_cleanup();
//	CRYPTO_set_dynlock_create_callback(NULL);
//	CRYPTO_set_dynlock_destroy_callback(NULL);
//	CRYPTO_set_dynlock_lock_callback(NULL);
//	CRYPTO_set_locking_callback(NULL);
//	CRYPTO_set_id_callback(NULL);
//	ERR_remove_state(0);
//	CONF_modules_unload(1);
//	ERR_free_strings();
//	EVP_cleanup();
//	CRYPTO_cleanup_all_ex_data();
//	ENGINE_cleanup();
}

