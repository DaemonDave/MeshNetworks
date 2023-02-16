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



//! \note moved the certificate data structs here for control integrity.
struct util_cert selfcert;
struct util_cert selftlscert;
struct util_cert selftlsclientcert;



struct util_cert* ctrl_GetCert() 
{
    return &selfcert;
}
struct util_cert* ctrl_GetTlsCert() 
{
    return &selftlscert;
}
struct util_cert* ctrl_GetTlsClientCert() 
{
    return &selftlsclientcert;
}
char* ctrl_GetSelfNodeId() 
{
    return g_selfid;
}
NodeInfoBlock_t* ctrl_GetCurrentNodeInfoBlock() 
{
    return g_nodeblock;
}
unsigned int ctrl_GetSignedBlockSyncCounter() 
{
    return g_signedblocksynccounter;
}

#define INET_SOCKADDR_LENGTH(x) ((x==AF_INET6?sizeof(struct sockaddr_in6):sizeof(struct sockaddr_in)))
//! \fn ctrl_MeshInit is the data base loader or regenerator for the entire mesh security setup
int ctrl_MeshInit()
{
    int l, i;
    char* str;

    // Mesh Setup
    // open the database
    l = mdb_open();
    // mesh OpenSSL configuration from the database installed.
    switch (l)
    {
		case 0:
			// Load existing node certificate
			i = mdb_get("SelfNodeCert", &str);
			if (util_from_p12(str, i, "hidden", &selfcert) == 0) 
			{
				MSG("Failed to open node cert.\r\n");    // Failed to load node certificate
				return 100;
			}
			util_free(str);

			// Load existing TLS certificate
			i = mdb_get("SelfNodeTlsCert", &str);
			if (util_from_p12(str, i, "hidden", &selftlscert) == 0) {
				MSG("Failed to open TLS cert.\r\n");    // Failed to load node certificate
				return 100;
			}
			util_free(str);

			// Load existing TLS client certificate
			i = mdb_get("SelfNodeTlsClientCert", &str);
			if (util_from_p12(str, i, "hidden", &selftlsclientcert) == 0) {
				MSG("Failed to open TLS client cert.\r\n");    // Failed to load node certificate
				return 100;
			}
			util_free(str);

			MSG("Loaded existing certificates.\r\n");
			break;
		case 1:
			// Failed to open database
			MSG("Failed to open database.\r\n");
			return 101;
	    //! \note this segment show how to make a 
		case 2:
			MSG("Generating new certificates...\r\n");

			// Generate a new node certificate
			l = util_mkCert(NULL, &selfcert, 2048, 10000, "RootCertificate", CERTIFICATE_ROOT);
			l = util_to_p12(selfcert, "hidden", &str);
			mdb_set("SelfNodeCert", str, l);
			util_free(str);

			// Generate a new TLS certificate
			l = util_mkCert(&selfcert, &selftlscert, 2048, 10000, "localhost", CERTIFICATE_TLS_SERVER);
			l = util_to_p12(selftlscert, "hidden", &str);
			mdb_set("SelfNodeTlsCert", str, l);
			util_free(str);

			// Generate a new TLS client certificate
			l = util_mkCert(&selfcert, &selftlsclientcert, 2048, 10000, "localhost", CERTIFICATE_TLS_CLIENT);
			l = util_to_p12(selftlsclientcert, "hidden", &str);
			mdb_set("SelfNodeTlsClientCert", str, l);
			util_free(str);

			MSG("Certificates ready.\r\n");
			break;
    }
    // setup serial number
    // Get our current serial number, add 1 more for safety.
    g_serial = mdb_get_i("nodeserial") + 1;

	
    // Setup the session secret key
    g_SessionRandomId = g_serial;
    util_random(32, g_SessionRandom);

    // Compute our own NodeID & setup packet used for multicast at the same time
    util_keyhash(selfcert, g_selfid);
    ((unsigned short*)g_selfid_mcast)[0] = PB_NODEID;
    ((unsigned short*)g_selfid_mcast)[1] = 36;
    memcpy(g_selfid_mcast + 4, g_selfid, UTIL_HASHSIZE);

    // Compute our latest node block
    ctrl_GetCurrentSignedNodeInfoBlock(&str);

    // Setup local subscriptions
    memset(ctrl_SubscriptionChain, 0, sizeof(struct LocalSubscription) * 8);	// Clear the subscription list
    ctrl_SubscriptionLoopback.sin_family = AF_INET;								// IPv4
#ifdef WINSOCK2
    ctrl_SubscriptionLoopback.sin_addr.S_un.S_addr = 0x0100007F;				// 127.0.0.1
#else
    ctrl_SubscriptionLoopback.sin_addr.s_addr = 0x0100007F;						// 127.0.0.1
#endif

    return 0;
}

void ctrl_MeshUnInit()
{
    if (g_nodeblock != NULL) info_FreeInfoBlock(g_nodeblock);
    if (g_signedblock != NULL) free(g_signedblock);
    if (g_signedblockhash != NULL) free(g_signedblockhash);
    g_nodeblock = NULL;
    util_freecert(&selftlsclientcert);
    util_freecert(&selftlscert);
    util_freecert(&selfcert);
    mdb_close();
}


int ctrl_GetCurrentSignedNodeInfoBlock(char** block)
{
    unsigned short includes[] = { 0x01, 0x02, 0x03, 0x00 };
    NodeInfoBlock_t *node = NULL;
    char *hash;
    char *temp;
    int len;

    if ((hash = malloc(UTIL_HASHSIZE)) == NULL) 
    {
        if (block != NULL) *block = g_signedblock;
        return g_signedblocklen;
    }
    // Get the block & run a hash on it
    node = info_CreateInfoBlock(includes, (UTIL_HASHSIZE * 2) + 4);		// [CertHash(UTIL_HASHSIZE) + NodeID(UTIL_HASHSIZE) + Serial(4)] + CompressedInfo
    if (node == NULL) 
    {
        free(hash);
        if (block != NULL) *block = g_signedblock;
        return g_signedblocklen;
    }
    util_sha256(node->rawdata + ((UTIL_HASHSIZE * 2) + 4), node->rawdatasize - ((UTIL_HASHSIZE * 2) + 4), hash);
    if (g_signedblockhash != NULL && memcmp(hash, g_signedblockhash, UTIL_HASHSIZE) == 0)
    {
        // Node block has not changed, return the one in the database
        info_FreeInfoBlock(node);
        free(hash);
        if (block != NULL) *block = g_signedblock;
        return g_signedblocklen;
    }

    // Fetch node serial number & copy it and node id in correct spot
    mdb_set_i("nodeserial", ++g_serial);
    memcpy((node->rawdata)+ (UTIL_HASHSIZE * 2), &g_serial, 4);				// Copy the serial number in correct spot.
    memcpy((node->rawdata)+ UTIL_HASHSIZE, g_selfid, UTIL_HASHSIZE);		// Copy the NodeID in correct spot.

    // Update the global node block
    if (g_nodeblock != NULL) info_FreeInfoBlock(g_nodeblock);
    g_nodeblock = node;

    // Sign it
    len = util_sign(selfcert, node->rawdata, node->rawdatasize, &temp);

    // Add the header
    if (g_signedblock != NULL) free(g_signedblock);
    if ((g_signedblock = malloc(g_signedblocklen = len + 4)) == NULL) return 0;
    ((unsigned short*)(g_signedblock))[0] = PB_NODEPUSH;
    ((unsigned short*)(g_signedblock))[1] = (unsigned short)g_signedblocklen;
    memcpy(g_signedblock + 4, temp, len);
    free(temp);
    if (g_signedblockhash != NULL) free(g_signedblockhash);
    g_signedblockhash = hash;
    if (block != NULL) *block = g_signedblock;

    // Send the new block as a local event
    ctrl_SendSubscriptionEvent(g_signedblock, g_signedblocklen);

    return g_signedblocklen;
}

NodeInfoBlock_t* ctrl_ParseSignedNodeInfoBlock(unsigned short xsize, char* xblock, char* blockid)
{
    int l, r;
    char* data;
    char* nodeid;
    char nodeid2[UTIL_HASHSIZE];
    unsigned int serial;
    struct util_cert cert;
    NodeInfoBlock_t* node;
    unsigned short size = xsize - 4;
    char* block = xblock + 4;

    // Process the incoming signed block
    l = util_verify(block, size, &cert, &data);
    if (data == NULL) return NULL;
    if (l < ((UTIL_HASHSIZE * 2) + 4)) 
    {
        free(data);
        return NULL;
    }

    // Get the summary data
    nodeid = data + UTIL_HASHSIZE;
    serial = ((unsigned int*)(data + (UTIL_HASHSIZE * 2)))[0];

    // If this is our own block, ignore it... but only after checking the serial number.
    if (memcmp(g_selfid, nodeid, UTIL_HASHSIZE) == 0)
    {
        if (serial > g_serial)
        {
            // Found a higher serial number. Set the new serial and clear our current node block.
            g_serial = serial + 1;
            if (g_signedblock != NULL) free(g_signedblock);
            if (g_signedblockhash != NULL) free(g_signedblockhash);
            g_signedblock = NULL;
            g_signedblockhash = NULL;
            ctrl_GetCurrentSignedNodeInfoBlock(NULL);
        }

        // Ignore our own node
        util_freecert(&cert);
        free(data);
        return NULL;
    }

    // Check the NodeID against the cert public key hash
    util_keyhash(cert, nodeid2);
    if (memcmp(nodeid, nodeid2, UTIL_HASHSIZE) != 0)
    {
        // Failed NodeId check.
        util_freecert(&cert);
        free(data);
        return NULL;
    }
    util_freecert(&cert);

    // Parse the data
    node = info_ParseInfoBlock(data, l, ((UTIL_HASHSIZE * 2) + 4));

    // Save the node in the database
    r = mdb_blockset(nodeid, serial, xblock, xsize);
    if (blockid != NULL) memcpy(blockid, nodeid, UTIL_HASHSIZE);

    // If this node is new or updated, analyse the information
    if (r > 0) ctrl_AnalyseNewPushBlock(node, r);

    return node;
}

// Process a single block of data.
// OUT: If blockid is not null, it must point to 32 bytes of free memory.
// IN : If the sender's nodeid is known, it will be in nodeid;
int ctrl_ProcessDataBlock(char* block, int blocklen, char* blockid, char* nodeid, struct sockaddr_in6 *remoteInterface, char* returnkey)
{
    NodeInfoBlock_t* node;
    unsigned short type, size;

    // Decode the block header
    if (blocklen < 4) return 0;
    type = ((unsigned short*)(block))[0];
    size = ((unsigned short*)(block))[1];

    // Must check block length overrun here.
    if (size > blocklen) return 0;

    // Switch on the block type
    switch(type)
    {
		case PB_NODEPUSH: // Standard push block
			// Parse the data and add it to the database if needed
			node = ctrl_ParseSignedNodeInfoBlock(size, block, NULL);
			if (node != NULL)
			{

	#ifdef WIN32 // DEBUG
				if (size == 0)
				{
					__asm int 3;
				}
	#endif

				MSG3("Incoming node block, size=%d, name=%s\r\n", size, node->compinfo->name);
				info_FreeInfoBlock(node);
			}
			else
			{
				MSG2("Incoming bad or self node block, size=%d\r\n", size);
			}
			break;
		case PB_AESCRYPTO: // AES-256 encrypted block, decrypt this and run it thru again.
		{
			char *data;
			int len;
			char sourcenode[UTIL_HASHSIZE];

			if ((len = util_decipher(block, size, &data, sourcenode)) == 0)
			{
				//MSG("AES-128-CBC decode FAILED.\r\n");
				break;
			}
			if (blockid != NULL) memcpy(blockid, sourcenode, UTIL_HASHSIZE);

			// If the first block is the return key, use it.
			// Then process the blocks and free the data
			if (((unsigned short*)data)[0] == PB_SESSIONKEY && ((unsigned short*)data)[1] == 40)
			{
				ctrl_ProcessDataBlocks(data + 40, len - 40, blockid, sourcenode, remoteInterface, data + 4);
			}
			else
			{
				ctrl_ProcessDataBlocks(data, len, blockid, sourcenode, remoteInterface, NULL);
			}

			free(data);
		}
		break;
		case PB_SESSIONKEY: // This is a private session key, store it in the database
		{
			// If this is a proper key and we know for what node, store the key in the target database
			if (nodeid != NULL && size == 40) mdb_setsessionkey(nodeid, block + 4);
		}
		break;
		case PB_SYNCSTART:
		{
			// Use to start a sync session, lets fetch a setup of record data and send it back.
			if (nodeid != NULL && size == 36 && remoteInterface != NULL)
			{
				char* data = NULL;
				int datalen = 0;
				char sessionkey[36];
				char nodeid2[32];
				unsigned char power;

				if (returnkey == NULL)
				{
					// Fetch the session key for this node, if we don't already have a return key
					((unsigned int*)sessionkey)[0] = 0;
					if (mdb_gettargetstate((struct sockaddr*)remoteInterface, nodeid2, &power, sessionkey, NULL) == 0) break; // If we don't have state for this target, exit.
					if (((unsigned int*)sessionkey)[0] == 0 || memcmp(nodeid, nodeid2, 32) != 0) break; // This packet was received from an unexpected source
				}

				// Fetch a block of metadata, maximum size of the block is 1000 bytes
				datalen = mdb_getmetadatablock(block + 4, 1000, &data, nodeid);

				// Send it back to the requester & free the block
				if (data != NULL && datalen != 0) SendCryptoUdpToTarget((struct sockaddr*)remoteInterface, nodeid, returnkey == NULL?sessionkey:returnkey, data, datalen, 0);
				free(data);
			}
		}
		break;
		case PB_SYNCMETADATA:
		{
			// We received metadata from another node, lets compare it against our own data and see what is different
			if (nodeid != NULL && size >= 36 && remoteInterface != NULL)
			{
				char sessionkey[36];
				char nodeid2[32];
				unsigned char power;
				unsigned int serial;

				if (returnkey == NULL)
				{
					// Fetch the session key for this node, if we don't already have a return key					((unsigned int*)sessionkey)[0] = 0;
					if (mdb_gettargetstate((struct sockaddr*)remoteInterface, nodeid2, &power, sessionkey, &serial) == 0) break; // If we don't have state for this target, exit.
					if (((unsigned int*)sessionkey)[0] == 0 || memcmp(nodeid, nodeid2, 32) != 0) break; // This packet was received from an unexpected source
				}

				// Since we have proof that a node is at a given address and running, update the target.
				if (remoteInterface != NULL) mdb_updatetarget(nodeid, (struct sockaddr*)remoteInterface, MDB_AGENT, 1);

				// Now, our database module will do the really difficult work
				mdb_performsync(block + 4, size - 4, nodeid, (struct sockaddr*)remoteInterface, returnkey == NULL?sessionkey:returnkey, serial);

				// One more thing, lets fire the metadata from this node as an event, but we need to also include the source node in the event.
				if (ctrl_SubscriptionChainCount > 0)
				{
					// This is an expensive memcopy, would be nice to find a way around it. Still, it only happens when there are local subscribers.
					char* buf;
					if ((buf = malloc(36 + size)) == NULL) ILIBCRITICALEXIT(254);
					((unsigned short*)buf)[0] = PB_NODEID;
					((unsigned short*)buf)[1] = 36;
					memcpy(buf + 4, nodeid, 32);
					memcpy(buf + 36, block, size);
					ctrl_SendSubscriptionEvent(buf, size + 36);
					free(buf);
				}
			}
		}
		break;
		case PB_SYNCREQUEST:
		{
			// This is a list of requested blocks, lets push them back.
			if (nodeid != NULL && size >= 36 && remoteInterface != NULL)
			{
				int ptr = 4;
				char* data;
				int datalen;
				char sessionkey[36];
				char nodeid2[32];
				unsigned char power;

				if (returnkey == NULL)
				{
					// Fetch the session key for this node, if we don't already have a return key
					((unsigned int*)sessionkey)[0] = 0;
					if (mdb_gettargetstate((struct sockaddr*)remoteInterface, nodeid2, &power, sessionkey, NULL) == 0) break; // If we don't have state for this target, exit.
					if (((unsigned int*)sessionkey)[0] == 0 || memcmp(nodeid, nodeid2, 32) != 0) break; // This packet was received from an unexpected source
				}

				// Go thru the list of requests and send them all
				while (ptr < size)
				{
					// Fetch the block from the database
					datalen = mdb_blockget(block + ptr, &data);
					if (data != NULL)
					{
						// We got the requested block, send it out
						SendCryptoUdpToTarget((struct sockaddr*)remoteInterface, nodeid, returnkey == NULL?sessionkey:returnkey, data, datalen, 0);
						free(data);
					}
					else
					{
						// This block is not in the database, check to see if the request is for our own block
						if (memcmp(block + ptr, g_selfid, UTIL_HASHSIZE) == 0 && g_signedblock != NULL && g_signedblocklen != 0)
						{
							// Yes, it's out own block, send it out. This is simple, we got that in memory and ready to go.
							SendCryptoUdpToTarget((struct sockaddr*)remoteInterface, nodeid, returnkey == NULL?sessionkey:returnkey, g_signedblock, g_signedblocklen, 0);
						}
					}
					ptr += 32;
				}
			}
		}
		break;
		case PB_NODEID:
		{
			if (blockid != NULL && size == 36 && remoteInterface != NULL)
			{
				// This is a simple NodeID block
				memcpy(blockid, block+4, UTIL_HASHSIZE);
			}
		}
		break;
		case PB_AGENTID:
		{
			if (size == 10 && remoteInterface != NULL)
			{
				struct HttpRequestBlock* user;
				unsigned short r_agentid = ntohs(((unsigned short*)block)[4]);
				unsigned long r_agentversion = ntohl(((unsigned int*)block)[1]);

				// Let check to see if this node has a better version of the agent
				if (g_PerformingSelfUpdate == 0 && g_agentid != 0 && r_agentid != 0 && g_agentid == r_agentid && r_agentversion > MESH_AGENT_VERSION)
				{
					// Attempt an HTTP connection to that target
					if ((user = malloc(sizeof(struct HttpRequestBlock))) == NULL) ILIBCRITICALEXIT(254);
					memset(user, 0, sizeof(struct HttpRequestBlock));
					if ((user->addr = malloc(sizeof(struct sockaddr_in6))) == NULL) ILIBCRITICALEXIT(254);

					// Copy the address and set to port
					memcpy(user->addr, remoteInterface, sizeof(struct sockaddr_in6));
					if (((struct sockaddr_in*)(user->addr))->sin_family == AF_INET) ((struct sockaddr_in*)(user->addr))->sin_port = htons(MESH_AGENT_PORT);
					else ((struct sockaddr_in6*)(user->addr))->sin6_port = htons(MESH_AGENT_PORT);

					// Setup and perform the HTTP request to get the updated executable
					user->requesttype = 3;
					g_PerformingSelfUpdate = 1;
					PerformHttpRequest(1, (struct sockaddr*)user->addr, "/mesh/selfexe.bin", user, NULL, 0);
				}
			}
		}
		break;
		default:
			MSG3("Incoming block, type=%d, size=%d\r\n", type, size);
	#ifdef WIN32
			//_asm int 3;
	#endif
			break;
    }
    return size;
}

// Process a series of blocks
// OUT: If blockid is not null, it must point to 32 bytes of free memory.
// IN : If the sender's nodeid is known, it will be in nodeid;
int ctrl_ProcessDataBlocks(char* block, int blocklen, char* blockid, char* nodeid, struct sockaddr_in6 *remoteInterface, char* returnkey)
{
    int bl, ptr = 0;
    mdb_begin();
    while ((blocklen - ptr) > 4)
    {
        // Process this block of data
        if ((bl = ctrl_ProcessDataBlock(block + ptr, blocklen - ptr, (ptr==0)?blockid:NULL, nodeid, remoteInterface, returnkey)) == 0) break;
        ptr += bl;
    }
    mdb_commit();
    return ptr;
}

// Sync with another node
void ctrl_SyncToNodeUDP(struct sockaddr *addr, char *nodeid, int state, char* key, char* nextsyncblock, unsigned int lastcontact, unsigned int serial)
{
    // If this target is in Intel(R) AMT only mode, keep using Intel(R) AMT for sync.
    if (state == MDB_AMTONLY) return;

    // Send Syncronization Request
    if (key != NULL && ((unsigned int*)key)[0] != 0)
    {
        SendCryptoUdpToTarget(addr, nodeid, key, nextsyncblock, 36, 1); // Send the SYNCSTART block using UDP
    }
}

// Sync with another node
void ctrl_SyncToNodeTCP(struct sockaddr *addr, char *nodeid, int state, char* key, char* nextsyncblock, unsigned int lastcontact, unsigned int serial)
{
    struct HttpRequestBlock* user;
    NodeInfoBlock_t* nodeinfo;
    char* post;

    // If this target is in Intel(R) AMT only mode, keep using Intel(R) AMT for sync.
    if (state == MDB_AMTONLY)
    {
        if ((nodeinfo = ctrl_GetNodeInfoBlock(nodeid)) != NULL)
        {
            if (nodeinfo->meinfo != NULL && nodeinfo->meinfo->guestuser[0] != 0 && nodeinfo->meinfo->guestpassword[0] != 0)
            {
                // Launch a sync with Intel AMT
                ctrl_SyncToIntelAmt(nodeinfo->meinfo->tlsenabled, addr, (nodeinfo->meinfo->tlsenabled==0?16992:16993), nodeid, (char*)(nodeinfo->meinfo->guestuser), (char*)(nodeinfo->meinfo->guestpassword));
            }
            else
            {
                // Target is in Intel AMT mode but with not Intel AMT credentials. In this rare case, remove this target.
                mdb_updatetarget(NULL, addr, MDB_UNKNOWN, 0);
            }
            info_FreeInfoBlock(nodeinfo);
        }
        return;
    }

    // Let perform a normal agent-to-agent QuickSick connection. Setup the request.
    if ((user = malloc(sizeof(struct HttpRequestBlock))) == NULL) ILIBCRITICALEXIT(254);
    memset(user, 0, sizeof(struct HttpRequestBlock));
    user->requesttype = 1;
    if ((user->nodeid = malloc(UTIL_HASHSIZE)) == NULL) ILIBCRITICALEXIT(254);
    memcpy(user->nodeid, nodeid, UTIL_HASHSIZE);
    if ((user->addr = malloc(sizeof(struct sockaddr_in6))) == NULL) ILIBCRITICALEXIT(254);
    memcpy(user->addr, addr, INET_SOCKADDR_LENGTH(addr->sa_family));

    // We need to package own NodeID & serial number in the post
    if ((post = malloc(4 + UTIL_HASHSIZE)) == NULL) ILIBCRITICALEXIT(254);
    ((unsigned int*)post)[0] = htonl(serial);
    memcpy(post + 4, nodeid, UTIL_HASHSIZE);

    // This will launch a TLS connection and ask for the remote push block and session key
    PerformHttpRequest(1, addr, "/mesh/quicksync.bin", user, post, 4 + UTIL_HASHSIZE);
}

// Get the node information block for a given NodeID
// TODO: Optimize: This method is far from optimal since it re-verifies the PKCS#7 signature, etc.
// a possible solution is to avoid calling this and store seperate computer data in the database
// upon first decode.
NodeInfoBlock_t* ctrl_GetNodeInfoBlock(char* nodeid)
{
    char* block;
    int len;
    struct util_cert cert;
    char* data;

    // Fetch the block from the database
    len = mdb_blockget(nodeid, &block);
    if (block == NULL) return NULL;

    // Unpack the PKCS#12 message
    len = util_verify(block+4, len-4, &cert, &data);
    util_freecert(&cert);
    free(block);

    // Parse the computer information
    return info_ParseInfoBlock(data, len, ((UTIL_HASHSIZE * 2) + 4));
}

// This method is called when a new push block is received that is better than the previous
// one we had before or this is a completely new block. We should look into the block to see
// if there is anything interesting.
void ctrl_AnalyseNewPushBlock(NodeInfoBlock_t* node, int newnode)
{
    //info_PrintInfoBlock(node);
}

// Add a local event subscriber. Only the port is needed because the target will be IPv4 127.0.0.1
// Subscribers must renew subscriptions every 2 minutes
void ctrl_AddSubscription(unsigned short port)
{
    int i = 0;
    char e = LOCALEVENT_UNSUBSCRIBE;
    unsigned long time = util_gettime();
    unsigned long expired = time - (60000 * MESH_LOCAL_EVENT_SUBSCRIPTION_TIMEOUT);				// Minutes event expiration
    ctrl_SubscriptionLoopback.sin_port = port;

    // Go thru the list and find a spot for this new subscriber. It's possible this is just a renewal.
    ctrl_SubscriptionChainCount++;
    while (i < 8)
    {
        if (ctrl_SubscriptionChain[i].time < expired || ctrl_SubscriptionChain[i].port == port)
        {
            ctrl_SubscriptionChain[i].time = time;
            ctrl_SubscriptionChain[i].port = port;
            e = LOCALEVENT_SUBSCRIBE;
            time = 0;
            port = 0;
        }
        i++;
    }

    // Send an unicast event back to the subscriber
    UnicastUdpPacket((struct sockaddr*)&ctrl_SubscriptionLoopback, &e, 1);
}

// Remove a local event subscriber
void ctrl_RemoveSubscription(unsigned short port)
{
    int i = 0;
    char e = LOCALEVENT_UNSUBSCRIBE;

    // Go thru the list and find subscriber to delete
    while (i < 8)
    {
        if (ctrl_SubscriptionChain[i].port == port) ctrl_SubscriptionChain[i].time = ctrl_SubscriptionChain[i].port = 0;
        i++;
    }

    // Send an unicast event back to the subscriber
    ctrl_SubscriptionLoopback.sin_port = port;
    UnicastUdpPacket((struct sockaddr*)&ctrl_SubscriptionLoopback, &e, 1);
}

// Notify the subscribers of an event. All valid subscribers will get a UDP packet
extern char IPv4Loopback[4];
void ctrl_SendSubscriptionEvent(char *data, int datalen)
{
    int i = 0;
    int count = 0;
    unsigned long expired;

    if (ctrl_SubscriptionChainCount == 0) return;
    expired = util_gettime() - (60000 * MESH_LOCAL_EVENT_SUBSCRIPTION_TIMEOUT);	// Minutes event expiration
    while (i < 8)
    {
        if (ctrl_SubscriptionChain[i].time > expired && ctrl_SubscriptionChain[i].port != 0)
        {
            // Send the event using UDP to 127.0.0.1 and the specified port
            ctrl_SubscriptionLoopback.sin_port = ctrl_SubscriptionChain[i].port;
            UnicastUdpPacket((struct sockaddr*)&ctrl_SubscriptionLoopback, data, datalen);
            count++;
        }
        i++;
    }
    ctrl_SubscriptionChainCount = count;
}

char* ctrl_GetChallengeHash(char* nonce, char* secret, int counter)
{
    char input[68];
    char* output;
    if ((output = malloc(UTIL_HASHSIZE)) == NULL) return NULL;

    // temp3 = Hash(random + secret + counter)
    memcpy(input, nonce, 32);
    memcpy(input + 32, secret, 32);
    memcpy(input + 64, (char*)&counter, 4);
    util_sha256(input, 68, output);

    return output;
}

// Generates a node challenge block, used to check the identitiy of a node
int ctrl_GetNodeChallenge(char* secret, int counter, char** challenge)
{
    char random[32];
    char* temp3 = NULL;
    char* block;
    *challenge = NULL;

    // Get random string and compute hash
    util_random(32, random);
    temp3 = ctrl_GetChallengeHash(random, secret, counter);
    if (temp3 == NULL) return 0;
    if ((block = malloc(72)) == NULL) ILIBCRITICALEXIT(254);

    // block = header + counter + hash + random
    ((unsigned short*)block)[0] = PB_NODECHALLENGE;	// Block Type
    ((unsigned short*)block)[1] = 72;				// Block Length
    memcpy(block + 4, (char*)&counter, 4);			// Counter
    memcpy(block + 8, temp3, 32);					// Hash
    memcpy(block + 40, random, 32);					// Random

    // Cleanup
    free(temp3);

    *challenge = block;
    return 72;
}

// Resolves a node identity challenge, returning a response block
int ctrl_PerformNodeChallenge(struct util_cert cert, char* challenge, int challengelen, char** response)
{
    int len;
    char* sign = NULL;
    char* block;
    char* challenge2;
    *response = NULL;
    if (challenge == NULL || challengelen != 72) return 0;
    if (((unsigned short*)challenge)[0] != PB_NODECHALLENGE) return 0;
    if (((unsigned short*)challenge)[1] != 72) return 0;

    // Build the same block but with 32 bytes spare in front.
    if ((challenge2 = malloc(32 + 68)) == NULL) return 0;
    memcpy(challenge2 + 32, challenge + 4, 68);

    // Sign and build a response
    len = util_sign(cert, challenge2, 32 + 68, &sign);
    free(challenge2);
    if (len == 0 || sign == NULL) return 0;
    if ((block = malloc(len + 4)) == NULL) return 0;
    ((unsigned short*)block)[0] = PB_NODECRESPONSE;	// Block Type
    ((unsigned short*)block)[1] = (unsigned short)len + 4;			// Block Length
    memcpy(block + 4, sign, len);
    free(sign);

    *response = block;
    return len + 4;
}

// Checks a node challenge block, returns the node identifier
int ctrl_CheckNodeChallenge(char* secret, char* response, int len, char* nodeid, int* counter)
{
    int templen;
    char* temp = NULL;
    char* temp3 = NULL;
    struct util_cert cert;
    if (response == NULL || len < 8) return 0;
    if (((unsigned short*)response)[0] != PB_NODECRESPONSE) return -1;
    if (((unsigned short*)response)[1] != len) return -1;

    UNREFERENCED_PARAMETER( counter );

    // Check the signature
    templen = util_verify(response + 4, len - 4, &cert, &temp);
    if (temp == NULL) return 0;
    if (templen != 100) goto error; // Signature verification failed

    // Check the hash
    temp3 = ctrl_GetChallengeHash(temp + 32 + 36, secret, ((int*)(temp + 32))[0]);
    if (temp3 == NULL) goto error;
    if (memcmp(temp3, temp + 32 + 4, 32) != 0) goto error; // Failed the hash check

    // Get the node identifier
    util_keyhash(cert, nodeid);

    // Cleanup
    util_freecert(&cert);
    free(temp);
    free(temp3);

    return 0;

    //! \note commented out certification
error:
    //if (cert.pkey != NULL || cert.x509 != NULL) util_freecert(&cert);
    if (temp != NULL) free(temp);
    if (temp3 != NULL) free(temp3);
    return -1;
}

// Initiate a sync to another nodes Intel AMT.
// Intel AMT username and password will be fetched from database once we get the Intel AMT TLS certificate...
void ctrl_SyncToIntelAmt(int tls, struct sockaddr *addr, unsigned short port, char* nodeid, char* username, char* password)
{
    struct HttpRequestBlock* user;
    size_t len;

    // Setup the request
    if ((user = malloc(sizeof(struct HttpRequestBlock))) == NULL) ILIBCRITICALEXIT(254);
    memset(user, 0, sizeof(struct HttpRequestBlock));
    user->requesttype = 2;

    // Setup the target address
    if (addr->sa_family == AF_INET6) ((struct sockaddr_in6*)addr)->sin6_port = htons(port);
    if (addr->sa_family == AF_INET) ((struct sockaddr_in*)addr)->sin_port = htons(port);
    if ((user->addr = malloc(sizeof(struct sockaddr_in6))) == NULL) ILIBCRITICALEXIT(254);
    memcpy(user->addr, &addr, sizeof(struct sockaddr_in6));

    // Copy NodeID
    if ((user->nodeid = malloc(UTIL_HASHSIZE)) == NULL) ILIBCRITICALEXIT(254);
    memcpy(user->nodeid, nodeid, UTIL_HASHSIZE);

    // Copy username
    len = strlen(username) + 1;
    if ((user->username = malloc(len)) == NULL) ILIBCRITICALEXIT(254);
    memcpy(user->username, username, len);

    // Copy password
    len = strlen(password) + 1;
    if ((user->password = malloc(len)) == NULL) ILIBCRITICALEXIT(254);
    memcpy(user->password, password, len);

    // Update the target attempt time
    mdb_attempttarget((struct sockaddr*)&addr);

    // Send the request
    PerformHttpRequest(tls, (struct sockaddr*)&addr, "/index.htm", user, NULL, 0);
}

// Setup the local Intel(R) AMT admin username and password
void ctrl_SetLocalIntelAmtAdmin(int tls, char* username, char* password)
{
    // TODO: Verify that these setting are correct before storing.
    mdb_set_i("amt_tls", (tls==0)?0:1);
    mdb_set("amt_admin_user", username, (int)strlen(username));
    mdb_set("amt_admin_pass", password, (int)strlen(password));

    // TODO: Use the admin account to setup uguest account.
    mdb_set("amt_guest_user", username, (int)strlen(username));
    mdb_set("amt_guest_pass", password, (int)strlen(password));

    // Reset our current node info block
    ctrl_GetCurrentSignedNodeInfoBlock(NULL);
}

#ifdef WIN32
// Perform self-update (Windows console/tray version)
void ctrl_PerformSelfUpdate(char* selfpath, char* exepath)
{
    STARTUPINFOA info = {sizeof(info)};
    PROCESS_INFORMATION processInfo;

    // First, we wait a little to give time for the calling process to exit
    Sleep(5000);

    // Attempt to copy our own exe over the
    remove(exepath);
    CopyFileA(selfpath, exepath, FALSE);

    // Now run the process
    if (!CreateProcessA(NULL, exepath, NULL, NULL, TRUE, 0, NULL, NULL, &info, &processInfo))
    {
        // TODO: Failed to run update.
    }
}
#else
// Perform self-update (Linux version)
void ctrl_PerformSelfUpdate(char* selfpath, char* exepath)
{
    char temp[6000];

    // First, we wait a little to give time for the calling process to exit
    sleep(5);

    // Attempt to copy our own exe over the
    remove(exepath);
    snprintf(temp, 6000, "cp %s %s", selfpath, exepath);
    system(temp);

    // Now run the updated process
    snprintf(temp, 6000, "%s &", exepath);
    system(temp);
}
#endif

