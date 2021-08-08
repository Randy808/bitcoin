// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include <config/bitcoin-config.h>
#endif

#include <net.h>

#include <banman.h>
#include <clientversion.h>
#include <compat.h>
#include <consensus/consensus.h>
#include <crypto/sha256.h>
#include <i2p.h>
#include <net_permissions.h>
#include <netbase.h>
#include <node/ui_interface.h>
#include <protocol.h>
#include <random.h>
#include <scheduler.h>
#include <util/sock.h>
#include <util/strencodings.h>
#include <util/thread.h>
#include <util/translation.h>

#ifdef WIN32
#include <string.h>
#else
#include <fcntl.h>
#endif

#if HAVE_DECL_GETIFADDRS && HAVE_DECL_FREEIFADDRS
#include <ifaddrs.h>
#endif

#ifdef USE_POLL
#include <poll.h>
#endif

#include <algorithm>
#include <cstdint>
#include <functional>
#include <optional>
#include <unordered_map>

#include <math.h>

/** Maximum number of block-relay-only anchor connections */
static constexpr size_t MAX_BLOCK_RELAY_ONLY_ANCHORS = 2;
static_assert (MAX_BLOCK_RELAY_ONLY_ANCHORS <= static_cast<size_t>(MAX_BLOCK_RELAY_ONLY_CONNECTIONS), "MAX_BLOCK_RELAY_ONLY_ANCHORS must not exceed MAX_BLOCK_RELAY_ONLY_CONNECTIONS.");
/** Anchor IP address database file name */
const char* const ANCHORS_DATABASE_FILENAME = "anchors.dat";

// How often to dump addresses to peers.dat
static constexpr std::chrono::minutes DUMP_PEERS_INTERVAL{15};

/** Number of DNS seeds to query when the number of connections is low. */
static constexpr int DNSSEEDS_TO_QUERY_AT_ONCE = 3;

/** How long to delay before querying DNS seeds
 *
 * If we have more than THRESHOLD entries in addrman, then it's likely
 * that we got those addresses from having previously connected to the P2P
 * network, and that we'll be able to successfully reconnect to the P2P
 * network via contacting one of them. So if that's the case, spend a
 * little longer trying to connect to known peers before querying the
 * DNS seeds.
 */
static constexpr std::chrono::seconds DNSSEEDS_DELAY_FEW_PEERS{11};
static constexpr std::chrono::minutes DNSSEEDS_DELAY_MANY_PEERS{5};
static constexpr int DNSSEEDS_DELAY_PEER_THRESHOLD = 1000; // "many" vs "few" peers

/** The default timeframe for -maxuploadtarget. 1 day. */
static constexpr std::chrono::seconds MAX_UPLOAD_TIMEFRAME{60 * 60 * 24};

// We add a random period time (0 to 1 seconds) to feeler connections to prevent synchronization.
#define FEELER_SLEEP_WINDOW 1

/** Used to pass flags to the Bind() function */
enum BindFlags {
    BF_NONE         = 0,
    BF_EXPLICIT     = (1U << 0),
    BF_REPORT_ERROR = (1U << 1),
    /**
     * Do not call AddLocal() for our special addresses, e.g., for incoming
     * Tor connections, to prevent gossiping them over the network.
     */
    BF_DONT_ADVERTISE = (1U << 2),
};

// The set of sockets cannot be modified while waiting
// The sleep time needs to be small to avoid new sockets stalling
static const uint64_t SELECT_TIMEOUT_MILLISECONDS = 50;

const std::string NET_MESSAGE_COMMAND_OTHER = "*other*";

static const uint64_t RANDOMIZER_ID_NETGROUP = 0x6c0edd8036ef4036ULL; // SHA256("netgroup")[0:8]
static const uint64_t RANDOMIZER_ID_LOCALHOSTNONCE = 0xd93e69e2bbfa5735ULL; // SHA256("localhostnonce")[0:8]
static const uint64_t RANDOMIZER_ID_ADDRCACHE = 0x1cf2e4ddd306dda9ULL; // SHA256("addrcache")[0:8]
//
// Global state variables
//
bool fDiscover = true;
bool fListen = true;
RecursiveMutex cs_mapLocalHost;
std::map<CNetAddr, LocalServiceInfo> mapLocalHost GUARDED_BY(cs_mapLocalHost);
static bool vfLimited[NET_MAX] GUARDED_BY(cs_mapLocalHost) = {};
std::string strSubVersion;

void CConnman::AddAddrFetch(const std::string& strDest)
{
    LOCK(m_addr_fetches_mutex);
    m_addr_fetches.push_back(strDest);
}

//Gets an unsigned 16 bit integer representing a port parameter that was passed in on execution
uint16_t GetListenPort()
{
    return static_cast<uint16_t>(gArgs.GetArg("-port", Params().GetDefaultPort()));
}


//RANDY_COMMENTED
//BITCOIN_START
// find 'best' local address for a particular peer
//BITCOIN_END
bool GetLocal(CService& addr, const CNetAddr *paddrPeer)
{

    //If fListen isn't true
    if (!fListen)
        //Just return false
        return false;

    //Initialize a best score to -1
    int nBestScore = -1;
    //initialize bestReachability to a lowe number as well
    int nBestReachability = -1;
    {
        //lock in-memory local hosts?
        LOCK(cs_mapLocalHost);

        //For every entry in local host map
        for (const auto& entry : mapLocalHost)
        {
            //Make the score equal the nScore of that 'LocalServiceInfo' found in the map
            int nScore = entry.second.nScore;

            //Get a reachability score from the CNetAddr using parameter
            int nReachability = entry.first.GetReachabilityFrom(paddrPeer);

            //If reachability is greater than the best or the reachability is the same as the best but with a better score
            if (nReachability > nBestReachability || (nReachability == nBestReachability && nScore > nBestScore))
            {
                //Set the new best and set the 'addr' reference in the parameter to the current entry we're iterating with
                addr = CService(entry.first, entry.second.nPort);
                nBestReachability = nReachability;
                nBestScore = nScore;
            }
        }
    }

    //Return whether we were able to find at least one address that could override the default best score
    return nBestScore >= 0;
}

//RANDY COMMENTED
/*
Deserializes the seeds passed in and returns them in an output vector
*/
//BITCOIN_START
//! Convert the serialized seeds into usable address objects.
//BITCOIN_END
static std::vector<CAddress> ConvertSeeds(const std::vector<uint8_t> &vSeedsIn)
{
    //B
    // It'll only connect to one or two seed nodes because once it connects,
    // it'll get a pile of addresses with newer timestamps.
    // Seed nodes are given a random 'last seen time' of between one and two
    // weeks ago.
    //B_END

    //Create one week in seconds
    const int64_t nOneWeek = 7*24*60*60;

    //Create vector for seeds out
    std::vector<CAddress> vSeedsOut;

    //Create a random context
    FastRandomContext rng;

    //Create a steam that takes in vSeedsIn from the parameter and is sent to network?
    CDataStream s(vSeedsIn, SER_NETWORK, PROTOCOL_VERSION | ADDRV2_FORMAT);

    //While there remains information in the stream from seeds
    while (!s.eof()) {
        //Declare a CService
        CService endpoint;

        //give data from the stream to the endpoint
        //Or rather maybe it's just populate data of endpoint from stream
        s >> endpoint;

        //Declare an address representing endpoint?
        CAddress addr{endpoint, GetDesirableServiceFlags(NODE_NONE)};

        //Set the time of the address as the curent time minus one week and some change (randomly generated)
        addr.nTime = GetTime() - rng.randrange(nOneWeek) - nOneWeek;

        //Print out the address
        LogPrint(BCLog::NET, "Added hardcoded seed: %s\n", addr.ToString());

        //Add address to seeds out
        vSeedsOut.push_back(addr);
    }

    //Return vector of seeds converted to addresses
    return vSeedsOut;
}

// get best local address for a particular peer as a CAddress
// Otherwise, return the unroutable 0.0.0.0 but filled in with
// the normal parameters, since the IP may be changed to a useful
// one by discovery.
CAddress GetLocalAddress(const CNetAddr *paddrPeer, ServiceFlags nLocalServices)
{
    CAddress ret(CService(CNetAddr(),GetListenPort()), nLocalServices);
    CService addr;
    if (GetLocal(addr, paddrPeer))
    {
        ret = CAddress(addr, nLocalServices);
    }
    ret.nTime = GetAdjustedTime();
    return ret;
}

static int GetnScore(const CService& addr)
{
    LOCK(cs_mapLocalHost);
    if (mapLocalHost.count(addr) == 0) return 0;
    return mapLocalHost[addr].nScore;
}

// Is our peer's addrLocal potentially useful as an external IP source?
bool IsPeerAddrLocalGood(CNode *pnode)
{
    CService addrLocal = pnode->GetAddrLocal();
    return fDiscover && pnode->addr.IsRoutable() && addrLocal.IsRoutable() &&
           IsReachable(addrLocal.GetNetwork());
}

std::optional<CAddress> GetLocalAddrForPeer(CNode *pnode)
{
    CAddress addrLocal = GetLocalAddress(&pnode->addr, pnode->GetLocalServices());
    if (gArgs.GetBoolArg("-addrmantest", false)) {
        // use IPv4 loopback during addrmantest
        addrLocal = CAddress(CService(LookupNumeric("127.0.0.1", GetListenPort())), pnode->GetLocalServices());
    }
    // If discovery is enabled, sometimes give our peer the address it
    // tells us that it sees us as in case it has a better idea of our
    // address than we do.
    FastRandomContext rng;
    if (IsPeerAddrLocalGood(pnode) && (!addrLocal.IsRoutable() ||
         rng.randbits((GetnScore(addrLocal) > LOCAL_MANUAL) ? 3 : 1) == 0))
    {
        addrLocal.SetIP(pnode->GetAddrLocal());
    }
    if (addrLocal.IsRoutable() || gArgs.GetBoolArg("-addrmantest", false))
    {
        LogPrint(BCLog::NET, "Advertising address %s to peer=%d\n", addrLocal.ToString(), pnode->GetId());
        return addrLocal;
    }
    // Address is unroutable. Don't advertise.
    return std::nullopt;
}

// learn a new local address
bool AddLocal(const CService& addr, int nScore)
{
    if (!addr.IsRoutable())
        return false;

    if (!fDiscover && nScore < LOCAL_MANUAL)
        return false;

    if (!IsReachable(addr))
        return false;

    LogPrintf("AddLocal(%s,%i)\n", addr.ToString(), nScore);

    {
        LOCK(cs_mapLocalHost);
        bool fAlready = mapLocalHost.count(addr) > 0;
        LocalServiceInfo &info = mapLocalHost[addr];
        if (!fAlready || nScore >= info.nScore) {
            info.nScore = nScore + (fAlready ? 1 : 0);
            info.nPort = addr.GetPort();
        }
    }

    return true;
}

bool AddLocal(const CNetAddr &addr, int nScore)
{
    return AddLocal(CService(addr, GetListenPort()), nScore);
}

void RemoveLocal(const CService& addr)
{
    LOCK(cs_mapLocalHost);
    LogPrintf("RemoveLocal(%s)\n", addr.ToString());
    mapLocalHost.erase(addr);
}

void SetReachable(enum Network net, bool reachable)
{
    if (net == NET_UNROUTABLE || net == NET_INTERNAL)
        return;
    LOCK(cs_mapLocalHost);
    vfLimited[net] = !reachable;
}

bool IsReachable(enum Network net)
{
    LOCK(cs_mapLocalHost);
    return !vfLimited[net];
}

bool IsReachable(const CNetAddr &addr)
{
    return IsReachable(addr.GetNetwork());
}

/** vote for a local address */
bool SeenLocal(const CService& addr)
{
    {
        LOCK(cs_mapLocalHost);
        if (mapLocalHost.count(addr) == 0)
            return false;
        mapLocalHost[addr].nScore++;
    }
    return true;
}


/** check whether a given address is potentially local */
bool IsLocal(const CService& addr)
{
    LOCK(cs_mapLocalHost);
    return mapLocalHost.count(addr) > 0;
}

CNode* CConnman::FindNode(const CNetAddr& ip)
{
    LOCK(cs_vNodes);
    for (CNode* pnode : vNodes) {
      if (static_cast<CNetAddr>(pnode->addr) == ip) {
            return pnode;
        }
    }
    return nullptr;
}

CNode* CConnman::FindNode(const CSubNet& subNet)
{
    LOCK(cs_vNodes);
    for (CNode* pnode : vNodes) {
        if (subNet.Match(static_cast<CNetAddr>(pnode->addr))) {
            return pnode;
        }
    }
    return nullptr;
}

CNode* CConnman::FindNode(const std::string& addrName)
{
    LOCK(cs_vNodes);
    for (CNode* pnode : vNodes) {
        if (pnode->GetAddrName() == addrName) {
            return pnode;
        }
    }
    return nullptr;
}

CNode* CConnman::FindNode(const CService& addr)
{
    LOCK(cs_vNodes);
    for (CNode* pnode : vNodes) {
        if (static_cast<CService>(pnode->addr) == addr) {
            return pnode;
        }
    }
    return nullptr;
}

bool CConnman::AlreadyConnectedToAddress(const CAddress& addr)
{
    return FindNode(static_cast<CNetAddr>(addr)) || FindNode(addr.ToStringIPPort());
}

bool CConnman::CheckIncomingNonce(uint64_t nonce)
{
    LOCK(cs_vNodes);
    for (const CNode* pnode : vNodes) {
        if (!pnode->fSuccessfullyConnected && !pnode->IsInboundConn() && pnode->GetLocalNonce() == nonce)
            return false;
    }
    return true;
}

/** Get the bind address for a socket as CAddress */
static CAddress GetBindAddress(SOCKET sock)
{
    CAddress addr_bind;
    struct sockaddr_storage sockaddr_bind;
    socklen_t sockaddr_bind_len = sizeof(sockaddr_bind);
    if (sock != INVALID_SOCKET) {
        if (!getsockname(sock, (struct sockaddr*)&sockaddr_bind, &sockaddr_bind_len)) {
            addr_bind.SetSockAddr((const struct sockaddr*)&sockaddr_bind);
        } else {
            LogPrint(BCLog::NET, "Warning: getsockname failed\n");
        }
    }
    return addr_bind;
}

//TODO: COMMENT
//RANDY COMMENT
CNode* CConnman::ConnectNode(CAddress addrConnect, const char *pszDest, bool fCountFailure, ConnectionType conn_type)
{
    assert(conn_type != ConnectionType::INBOUND);

    if (pszDest == nullptr) {
        if (IsLocal(addrConnect))
            return nullptr;

        // Look for an existing connection
        CNode* pnode = FindNode(static_cast<CService>(addrConnect));
        if (pnode)
        {
            LogPrintf("Failed to open new connection, already connected\n");
            return nullptr;
        }
    }

    /// debug print
    LogPrint(BCLog::NET, "trying connection %s lastseen=%.1fhrs\n",
        pszDest ? pszDest : addrConnect.ToString(),
        pszDest ? 0.0 : (double)(GetAdjustedTime() - addrConnect.nTime)/3600.0);

    // Resolve
    const uint16_t default_port{Params().GetDefaultPort()};
    if (pszDest) {
        std::vector<CService> resolved;
        if (Lookup(pszDest, resolved,  default_port, fNameLookup && !HaveNameProxy(), 256) && !resolved.empty()) {
            addrConnect = CAddress(resolved[GetRand(resolved.size())], NODE_NONE);
            if (!addrConnect.IsValid()) {
                LogPrint(BCLog::NET, "Resolver returned invalid address %s for %s\n", addrConnect.ToString(), pszDest);
                return nullptr;
            }
            // It is possible that we already have a connection to the IP/port pszDest resolved to.
            // In that case, drop the connection that was just created, and return the existing CNode instead.
            // Also store the name we used to connect in that CNode, so that future FindNode() calls to that
            // name catch this early.
            LOCK(cs_vNodes);
            CNode* pnode = FindNode(static_cast<CService>(addrConnect));
            if (pnode)
            {
                pnode->MaybeSetAddrName(std::string(pszDest));
                LogPrintf("Failed to open new connection, already connected\n");
                return nullptr;
            }
        }
    }

    // Connect
    bool connected = false;
    std::unique_ptr<Sock> sock;
    proxyType proxy;
    CAddress addr_bind;
    assert(!addr_bind.IsValid());

    if (addrConnect.IsValid()) {
        bool proxyConnectionFailed = false;

        if (addrConnect.GetNetwork() == NET_I2P && m_i2p_sam_session.get() != nullptr) {
            i2p::Connection conn;
            if (m_i2p_sam_session->Connect(addrConnect, conn, proxyConnectionFailed)) {
                connected = true;
                sock = std::move(conn.sock);
                addr_bind = CAddress{conn.me, NODE_NONE};
            }
        } else if (GetProxy(addrConnect.GetNetwork(), proxy)) {
            sock = CreateSock(proxy.proxy);
            if (!sock) {
                return nullptr;
            }
            connected = ConnectThroughProxy(proxy, addrConnect.ToStringIP(), addrConnect.GetPort(),
                                            *sock, nConnectTimeout, proxyConnectionFailed);
        } else {
            // no proxy needed (none set for target network)
            sock = CreateSock(addrConnect);
            if (!sock) {
                return nullptr;
            }
            connected = ConnectSocketDirectly(addrConnect, *sock, nConnectTimeout,
                                              conn_type == ConnectionType::MANUAL);
        }
        if (!proxyConnectionFailed) {
            // If a connection to the node was attempted, and failure (if any) is not caused by a problem connecting to
            // the proxy, mark this as an attempt.
            addrman.Attempt(addrConnect, fCountFailure);
        }
    } else if (pszDest && GetNameProxy(proxy)) {
        sock = CreateSock(proxy.proxy);
        if (!sock) {
            return nullptr;
        }
        std::string host;
        uint16_t port{default_port};
        SplitHostPort(std::string(pszDest), port, host);
        bool proxyConnectionFailed;
        connected = ConnectThroughProxy(proxy, host, port, *sock, nConnectTimeout,
                                        proxyConnectionFailed);
    }
    if (!connected) {
        return nullptr;
    }

    // Add node
    NodeId id = GetNewNodeId();
    uint64_t nonce = GetDeterministicRandomizer(RANDOMIZER_ID_LOCALHOSTNONCE).Write(id).Finalize();
    if (!addr_bind.IsValid()) {
        addr_bind = GetBindAddress(sock->Get());
    }
    CNode* pnode = new CNode(id, nLocalServices, sock->Release(), addrConnect, CalculateKeyedNetGroup(addrConnect), nonce, addr_bind, pszDest ? pszDest : "", conn_type, /* inbound_onion */ false);
    pnode->AddRef();

    // We're making a new connection, harvest entropy from the time (and our peer count)
    RandAddEvent((uint32_t)id);

    return pnode;
}

void CNode::CloseSocketDisconnect()
{
    fDisconnect = true;
    LOCK(cs_hSocket);
    if (hSocket != INVALID_SOCKET)
    {
        LogPrint(BCLog::NET, "disconnecting peer=%d\n", id);
        CloseSocket(hSocket);
    }
}

void CConnman::AddWhitelistPermissionFlags(NetPermissionFlags& flags, const CNetAddr &addr) const {
    for (const auto& subnet : vWhitelistedRange) {
        if (subnet.m_subnet.Match(addr)) NetPermissions::AddFlag(flags, subnet.m_flags);
    }
}

std::string ConnectionTypeAsString(ConnectionType conn_type)
{
    switch (conn_type) {
    case ConnectionType::INBOUND:
        return "inbound";
    case ConnectionType::MANUAL:
        return "manual";
    case ConnectionType::FEELER:
        return "feeler";
    case ConnectionType::OUTBOUND_FULL_RELAY:
        return "outbound-full-relay";
    case ConnectionType::BLOCK_RELAY:
        return "block-relay-only";
    case ConnectionType::ADDR_FETCH:
        return "addr-fetch";
    } // no default case, so the compiler can warn about missing cases

    assert(false);
}

std::string CNode::GetAddrName() const {
    LOCK(cs_addrName);
    return addrName;
}

void CNode::MaybeSetAddrName(const std::string& addrNameIn) {
    LOCK(cs_addrName);
    if (addrName.empty()) {
        addrName = addrNameIn;
    }
}

CService CNode::GetAddrLocal() const {
    LOCK(cs_addrLocal);
    return addrLocal;
}

void CNode::SetAddrLocal(const CService& addrLocalIn) {
    LOCK(cs_addrLocal);
    if (addrLocal.IsValid()) {
        error("Addr local already set for node: %i. Refusing to change from %s to %s", id, addrLocal.ToString(), addrLocalIn.ToString());
    } else {
        addrLocal = addrLocalIn;
    }
}

Network CNode::ConnectedThroughNetwork() const
{
    return m_inbound_onion ? NET_ONION : addr.GetNetClass();
}

#undef X
#define X(name) stats.name = name
void CNode::copyStats(CNodeStats &stats, const std::vector<bool> &m_asmap)
{
    stats.nodeid = this->GetId();
    X(nServices);
    X(addr);
    X(addrBind);
    stats.m_network = ConnectedThroughNetwork();
    stats.m_mapped_as = addr.GetMappedAS(m_asmap);
    if (m_tx_relay != nullptr) {
        LOCK(m_tx_relay->cs_filter);
        stats.fRelayTxes = m_tx_relay->fRelayTxes;
    } else {
        stats.fRelayTxes = false;
    }
    X(nLastSend);
    X(nLastRecv);
    X(nLastTXTime);
    X(nLastBlockTime);
    X(nTimeConnected);
    X(nTimeOffset);
    stats.addrName = GetAddrName();
    X(nVersion);
    {
        LOCK(cs_SubVer);
        X(cleanSubVer);
    }
    stats.fInbound = IsInboundConn();
    X(m_bip152_highbandwidth_to);
    X(m_bip152_highbandwidth_from);
    {
        LOCK(cs_vSend);
        X(mapSendBytesPerMsgCmd);
        X(nSendBytes);
    }
    {
        LOCK(cs_vRecv);
        X(mapRecvBytesPerMsgCmd);
        X(nRecvBytes);
    }
    X(m_permissionFlags);
    if (m_tx_relay != nullptr) {
        stats.minFeeFilter = m_tx_relay->minFeeFilter;
    } else {
        stats.minFeeFilter = 0;
    }

    X(m_last_ping_time);
    X(m_min_ping_time);

    // Leave string empty if addrLocal invalid (not filled in yet)
    CService addrLocalUnlocked = GetAddrLocal();
    stats.addrLocal = addrLocalUnlocked.IsValid() ? addrLocalUnlocked.ToString() : "";

    X(m_conn_type);
}
#undef X

bool CNode::ReceiveMsgBytes(Span<const uint8_t> msg_bytes, bool& complete)
{
    complete = false;
    const auto time = GetTime<std::chrono::microseconds>();
    LOCK(cs_vRecv);
    nLastRecv = std::chrono::duration_cast<std::chrono::seconds>(time).count();
    nRecvBytes += msg_bytes.size();
    while (msg_bytes.size() > 0) {
        // absorb network data
        int handled = m_deserializer->Read(msg_bytes);
        if (handled < 0) {
            // Serious header problem, disconnect from the peer.
            return false;
        }

        if (m_deserializer->Complete()) {
            // decompose a transport agnostic CNetMessage from the deserializer
            uint32_t out_err_raw_size{0};
            std::optional<CNetMessage> result{m_deserializer->GetMessage(time, out_err_raw_size)};
            if (!result) {
                // Message deserialization failed.  Drop the message but don't disconnect the peer.
                // store the size of the corrupt message
                mapRecvBytesPerMsgCmd.find(NET_MESSAGE_COMMAND_OTHER)->second += out_err_raw_size;
                continue;
            }

            //store received bytes per message command
            //to prevent a memory DOS, only allow valid commands
            mapMsgCmdSize::iterator i = mapRecvBytesPerMsgCmd.find(result->m_command);
            if (i == mapRecvBytesPerMsgCmd.end())
                i = mapRecvBytesPerMsgCmd.find(NET_MESSAGE_COMMAND_OTHER);
            assert(i != mapRecvBytesPerMsgCmd.end());
            i->second += result->m_raw_message_size;

            // push the message to the process queue,
            vRecvMsg.push_back(std::move(*result));

            complete = true;
        }
    }

    return true;
}

int V1TransportDeserializer::readHeader(Span<const uint8_t> msg_bytes)
{
    // copy data to temporary parsing buffer
    unsigned int nRemaining = CMessageHeader::HEADER_SIZE - nHdrPos;
    unsigned int nCopy = std::min<unsigned int>(nRemaining, msg_bytes.size());

    memcpy(&hdrbuf[nHdrPos], msg_bytes.data(), nCopy);
    nHdrPos += nCopy;

    // if header incomplete, exit
    if (nHdrPos < CMessageHeader::HEADER_SIZE)
        return nCopy;

    // deserialize to CMessageHeader
    try {
        hdrbuf >> hdr;
    }
    catch (const std::exception&) {
        LogPrint(BCLog::NET, "Header error: Unable to deserialize, peer=%d\n", m_node_id);
        return -1;
    }

    // Check start string, network magic
    if (memcmp(hdr.pchMessageStart, m_chain_params.MessageStart(), CMessageHeader::MESSAGE_START_SIZE) != 0) {
        LogPrint(BCLog::NET, "Header error: Wrong MessageStart %s received, peer=%d\n", HexStr(hdr.pchMessageStart), m_node_id);
        return -1;
    }

    // reject messages larger than MAX_SIZE or MAX_PROTOCOL_MESSAGE_LENGTH
    if (hdr.nMessageSize > MAX_SIZE || hdr.nMessageSize > MAX_PROTOCOL_MESSAGE_LENGTH) {
        LogPrint(BCLog::NET, "Header error: Size too large (%s, %u bytes), peer=%d\n", SanitizeString(hdr.GetCommand()), hdr.nMessageSize, m_node_id);
        return -1;
    }

    // switch state to reading message data
    in_data = true;

    return nCopy;
}

int V1TransportDeserializer::readData(Span<const uint8_t> msg_bytes)
{
    unsigned int nRemaining = hdr.nMessageSize - nDataPos;
    unsigned int nCopy = std::min<unsigned int>(nRemaining, msg_bytes.size());

    if (vRecv.size() < nDataPos + nCopy) {
        // Allocate up to 256 KiB ahead, but never more than the total message size.
        vRecv.resize(std::min(hdr.nMessageSize, nDataPos + nCopy + 256 * 1024));
    }

    hasher.Write(msg_bytes.first(nCopy));
    memcpy(&vRecv[nDataPos], msg_bytes.data(), nCopy);
    nDataPos += nCopy;

    return nCopy;
}

const uint256& V1TransportDeserializer::GetMessageHash() const
{
    assert(Complete());
    if (data_hash.IsNull())
        hasher.Finalize(data_hash);
    return data_hash;
}

std::optional<CNetMessage> V1TransportDeserializer::GetMessage(const std::chrono::microseconds time, uint32_t& out_err_raw_size)
{
    // decompose a single CNetMessage from the TransportDeserializer
    std::optional<CNetMessage> msg(std::move(vRecv));

    // store command string, time, and sizes
    msg->m_command = hdr.GetCommand();
    msg->m_time = time;
    msg->m_message_size = hdr.nMessageSize;
    msg->m_raw_message_size = hdr.nMessageSize + CMessageHeader::HEADER_SIZE;

    uint256 hash = GetMessageHash();

    // We just received a message off the wire, harvest entropy from the time (and the message checksum)
    RandAddEvent(ReadLE32(hash.begin()));

    // Check checksum and header command string
    if (memcmp(hash.begin(), hdr.pchChecksum, CMessageHeader::CHECKSUM_SIZE) != 0) {
        LogPrint(BCLog::NET, "Header error: Wrong checksum (%s, %u bytes), expected %s was %s, peer=%d\n",
                 SanitizeString(msg->m_command), msg->m_message_size,
                 HexStr(Span<uint8_t>(hash.begin(), hash.begin() + CMessageHeader::CHECKSUM_SIZE)),
                 HexStr(hdr.pchChecksum),
                 m_node_id);
        out_err_raw_size = msg->m_raw_message_size;
        msg = std::nullopt;
    } else if (!hdr.IsCommandValid()) {
        LogPrint(BCLog::NET, "Header error: Invalid message type (%s, %u bytes), peer=%d\n",
                 SanitizeString(hdr.GetCommand()), msg->m_message_size, m_node_id);
        out_err_raw_size = msg->m_raw_message_size;
        msg.reset();
    }

    // Always reset the network deserializer (prepare for the next message)
    Reset();
    return msg;
}

void V1TransportSerializer::prepareForTransport(CSerializedNetMsg& msg, std::vector<unsigned char>& header) {
    // create dbl-sha256 checksum
    uint256 hash = Hash(msg.data);

    // create header
    CMessageHeader hdr(Params().MessageStart(), msg.m_type.c_str(), msg.data.size());
    memcpy(hdr.pchChecksum, hash.begin(), CMessageHeader::CHECKSUM_SIZE);

    // serialize header
    header.reserve(CMessageHeader::HEADER_SIZE);
    CVectorWriter{SER_NETWORK, INIT_PROTO_VERSION, header, 0, hdr};
}

//Sends queued data in the node parameter's vSendMsg character vector using the node's socket descriptor property and writes the metadata of the sent data to the node property
size_t CConnman::SocketSendData(CNode& node) const
{
    //Get iterator at start of send message queue (a char vector)
    auto it = node.vSendMsg.begin();

    //initialize size counter for how much data has been sent so far
    size_t nSentSize = 0;

    //While the iterator is not at the end of the send queue
    while (it != node.vSendMsg.end()) {
        //Dereference the iterator into data
        const auto& data = *it;
        //Make sure the data isn't bigger than the sendOffset
        assert(data.size() > node.nSendOffset);

        //Initi bytes to 0
        int nBytes = 0;
        {
            //Lock socket
            LOCK(node.cs_hSocket);

            //If socket file descriptor/id is invalid then break
            if (node.hSocket == INVALID_SOCKET)
                break;

            //Set the number of bytes that was able to be successfully sent
            nBytes = send(node.hSocket, reinterpret_cast<const char*>(data.data()) + node.nSendOffset, data.size() - node.nSendOffset, MSG_NOSIGNAL | MSG_DONTWAIT);
        }

        //If something was sent (size of sent data was bigger than 0)
        if (nBytes > 0) {
            //Set metadata for node of when things were last sent
            node.nLastSend = GetSystemTimeInSeconds();
            node.nSendBytes += nBytes;
            node.nSendOffset += nBytes;
            nSentSize += nBytes;

            //If all the data at the current iterator has been sent (should be a char since we're in char vec)
            if (node.nSendOffset == data.size()) {
                //Set sendOffset to 0
                node.nSendOffset = 0;

                //Subtract the size of data we just sent from sendSize
                node.nSendSize -= data.size();

                //Pause sending if the sendSize is bigger than the max size for what should be sent
                node.fPauseSend = node.nSendSize > nSendBufferMaxSize;
                //increment iterator
                it++;
            } else {
                //BITCOIN_START
                // could not send full message; stop sending more
                //BITCOIN_END
                break;
            }
        } else {
            //Error out if not able to send anything
            if (nBytes < 0) {
                // get the last error from error code
                int nErr = WSAGetLastError();

                //Log and close socket if error isn't recoverable (revisit)
                if (nErr != WSAEWOULDBLOCK && nErr != WSAEMSGSIZE && nErr != WSAEINTR && nErr != WSAEINPROGRESS) {
                    LogPrint(BCLog::NET, "socket send error for peer=%d: %s\n", node.GetId(), NetworkErrorString(nErr));
                    node.CloseSocketDisconnect();
                }
            }
            // couldn't send anything at all
            break;
        }
    }

    if (it == node.vSendMsg.end()) {
        assert(node.nSendOffset == 0);
        assert(node.nSendSize == 0);
    }

    //Erase what was sent from node's send queue
    node.vSendMsg.erase(node.vSendMsg.begin(), it);
    return nSentSize;
}

static bool ReverseCompareNodeMinPingTime(const NodeEvictionCandidate &a, const NodeEvictionCandidate &b)
{
    return a.m_min_ping_time > b.m_min_ping_time;
}

static bool ReverseCompareNodeTimeConnected(const NodeEvictionCandidate &a, const NodeEvictionCandidate &b)
{
    return a.nTimeConnected > b.nTimeConnected;
}

static bool CompareLocalHostTimeConnected(const NodeEvictionCandidate &a, const NodeEvictionCandidate &b)
{
    if (a.m_is_local != b.m_is_local) return b.m_is_local;
    return a.nTimeConnected > b.nTimeConnected;
}

static bool CompareOnionTimeConnected(const NodeEvictionCandidate& a, const NodeEvictionCandidate& b)
{
    if (a.m_is_onion != b.m_is_onion) return b.m_is_onion;
    return a.nTimeConnected > b.nTimeConnected;
}

static bool CompareNetGroupKeyed(const NodeEvictionCandidate &a, const NodeEvictionCandidate &b) {
    return a.nKeyedNetGroup < b.nKeyedNetGroup;
}

static bool CompareNodeBlockTime(const NodeEvictionCandidate &a, const NodeEvictionCandidate &b)
{
    // There is a fall-through here because it is common for a node to have many peers which have not yet relayed a block.
    if (a.nLastBlockTime != b.nLastBlockTime) return a.nLastBlockTime < b.nLastBlockTime;
    if (a.fRelevantServices != b.fRelevantServices) return b.fRelevantServices;
    return a.nTimeConnected > b.nTimeConnected;
}

static bool CompareNodeTXTime(const NodeEvictionCandidate &a, const NodeEvictionCandidate &b)
{
    // There is a fall-through here because it is common for a node to have more than a few peers that have not yet relayed txn.
    if (a.nLastTXTime != b.nLastTXTime) return a.nLastTXTime < b.nLastTXTime;
    if (a.fRelayTxes != b.fRelayTxes) return b.fRelayTxes;
    if (a.fBloomFilter != b.fBloomFilter) return a.fBloomFilter;
    return a.nTimeConnected > b.nTimeConnected;
}

// Pick out the potential block-relay only peers, and sort them by last block time.
static bool CompareNodeBlockRelayOnlyTime(const NodeEvictionCandidate &a, const NodeEvictionCandidate &b)
{
    if (a.fRelayTxes != b.fRelayTxes) return a.fRelayTxes;
    if (a.nLastBlockTime != b.nLastBlockTime) return a.nLastBlockTime < b.nLastBlockTime;
    if (a.fRelevantServices != b.fRelevantServices) return b.fRelevantServices;
    return a.nTimeConnected > b.nTimeConnected;
}

//! Sort an array by the specified comparator, then erase the last K elements where predicate is true.
template <typename T, typename Comparator>
static void EraseLastKElements(
    std::vector<T>& elements, Comparator comparator, size_t k,
    std::function<bool(const NodeEvictionCandidate&)> predicate = [](const NodeEvictionCandidate& n) { return true; })
{
    std::sort(elements.begin(), elements.end(), comparator);
    size_t eraseSize = std::min(k, elements.size());
    elements.erase(std::remove_if(elements.end() - eraseSize, elements.end(), predicate), elements.end());
}

void ProtectEvictionCandidatesByRatio(std::vector<NodeEvictionCandidate>& vEvictionCandidates)
{
    // Protect the half of the remaining nodes which have been connected the longest.
    // This replicates the non-eviction implicit behavior, and precludes attacks that start later.
    // To favorise the diversity of our peer connections, reserve up to (half + 2) of
    // these protected spots for onion and localhost peers, if any, even if they're not
    // longest uptime overall. This helps protect tor peers, which tend to be otherwise
    // disadvantaged under our eviction criteria.
    const size_t initial_size = vEvictionCandidates.size();
    size_t total_protect_size = initial_size / 2;
    const size_t onion_protect_size = total_protect_size / 2;

    if (onion_protect_size) {
        // Pick out up to 1/4 peers connected via our onion service, sorted by longest uptime.
        EraseLastKElements(vEvictionCandidates, CompareOnionTimeConnected, onion_protect_size,
                           [](const NodeEvictionCandidate& n) { return n.m_is_onion; });
    }

    const size_t localhost_min_protect_size{2};
    if (onion_protect_size >= localhost_min_protect_size) {
        // Allocate any remaining slots of the 1/4, or minimum 2 additional slots,
        // to localhost peers, sorted by longest uptime, as manually configured
        // hidden services not using `-bind=addr[:port]=onion` will not be detected
        // as inbound onion connections.
        const size_t remaining_tor_slots{onion_protect_size - (initial_size - vEvictionCandidates.size())};
        const size_t localhost_protect_size{std::max(remaining_tor_slots, localhost_min_protect_size)};
        EraseLastKElements(vEvictionCandidates, CompareLocalHostTimeConnected, localhost_protect_size,
                           [](const NodeEvictionCandidate& n) { return n.m_is_local; });
    }

    // Calculate how many we removed, and update our total number of peers that
    // we want to protect based on uptime accordingly.
    total_protect_size -= initial_size - vEvictionCandidates.size();
    EraseLastKElements(vEvictionCandidates, ReverseCompareNodeTimeConnected, total_protect_size);
}

[[nodiscard]] std::optional<NodeId> SelectNodeToEvict(std::vector<NodeEvictionCandidate>&& vEvictionCandidates)
{
    // Protect connections with certain characteristics

    // Deterministically select 4 peers to protect by netgroup.
    // An attacker cannot predict which netgroups will be protected
    EraseLastKElements(vEvictionCandidates, CompareNetGroupKeyed, 4);
    // Protect the 8 nodes with the lowest minimum ping time.
    // An attacker cannot manipulate this metric without physically moving nodes closer to the target.
    EraseLastKElements(vEvictionCandidates, ReverseCompareNodeMinPingTime, 8);
    // Protect 4 nodes that most recently sent us novel transactions accepted into our mempool.
    // An attacker cannot manipulate this metric without performing useful work.
    EraseLastKElements(vEvictionCandidates, CompareNodeTXTime, 4);
    // Protect up to 8 non-tx-relay peers that have sent us novel blocks.
    const size_t erase_size = std::min(size_t(8), vEvictionCandidates.size());
    EraseLastKElements(vEvictionCandidates, CompareNodeBlockRelayOnlyTime, erase_size,
                       [](const NodeEvictionCandidate& n) { return !n.fRelayTxes && n.fRelevantServices; });

    // Protect 4 nodes that most recently sent us novel blocks.
    // An attacker cannot manipulate this metric without performing useful work.
    EraseLastKElements(vEvictionCandidates, CompareNodeBlockTime, 4);

    // Protect some of the remaining eviction candidates by ratios of desirable
    // or disadvantaged characteristics.
    ProtectEvictionCandidatesByRatio(vEvictionCandidates);

    if (vEvictionCandidates.empty()) return std::nullopt;

    // If any remaining peers are preferred for eviction consider only them.
    // This happens after the other preferences since if a peer is really the best by other criteria (esp relaying blocks)
    //  then we probably don't want to evict it no matter what.
    if (std::any_of(vEvictionCandidates.begin(),vEvictionCandidates.end(),[](NodeEvictionCandidate const &n){return n.prefer_evict;})) {
        vEvictionCandidates.erase(std::remove_if(vEvictionCandidates.begin(),vEvictionCandidates.end(),
                                  [](NodeEvictionCandidate const &n){return !n.prefer_evict;}),vEvictionCandidates.end());
    }

    // Identify the network group with the most connections and youngest member.
    // (vEvictionCandidates is already sorted by reverse connect time)
    uint64_t naMostConnections;
    unsigned int nMostConnections = 0;
    int64_t nMostConnectionsTime = 0;
    std::map<uint64_t, std::vector<NodeEvictionCandidate> > mapNetGroupNodes;
    for (const NodeEvictionCandidate &node : vEvictionCandidates) {
        std::vector<NodeEvictionCandidate> &group = mapNetGroupNodes[node.nKeyedNetGroup];
        group.push_back(node);
        const int64_t grouptime = group[0].nTimeConnected;

        if (group.size() > nMostConnections || (group.size() == nMostConnections && grouptime > nMostConnectionsTime)) {
            nMostConnections = group.size();
            nMostConnectionsTime = grouptime;
            naMostConnections = node.nKeyedNetGroup;
        }
    }

    // Reduce to the network group with the most connections
    vEvictionCandidates = std::move(mapNetGroupNodes[naMostConnections]);

    // Disconnect from the network group with the most connections
    return vEvictionCandidates.front().id;
}

/** Try to find a connection to evict when the node is full.
 *  Extreme care must be taken to avoid opening the node to attacker
 *   triggered network partitioning.
 *  The strategy used here is to protect a small number of peers
 *   for each of several distinct characteristics which are difficult
 *   to forge.  In order to partition a node the attacker must be
 *   simultaneously better at all of them than honest peers.
 */

//RANDY_COMMENTED
//Add every node in vNodes as an eviciton candidate if it's an inbound connection and doesn't have permission to not be banned. Determine if a candidate should be evicted by calling the function 'SelectNodeToEvict' and retrieving a node id. If none of the nodes in vNodes have that id then return false, otherwise set the disconnect flag on the node to be evicted and return true.
bool CConnman::AttemptToEvictConnection()
{
    //Create a vector of object type 'NodeEvictionCandidate'
    std::vector<NodeEvictionCandidate> vEvictionCandidates;
    {
        //lock vNodes
        LOCK(cs_vNodes);

        //For every node in vnodes
        for (const CNode* node : vNodes) {
            //Continue if the node has permission to not be banned? (revisit)
            if (node->HasPermission(PF_NOBAN))
                continue;
            //Continue if the connecction to the node is not inbound
            if (!node->IsInboundConn())
                continue;

            //continue of the node is flagged for discocnnection
            if (node->fDisconnect)
                continue;

            //Initialze peer relay transactions? (revisit)
            bool peer_relay_txes = false;
            //Initialize the peer filter to *not* being not null (to being null)
            bool peer_filter_not_null = false;

            //If the node's m_tx_relay (revisit) isn't null
            if (node->m_tx_relay != nullptr) {
                //lock the node's transaction relay
                LOCK(node->m_tx_relay->cs_filter);
                //Set the peer relay transactions for this node to whatever is set on m_tx_relay
                peer_relay_txes = node->m_tx_relay->fRelayTxes;
                //See if there's a filter
                peer_filter_not_null = node->m_tx_relay->pfilter != nullptr;
            }

            //Create a candidate for eviction using node's properties
            NodeEvictionCandidate candidate = {node->GetId(), node->nTimeConnected, node->m_min_ping_time,
                                               node->nLastBlockTime, node->nLastTXTime,
                                               HasAllDesirableServiceFlags(node->nServices),
                                               peer_relay_txes, peer_filter_not_null, node->nKeyedNetGroup,
                                               node->m_prefer_evict, node->addr.IsLocal(),
                                               node->m_inbound_onion};

            //Add the candidate to eviction candidates
            vEvictionCandidates.push_back(candidate);
        }
    }

    //Create an optional nodeid type and the value it holds will be the value returned from SelectNodeToEvict (which is given candidates)
    const std::optional<NodeId> node_id_to_evict = SelectNodeToEvict(std::move(vEvictionCandidates));

    //If the optional is null/not-defined return false
    if (!node_id_to_evict) {
        return false;
    }

    //If there is a node to evict, lock the vNodes
    LOCK(cs_vNodes);

    //For every node in vNodes
    for (CNode* pnode : vNodes) {
        //If the id on the node is equal to the id to evict
        if (pnode->GetId() == *node_id_to_evict) {
            //log the connection type being evicted and their id
            LogPrint(BCLog::NET, "selected %s connection for eviction peer=%d; disconnecting\n", pnode->ConnectionTypeAsString(), pnode->GetId());

            //Set the disconnect flag to true
            pnode->fDisconnect = true;
            //and return true
            return true;
        }
    }

    //If the node wasn't found in vNodes, reurn false
    return false;
}

void CConnman::AcceptConnection(const ListenSocket& hListenSocket) {
    struct sockaddr_storage sockaddr;
    socklen_t len = sizeof(sockaddr);
    SOCKET hSocket = accept(hListenSocket.socket, (struct sockaddr*)&sockaddr, &len);
    CAddress addr;

    if (hSocket == INVALID_SOCKET) {
        const int nErr = WSAGetLastError();
        if (nErr != WSAEWOULDBLOCK) {
            LogPrintf("socket error accept failed: %s\n", NetworkErrorString(nErr));
        }
        return;
    }

    if (!addr.SetSockAddr((const struct sockaddr*)&sockaddr)) {
        LogPrintf("Warning: Unknown socket family\n");
    }

    const CAddress addr_bind = GetBindAddress(hSocket);

    NetPermissionFlags permissionFlags = NetPermissionFlags::PF_NONE;
    hListenSocket.AddSocketPermissionFlags(permissionFlags);

    CreateNodeFromAcceptedSocket(hSocket, permissionFlags, addr_bind, addr);
}

void CConnman::CreateNodeFromAcceptedSocket(SOCKET hSocket,
                                            NetPermissionFlags permissionFlags,
                                            const CAddress& addr_bind,
                                            const CAddress& addr)
{
    int nInbound = 0;
    int nMaxInbound = nMaxConnections - m_max_outbound;

    AddWhitelistPermissionFlags(permissionFlags, addr);
    if (NetPermissions::HasFlag(permissionFlags, NetPermissionFlags::PF_ISIMPLICIT)) {
        NetPermissions::ClearFlag(permissionFlags, PF_ISIMPLICIT);
        if (gArgs.GetBoolArg("-whitelistforcerelay", DEFAULT_WHITELISTFORCERELAY)) NetPermissions::AddFlag(permissionFlags, PF_FORCERELAY);
        if (gArgs.GetBoolArg("-whitelistrelay", DEFAULT_WHITELISTRELAY)) NetPermissions::AddFlag(permissionFlags, PF_RELAY);
        NetPermissions::AddFlag(permissionFlags, PF_MEMPOOL);
        NetPermissions::AddFlag(permissionFlags, PF_NOBAN);
    }

    {
        LOCK(cs_vNodes);
        for (const CNode* pnode : vNodes) {
            if (pnode->IsInboundConn()) nInbound++;
        }
    }

    if (!fNetworkActive) {
        LogPrint(BCLog::NET, "connection from %s dropped: not accepting new connections\n", addr.ToString());
        CloseSocket(hSocket);
        return;
    }

    if (!IsSelectableSocket(hSocket))
    {
        LogPrintf("connection from %s dropped: non-selectable socket\n", addr.ToString());
        CloseSocket(hSocket);
        return;
    }

    // According to the internet TCP_NODELAY is not carried into accepted sockets
    // on all platforms.  Set it again here just to be sure.
    SetSocketNoDelay(hSocket);

    // Don't accept connections from banned peers.
    bool banned = m_banman && m_banman->IsBanned(addr);
    if (!NetPermissions::HasFlag(permissionFlags, NetPermissionFlags::PF_NOBAN) && banned)
    {
        LogPrint(BCLog::NET, "connection from %s dropped (banned)\n", addr.ToString());
        CloseSocket(hSocket);
        return;
    }

    // Only accept connections from discouraged peers if our inbound slots aren't (almost) full.
    bool discouraged = m_banman && m_banman->IsDiscouraged(addr);
    if (!NetPermissions::HasFlag(permissionFlags, NetPermissionFlags::PF_NOBAN) && nInbound + 1 >= nMaxInbound && discouraged)
    {
        LogPrint(BCLog::NET, "connection from %s dropped (discouraged)\n", addr.ToString());
        CloseSocket(hSocket);
        return;
    }

    if (nInbound >= nMaxInbound)
    {
        if (!AttemptToEvictConnection()) {
            // No connection to evict, disconnect the new connection
            LogPrint(BCLog::NET, "failed to find an eviction candidate - connection dropped (full)\n");
            CloseSocket(hSocket);
            return;
        }
    }

    NodeId id = GetNewNodeId();
    uint64_t nonce = GetDeterministicRandomizer(RANDOMIZER_ID_LOCALHOSTNONCE).Write(id).Finalize();

    ServiceFlags nodeServices = nLocalServices;
    if (NetPermissions::HasFlag(permissionFlags, PF_BLOOMFILTER)) {
        nodeServices = static_cast<ServiceFlags>(nodeServices | NODE_BLOOM);
    }

    const bool inbound_onion = std::find(m_onion_binds.begin(), m_onion_binds.end(), addr_bind) != m_onion_binds.end();
    CNode* pnode = new CNode(id, nodeServices, hSocket, addr, CalculateKeyedNetGroup(addr), nonce, addr_bind, "", ConnectionType::INBOUND, inbound_onion);
    pnode->AddRef();
    pnode->m_permissionFlags = permissionFlags;
    pnode->m_prefer_evict = discouraged;
    m_msgproc->InitializeNode(pnode);

    LogPrint(BCLog::NET, "connection from %s accepted\n", addr.ToString());

    {
        LOCK(cs_vNodes);
        vNodes.push_back(pnode);
    }

    // We received a new connection, harvest entropy from the time (and our peer count)
    RandAddEvent((uint32_t)id);
}

bool CConnman::AddConnection(const std::string& address, ConnectionType conn_type)
{
    if (conn_type != ConnectionType::OUTBOUND_FULL_RELAY && conn_type != ConnectionType::BLOCK_RELAY) return false;

    const int max_connections = conn_type == ConnectionType::OUTBOUND_FULL_RELAY ? m_max_outbound_full_relay : m_max_outbound_block_relay;

    // Count existing connections
    int existing_connections = WITH_LOCK(cs_vNodes,
                                         return std::count_if(vNodes.begin(), vNodes.end(), [conn_type](CNode* node) { return node->m_conn_type == conn_type; }););

    // Max connections of specified type already exist
    if (existing_connections >= max_connections) return false;

    // Max total outbound connections already exist
    CSemaphoreGrant grant(*semOutbound, true);
    if (!grant) return false;

    OpenNetworkConnection(CAddress(), false, &grant, address.c_str(), conn_type);
    return true;
}

void CConnman::DisconnectNodes()
{
    {
        LOCK(cs_vNodes);

        if (!fNetworkActive) {
            // Disconnect any connected nodes
            for (CNode* pnode : vNodes) {
                if (!pnode->fDisconnect) {
                    LogPrint(BCLog::NET, "Network not active, dropping peer=%d\n", pnode->GetId());
                    pnode->fDisconnect = true;
                }
            }
        }

        // Disconnect unused nodes
        std::vector<CNode*> vNodesCopy = vNodes;
        for (CNode* pnode : vNodesCopy)
        {
            if (pnode->fDisconnect)
            {
                // remove from vNodes
                vNodes.erase(remove(vNodes.begin(), vNodes.end(), pnode), vNodes.end());

                // release outbound grant (if any)
                pnode->grantOutbound.Release();

                // close socket and cleanup
                pnode->CloseSocketDisconnect();

                // hold in disconnected pool until all refs are released
                pnode->Release();
                vNodesDisconnected.push_back(pnode);
            }
        }
    }
    {
        // Delete disconnected nodes
        std::list<CNode*> vNodesDisconnectedCopy = vNodesDisconnected;
        for (CNode* pnode : vNodesDisconnectedCopy)
        {
            // Destroy the object only after other threads have stopped using it.
            if (pnode->GetRefCount() <= 0) {
                vNodesDisconnected.remove(pnode);
                DeleteNode(pnode);
            }
        }
    }
}

void CConnman::NotifyNumConnectionsChanged()
{
    size_t vNodesSize;
    {
        LOCK(cs_vNodes);
        vNodesSize = vNodes.size();
    }
    if(vNodesSize != nPrevNodeCount) {
        nPrevNodeCount = vNodesSize;
        if(clientInterface)
            clientInterface->NotifyNumConnectionsChanged(vNodesSize);
    }
}

bool CConnman::ShouldRunInactivityChecks(const CNode& node, std::optional<int64_t> now_in) const
{
    const int64_t now = now_in ? now_in.value() : GetSystemTimeInSeconds();
    return node.nTimeConnected + m_peer_connect_timeout < now;
}

bool CConnman::InactivityCheck(const CNode& node) const
{
    // Use non-mockable system time (otherwise these timers will pop when we
    // use setmocktime in the tests).
    int64_t now = GetSystemTimeInSeconds();

    if (!ShouldRunInactivityChecks(node, now)) return false;

    if (node.nLastRecv == 0 || node.nLastSend == 0) {
        LogPrint(BCLog::NET, "socket no message in first %i seconds, %d %d peer=%d\n", m_peer_connect_timeout, node.nLastRecv != 0, node.nLastSend != 0, node.GetId());
        return true;
    }

    if (now > node.nLastSend + TIMEOUT_INTERVAL) {
        LogPrint(BCLog::NET, "socket sending timeout: %is peer=%d\n", now - node.nLastSend, node.GetId());
        return true;
    }

    if (now > node.nLastRecv + TIMEOUT_INTERVAL) {
        LogPrint(BCLog::NET, "socket receive timeout: %is peer=%d\n", now - node.nLastRecv, node.GetId());
        return true;
    }

    if (!node.fSuccessfullyConnected) {
        LogPrint(BCLog::NET, "version handshake timeout peer=%d\n", node.GetId());
        return true;
    }

    return false;
}

bool CConnman::GenerateSelectSet(std::set<SOCKET> &recv_set, std::set<SOCKET> &send_set, std::set<SOCKET> &error_set)
{
    for (const ListenSocket& hListenSocket : vhListenSocket) {
        recv_set.insert(hListenSocket.socket);
    }

    {
        LOCK(cs_vNodes);
        for (CNode* pnode : vNodes)
        {
            // Implement the following logic:
            // * If there is data to send, select() for sending data. As this only
            //   happens when optimistic write failed, we choose to first drain the
            //   write buffer in this case before receiving more. This avoids
            //   needlessly queueing received data, if the remote peer is not themselves
            //   receiving data. This means properly utilizing TCP flow control signalling.
            // * Otherwise, if there is space left in the receive buffer, select() for
            //   receiving data.
            // * Hand off all complete messages to the processor, to be handled without
            //   blocking here.

            bool select_recv = !pnode->fPauseRecv;
            bool select_send;
            {
                LOCK(pnode->cs_vSend);
                select_send = !pnode->vSendMsg.empty();
            }

            LOCK(pnode->cs_hSocket);
            if (pnode->hSocket == INVALID_SOCKET)
                continue;

            error_set.insert(pnode->hSocket);
            if (select_send) {
                send_set.insert(pnode->hSocket);
                continue;
            }
            if (select_recv) {
                recv_set.insert(pnode->hSocket);
            }
        }
    }

    return !recv_set.empty() || !send_set.empty() || !error_set.empty();
}

#ifdef USE_POLL
void CConnman::SocketEvents(std::set<SOCKET> &recv_set, std::set<SOCKET> &send_set, std::set<SOCKET> &error_set)
{
    std::set<SOCKET> recv_select_set, send_select_set, error_select_set;
    if (!GenerateSelectSet(recv_select_set, send_select_set, error_select_set)) {
        interruptNet.sleep_for(std::chrono::milliseconds(SELECT_TIMEOUT_MILLISECONDS));
        return;
    }

    std::unordered_map<SOCKET, struct pollfd> pollfds;
    for (SOCKET socket_id : recv_select_set) {
        pollfds[socket_id].fd = socket_id;
        pollfds[socket_id].events |= POLLIN;
    }

    for (SOCKET socket_id : send_select_set) {
        pollfds[socket_id].fd = socket_id;
        pollfds[socket_id].events |= POLLOUT;
    }

    for (SOCKET socket_id : error_select_set) {
        pollfds[socket_id].fd = socket_id;
        // These flags are ignored, but we set them for clarity
        pollfds[socket_id].events |= POLLERR|POLLHUP;
    }

    std::vector<struct pollfd> vpollfds;
    vpollfds.reserve(pollfds.size());
    for (auto it : pollfds) {
        vpollfds.push_back(std::move(it.second));
    }

    if (poll(vpollfds.data(), vpollfds.size(), SELECT_TIMEOUT_MILLISECONDS) < 0) return;

    if (interruptNet) return;

    for (struct pollfd pollfd_entry : vpollfds) {
        if (pollfd_entry.revents & POLLIN)            recv_set.insert(pollfd_entry.fd);
        if (pollfd_entry.revents & POLLOUT)           send_set.insert(pollfd_entry.fd);
        if (pollfd_entry.revents & (POLLERR|POLLHUP)) error_set.insert(pollfd_entry.fd);
    }
}
#else
void CConnman::SocketEvents(std::set<SOCKET> &recv_set, std::set<SOCKET> &send_set, std::set<SOCKET> &error_set)
{
    std::set<SOCKET> recv_select_set, send_select_set, error_select_set;
    if (!GenerateSelectSet(recv_select_set, send_select_set, error_select_set)) {
        interruptNet.sleep_for(std::chrono::milliseconds(SELECT_TIMEOUT_MILLISECONDS));
        return;
    }

    //
    // Find which sockets have data to receive
    //
    struct timeval timeout;
    timeout.tv_sec  = 0;
    timeout.tv_usec = SELECT_TIMEOUT_MILLISECONDS * 1000; // frequency to poll pnode->vSend

    fd_set fdsetRecv;
    fd_set fdsetSend;
    fd_set fdsetError;
    FD_ZERO(&fdsetRecv);
    FD_ZERO(&fdsetSend);
    FD_ZERO(&fdsetError);
    SOCKET hSocketMax = 0;

    for (SOCKET hSocket : recv_select_set) {
        FD_SET(hSocket, &fdsetRecv);
        hSocketMax = std::max(hSocketMax, hSocket);
    }

    for (SOCKET hSocket : send_select_set) {
        FD_SET(hSocket, &fdsetSend);
        hSocketMax = std::max(hSocketMax, hSocket);
    }

    for (SOCKET hSocket : error_select_set) {
        FD_SET(hSocket, &fdsetError);
        hSocketMax = std::max(hSocketMax, hSocket);
    }

    int nSelect = select(hSocketMax + 1, &fdsetRecv, &fdsetSend, &fdsetError, &timeout);

    if (interruptNet)
        return;

    if (nSelect == SOCKET_ERROR)
    {
        int nErr = WSAGetLastError();
        LogPrintf("socket select error %s\n", NetworkErrorString(nErr));
        for (unsigned int i = 0; i <= hSocketMax; i++)
            FD_SET(i, &fdsetRecv);
        FD_ZERO(&fdsetSend);
        FD_ZERO(&fdsetError);
        if (!interruptNet.sleep_for(std::chrono::milliseconds(SELECT_TIMEOUT_MILLISECONDS)))
            return;
    }

    for (SOCKET hSocket : recv_select_set) {
        if (FD_ISSET(hSocket, &fdsetRecv)) {
            recv_set.insert(hSocket);
        }
    }

    for (SOCKET hSocket : send_select_set) {
        if (FD_ISSET(hSocket, &fdsetSend)) {
            send_set.insert(hSocket);
        }
    }

    for (SOCKET hSocket : error_select_set) {
        if (FD_ISSET(hSocket, &fdsetError)) {
            error_set.insert(hSocket);
        }
    }
}
#endif

//RANDY_COMMENTED (revisit)
//Populates sets of sockets using 'SocketEvents' function and adds the valid sockets in the recv_set that are also in 'vhListenSocket'.
//Gets data from each node if it's in the recv_set or erorr_set and try to deserialize data for processing on every node. If no data was sent from the node or there's some other error, disconnect the nodes.
//If the node is inactive, disconnect the node
//If the node's socket is in the nodes of send_set, then send some data to those nodes
void CConnman::SocketHandler()
{
    //Create lots of sets of sockets
    std::set<SOCKET> recv_set, send_set, error_set;

    //Call Socket events method on the set of sockets that represent receive, send, and error socket sets
    SocketEvents(recv_set, send_set, error_set);

    //If the turn-off-network flag is enabled, just return
    if (interruptNet) return;

    //BITCOIN_START
    //
    // Accept new connections
    //
    //BITCOIN_END

    //For every  'ListenSocket' in 'vhListenSocket'
    for (const ListenSocket& hListenSocket : vhListenSocket)
    {
        //If the socket in the object hListenSocket is valid and the receive set has the listen socket
        if (hListenSocket.socket != INVALID_SOCKET && recv_set.count(hListenSocket.socket) > 0)
        {
            //Accept the connection from the listen socket
            AcceptConnection(hListenSocket);
        }
    }

    //BITCOIN_START
    //
    // Service each socket
    //
    //BITCOIN_END

    //Create a vector that'll act as a vnodes copy
    std::vector<CNode*> vNodesCopy;
    {
        //lock the vNodes vector carrying info of peers
        LOCK(cs_vNodes);
        //Copy over vector with assignment
        vNodesCopy = vNodes;

        //For every node in the vNodesCopy
        for (CNode* pnode : vNodesCopy)
            //Call 'AddRef' on the copied node reference.
            //This increments a counter in the node that represents how many places it's actively being referenced
            pnode->AddRef();
    }

    //For every node in the copy
    for (CNode* pnode : vNodesCopy)
    {
        //If the flag to disconnect network, return
        if (interruptNet)
            return;

        //BITCOIN_START
        //
        // Receive
        //
        //BITCOIN_END

        //Initialize bool for receive set to false
        bool recvSet = false;
        //Initialize bool for send set to false
        bool sendSet = false;
        //Initialize bool for error set to false
        bool errorSet = false;

        //Create a section to lock socket reference on node
        {
            //lock socket ref on node
            LOCK(pnode->cs_hSocket);

            //if the socket on the node is invalid, continue to next node
            if (pnode->hSocket == INVALID_SOCKET)
                continue;

            //If receive set has the socket, set recvSet bool to true
            recvSet = recv_set.count(pnode->hSocket) > 0;

            //if send_set vector has the node, set this bool too
            sendSet = send_set.count(pnode->hSocket) > 0;

            //See if this node's socket is in the error set
            errorSet = error_set.count(pnode->hSocket) > 0;
        }

        //if the node info being processed has a socket in the receive or error set
        if (recvSet || errorSet)
        {
            //BITCOIN_START
            // typical socket buffer is 8K-64K
            //BITCOIN_END

            //Make an array of uint8 to act as a buffer
            uint8_t pchBuf[0x10000];

            //Set nBytes to 0 (count of bytes received from node socket)
            int nBytes = 0;
            {
                //Lock the node's socket
                LOCK(pnode->cs_hSocket);
                //If the socket is invalid, continue
                if (pnode->hSocket == INVALID_SOCKET)
                    continue;

                //Get all the bytes in the socket from that node
                nBytes = recv(pnode->hSocket, (char*)pchBuf, sizeof(pchBuf), MSG_DONTWAIT);
            }

            //if some bytes were able to be received
            if (nBytes > 0)
            {
                //Initialize notify to false
                bool notify = false;

                //I think: If not able to deserialize and save the data onto node with 'ReceiveMsgBytes' (revisit)
                if (!pnode->ReceiveMsgBytes(Span<const uint8_t>(pchBuf, nBytes), notify))
                    //Close the socket
                    pnode->CloseSocketDisconnect();
                //Record how many bytes retrieved from node
                RecordBytesRecv(nBytes);

                //If notify was set to true from node's ReceiveMsgBytes method
                if (notify) {
                    //Initialize sizeAdded to 0
                    //This represents how much deserialized data we were able to get from the node
                    size_t nSizeAdded = 0;
                    //Make an iterator starting at vRecvMsg (which I believe is deserialized messages)
                    auto it(pnode->vRecvMsg.begin());

                    //For every 'CNetMessage' in the node's receive queue
                    for (; it != pnode->vRecvMsg.end(); ++it) {

                        //BITCOIN_START
                        // vRecvMsg contains only completed CNetMessage
                        // the single possible partially deserialized message are held by TransportDeserializer
                        //BITCOIN_END

                        //Add the message size
                        nSizeAdded += it->m_raw_message_size;
                    }
                    {
                        //Lock the processMsg on queue
                        LOCK(pnode->cs_vProcessMsg);
                        //Adds the items from vRecvMsg to vProcessMsg to get processed starting from beginning to where end iterator should be('it' should equal vRecvMsg.end() here)
                        pnode->vProcessMsg.splice(pnode->vProcessMsg.end(), pnode->vRecvMsg,
                        pnode->vRecvMsg.begin(), it);

                        //The queue to be processed has its size increased by data received from the node just processed
                        pnode->nProcessQueueSize += nSizeAdded;

                        //Let the pauseRecv flag on the node be triggered if the the things in the queue is bigger than the receive flood size
                        pnode->fPauseRecv = pnode->nProcessQueueSize > nReceiveFloodSize;
                    }
                    //Start processing the messages? (revisit)
                    WakeMessageHandler();
                }
            }
            //If there's no bytes to receive
            else if (nBytes == 0)
            {
                //BITOIN_START
                // socket closed gracefully
                //BITCOIN_END
                //Log if the node is not yet disconnected
                if (!pnode->fDisconnect) {
                    LogPrint(BCLog::NET, "socket closed for peer=%d\n", pnode->GetId());
                }

                //Disconnect node since there's nothing it's giving us
                pnode->CloseSocketDisconnect();
            }

            //If the bytes received is less than 0 it's just in error
            else if (nBytes < 0)
            {
                //BITCOIN_START
                // error
                //BITCOIN_END

                //Get last error code as integer
                int nErr = WSAGetLastError();

                //If the error code isn't one that can be recovered? (revisit)
                if (nErr != WSAEWOULDBLOCK && nErr != WSAEMSGSIZE && nErr != WSAEINTR && nErr != WSAEINPROGRESS)
                {
                    //Log if the node hasn't been disconnected already
                    if (!pnode->fDisconnect) {
                        LogPrint(BCLog::NET, "socket recv error for peer=%d: %s\n", pnode->GetId(), NetworkErrorString(nErr));
                    }

                    //Disconnect the node
                    pnode->CloseSocketDisconnect();
                }
            }
        }

        //If any sockes for nodes in VNodes are in the sendSet
        if (sendSet) {
            //BITCOIN_START
            // Send data
            //BITCOIN_END

            // lock the send buffer and send the data from that node
            size_t bytes_sent = WITH_LOCK(pnode->cs_vSend, return SocketSendData(*pnode));
            //Record bytes sent if non-zero
            if (bytes_sent) RecordBytesSent(bytes_sent);
        }

        //If the nodes are inactive, disconnect them
        if (InactivityCheck(*pnode)) pnode->fDisconnect = true;
    }
    {
        //Lock the vNodes array
        LOCK(cs_vNodes);
        //For every node in the node copy
        for (CNode* pnode : vNodesCopy)
            //call release on them (opposite of 'AddRef'?) (revisit)
            pnode->Release();
    }
}

//RANDY_COMMENTED (revisit)
void CConnman::ThreadSocketHandler()
{
    //As long as flag to stop networking activity isnt true
    while (!interruptNet)
    {
        //Disconect nodes
        DisconnectNodes();

        //Notify something about any disconnected nodes
        NotifyNumConnectionsChanged();

        //Call socket handler
        SocketHandler();
    }
}

void CConnman::WakeMessageHandler()
{
    {
        LOCK(mutexMsgProc);
        fMsgProcWake = true;
    }
    condMsgProc.notify_one();
}

//TODO: COMMENT
//RANDY_COMMENT
//Try to see if we should use all seeds vs sleectively pulling some to use.
//Look to see if nodes we have can be used as seeds
//If we have a name proxy or 'LookupHost' doesn't work, call 'AddAddrFetch'
//If 'LookupHost' does work, collect ips from DNS seeds
void CConnman::ThreadDNSAddressSeed()
{
    FastRandomContext rng;

    //Create a vector of strings and call it seeds.
    //Set it to 'Params().DNSSeeds();'
    //Params is a function that returns the global 'globalChainParams' of type CChainParams
    std::vector<std::string> seeds = Params().DNSSeeds();

    //Every elements successively gets swapped with a random element
    Shuffle(seeds.begin(), seeds.end(), rng);


    //BITCOIN_START
    // Number of seeds left before testing if we have enough connections
    //BITCOIN_END

    //Current number of seeds
    int seeds_right_now = 0;

    //number of seeds found
    int found = 0;

    //If the bitcoind arg forcedDnsSeed is true
    if (gArgs.GetBoolArg("-forcednsseed", DEFAULT_FORCEDNSSEED)) {
        //BITCOIN_START
        // When -forcednsseed is provided, query all.
        //BITCOIN_END

        //Set seeds right now to the total number of seeds in 'seeds'
        seeds_right_now = seeds.size();
    } else if (addrman.size() == 0) {

        //Even if the forcedDnsSeed isn't truw, iff the addrman.size is 0, then set seeds_right_now to 'seeds' size

        //BITCOIN_START
        // If we have no known peers, query all.
        // This will occur on the first run, or if peers.dat has been
        // deleted.
        //BITCOIN_END
        seeds_right_now = seeds.size();
    }

    //BITCOIN_START
    // goal: only query DNS seed if address need is acute
    // * If we have a reasonable number of peers in addrman, spend
    //   some time trying them first. This improves user privacy by
    //   creating fewer identifying DNS requests, reduces trust by
    //   giving seeds less influence on the network topology, and
    //   reduces traffic to the seeds.
    // * When querying DNS seeds query a few at once, this ensures
    //   that we don't give DNS seeds the ability to eclipse nodes
    //   that query them.
    // * If we continue having problems, eventually query all the
    //   DNS seeds, and if that fails too, also try the fixed seeds.
    //   (done in ThreadOpenConnections)
    //BITCOIN_END

    //Creae time value to represent a delay who's length depends on how many peers are detected
    const std::chrono::seconds seeds_wait_time = (addrman.size() >= DNSSEEDS_DELAY_PEER_THRESHOLD ? DNSSEEDS_DELAY_MANY_PEERS : DNSSEEDS_DELAY_FEW_PEERS);

    //For each string seed in 'seeds'
    for (const std::string& seed : seeds) {

        //If seeds right now is 0
        if (seeds_right_now == 0) {
            //Add the count of dns seeds we're about to query
            seeds_right_now += DNSSEEDS_TO_QUERY_AT_ONCE;

            //if addrman is bigger than 0 (i think represents 'peers')
            if (addrman.size() > 0) {
                //log
                LogPrintf("Waiting %d seconds before querying DNS seeds.\n", seeds_wait_time.count());
                //Add onto seeds_wait_time
                std::chrono::seconds to_wait = seeds_wait_time;

                //while seed wait time is greater than 0
                while (to_wait.count() > 0) {
                    //BITCOIN_START
                    // if sleeping for the MANY_PEERS interval, wake up
                    // early to see if we have enough peers and can stop
                    // this thread entirely freeing up its resources
                    //BITCOIN_END

                    //Keep trying to sleep for whatever is less, the delay time for few peers or original wait time
                    std::chrono::seconds w = std::min(DNSSEEDS_DELAY_FEW_PEERS, to_wait);
                    if (!interruptNet.sleep_for(w)) return;

                    //Subtract the time waited from wait time
                    to_wait -= w;

                    //Set relevant to 0
                    int nRelevant = 0;
                    {
                        //Lock the vNodes vector
                        LOCK(cs_vNodes);
                        //For every node in vNodes
                        for (const CNode* pnode : vNodes) {
                            //if the node we're looking at is successfully connected to us and
                            //the connection is outbound or blockrelay
                            if (pnode->fSuccessfullyConnected && pnode->IsOutboundOrBlockRelayConn())
                                //Add one to relevant
                                ++nRelevant;
                        }
                    }
                    //If 2 or more nodes have been marked as relevant
                    if (nRelevant >= 2) {
                        //If we've found more than one seed
                        if (found > 0) {
                            //Print that how any we've found
                            LogPrintf("%d addresses found from DNS seeds\n", found);
                            LogPrintf("P2P peers available. Finished DNS seeding.\n");
                        } else {
                            LogPrintf("P2P peers available. Skipped DNS seeding.\n");
                        }

                        //End the DNS seed search
                        return;
                    }
                }
            }
        }

        //If network flag is turned off, return
        if (interruptNet) return;

        //BITCOIN_START
        // hold off on querying seeds if P2P network deactivated
        //BITCOIN_END

        //If the network is not active
        if (!fNetworkActive) {
            //log
            LogPrintf("Waiting for network to be reactivated before querying DNS seeds.\n");
            do {
                //If the flag to turn off the network is still on then sleep until the network is active again
                if (!interruptNet.sleep_for(std::chrono::seconds{1})) return;
            } while (!fNetworkActive);
        }

        //log that we're going to look for addressed from DNS seed
        LogPrintf("Loading addresses from DNS seed %s\n", seed);

        //If the static variable 'nameProxy' is valud
        if (HaveNameProxy()) {
            //Add the seed we're looking at to 'm_addr_fetches'
            AddAddrFetch(seed);
        } else {
            //if we have no name proxy

            //Create a vector of ips
            std::vector<CNetAddr> vIPs;

            //Create a vector of abstract address objects
            std::vector<CAddress> vAdd;

            //Idk what this is (revisit)
            ServiceFlags requiredServiceBits = GetDesirableServiceFlags(NODE_NONE);

            //Set host to tje seed with some prefix using the 'requiredServiceBits'
            std::string host = strprintf("x%x.%s", requiredServiceBits, seed);

            //Create an address called 'resolveSource'
            CNetAddr resolveSource;

            //If the resolveAddress isn't able to be set to the host added
            if (!resolveSource.SetInternal(host)) {
                //then continue
                continue;
            }
            //Set maxIps to 256 which the comment says limits the ips we can learn from one dns url
            unsigned int nMaxIPs = 256; //B // Limits number of IPs learned from a DNS seed //B_END
            //If we're able to successfully look up the dns host
            if (LookupHost(host, vIPs, nMaxIPs, true)) {
                //for every ip returned for what I imagine is a DNS A record
                for (const CNetAddr& ip : vIPs) {
                    //Get one day in seconds
                    int nOneDay = 24*3600;
                    //Create an address object with that ip
                    CAddress addr = CAddress(CService(ip, Params().GetDefaultPort()), requiredServiceBits);
                    //Set the time on that address to the current time and subtract somewhere between 3 days and 7 days
                    addr.nTime = GetTime() - 3*nOneDay - rng.randrange(4*nOneDay);//B // use a random age between 3 and 7 days old //B_END

                    //Add the  the address to vAdd
                    vAdd.push_back(addr);
                    //Add onto found ip
                    found++;
                }
                //Add the ips to addrman with the associated DNS name
                addrman.Add(vAdd, resolveSource);
            } else {
                //BITCOIN_START
                // We now avoid directly using results from DNS Seeds which do not support service bit filtering,
                // instead using them as a addrfetch to get nodes with our desired service bits.
                //BITCOIN_END

                //From what I undertsand about the comment, this case occurs when the DNS seed doesn't support whaever addressing format that was being used. Instead we use it to call 'AddAddreFetch'
                AddAddrFetch(seed);
            }
        }
        --seeds_right_now;
    }
    LogPrintf("%d addresses found from DNS seeds\n", found);
}

void CConnman::DumpAddresses()
{
    int64_t nStart = GetTimeMillis();

    CAddrDB adb;
    adb.Write(addrman);

    LogPrint(BCLog::NET, "Flushed %d addresses to peers.dat  %dms\n",
           addrman.size(), GetTimeMillis() - nStart);
}

void CConnman::ProcessAddrFetch()
{
    std::string strDest;
    {
        LOCK(m_addr_fetches_mutex);
        if (m_addr_fetches.empty())
            return;
        strDest = m_addr_fetches.front();
        m_addr_fetches.pop_front();
    }
    CAddress addr;
    CSemaphoreGrant grant(*semOutbound, true);
    if (grant) {
        OpenNetworkConnection(addr, false, &grant, strDest.c_str(), ConnectionType::ADDR_FETCH);
    }
}

bool CConnman::GetTryNewOutboundPeer() const
{
    return m_try_another_outbound_peer;
}

void CConnman::SetTryNewOutboundPeer(bool flag)
{
    m_try_another_outbound_peer = flag;
    LogPrint(BCLog::NET, "net: setting try another outbound peer=%s\n", flag ? "true" : "false");
}

// Return the number of peers we have over our outbound connection limit
// Exclude peers that are marked for disconnect, or are going to be
// disconnected soon (eg ADDR_FETCH and FEELER)
// Also exclude peers that haven't finished initial connection handshake yet
// (so that we don't decide we're over our desired connection limit, and then
// evict some peer that has finished the handshake)
int CConnman::GetExtraFullOutboundCount() const
{
    int full_outbound_peers = 0;
    {
        LOCK(cs_vNodes);
        for (const CNode* pnode : vNodes) {
            if (pnode->fSuccessfullyConnected && !pnode->fDisconnect && pnode->IsFullOutboundConn()) {
                ++full_outbound_peers;
            }
        }
    }
    return std::max(full_outbound_peers - m_max_outbound_full_relay, 0);
}

int CConnman::GetExtraBlockRelayCount() const
{
    int block_relay_peers = 0;
    {
        LOCK(cs_vNodes);
        for (const CNode* pnode : vNodes) {
            if (pnode->fSuccessfullyConnected && !pnode->fDisconnect && pnode->IsBlockOnlyConn()) {
                ++block_relay_peers;
            }
        }
    }
    return std::max(block_relay_peers - m_max_outbound_block_relay, 0);
}

//RANDY_COMMENT
//TODO: COMMENT
void CConnman::ThreadOpenConnections(const std::vector<std::string> connect)
{
    // Connect to specific addresses
    if (!connect.empty())
    {
        for (int64_t nLoop = 0;; nLoop++)
        {
            ProcessAddrFetch();
            for (const std::string& strAddr : connect)
            {
                CAddress addr(CService(), NODE_NONE);
                OpenNetworkConnection(addr, false, nullptr, strAddr.c_str(), ConnectionType::MANUAL);
                for (int i = 0; i < 10 && i < nLoop; i++)
                {
                    if (!interruptNet.sleep_for(std::chrono::milliseconds(500)))
                        return;
                }
            }
            if (!interruptNet.sleep_for(std::chrono::milliseconds(500)))
                return;
        }
    }

    // Initiate network connections
    auto start = GetTime<std::chrono::microseconds>();

    // Minimum time before next feeler connection (in microseconds).
    auto next_feeler = PoissonNextSend(start, FEELER_INTERVAL);
    auto next_extra_block_relay = PoissonNextSend(start, EXTRA_BLOCK_RELAY_ONLY_PEER_INTERVAL);
    const bool dnsseed = gArgs.GetBoolArg("-dnsseed", DEFAULT_DNSSEED);
    bool add_fixed_seeds = gArgs.GetBoolArg("-fixedseeds", DEFAULT_FIXEDSEEDS);

    if (!add_fixed_seeds) {
        LogPrintf("Fixed seeds are disabled\n");
    }

    while (!interruptNet)
    {
        ProcessAddrFetch();

        if (!interruptNet.sleep_for(std::chrono::milliseconds(500)))
            return;

        CSemaphoreGrant grant(*semOutbound);
        if (interruptNet)
            return;

        if (add_fixed_seeds && addrman.size() == 0) {
            // When the node starts with an empty peers.dat, there are a few other sources of peers before
            // we fallback on to fixed seeds: -dnsseed, -seednode, -addnode
            // If none of those are available, we fallback on to fixed seeds immediately, else we allow
            // 60 seconds for any of those sources to populate addrman.
            bool add_fixed_seeds_now = false;
            // It is cheapest to check if enough time has passed first.
            if (GetTime<std::chrono::seconds>() > start + std::chrono::minutes{1}) {
                add_fixed_seeds_now = true;
                LogPrintf("Adding fixed seeds as 60 seconds have passed and addrman is empty\n");
            }

            // Checking !dnsseed is cheaper before locking 2 mutexes.
            if (!add_fixed_seeds_now && !dnsseed) {
                LOCK2(m_addr_fetches_mutex, cs_vAddedNodes);
                if (m_addr_fetches.empty() && vAddedNodes.empty()) {
                    add_fixed_seeds_now = true;
                    LogPrintf("Adding fixed seeds as -dnsseed=0, -addnode is not provided and all -seednode(s) attempted\n");
                }
            }

            if (add_fixed_seeds_now) {
                CNetAddr local;
                local.SetInternal("fixedseeds");
                addrman.Add(ConvertSeeds(Params().FixedSeeds()), local);
                add_fixed_seeds = false;
            }
        }

        //
        // Choose an address to connect to based on most recently seen
        //
        CAddress addrConnect;

        // Only connect out to one peer per network group (/16 for IPv4).
        int nOutboundFullRelay = 0;
        int nOutboundBlockRelay = 0;
        std::set<std::vector<unsigned char> > setConnected;

        {
            LOCK(cs_vNodes);
            for (const CNode* pnode : vNodes) {
                if (pnode->IsFullOutboundConn()) nOutboundFullRelay++;
                if (pnode->IsBlockOnlyConn()) nOutboundBlockRelay++;

                // Netgroups for inbound and manual peers are not excluded because our goal here
                // is to not use multiple of our limited outbound slots on a single netgroup
                // but inbound and manual peers do not use our outbound slots. Inbound peers
                // also have the added issue that they could be attacker controlled and used
                // to prevent us from connecting to particular hosts if we used them here.
                switch (pnode->m_conn_type) {
                    case ConnectionType::INBOUND:
                    case ConnectionType::MANUAL:
                        break;
                    case ConnectionType::OUTBOUND_FULL_RELAY:
                    case ConnectionType::BLOCK_RELAY:
                    case ConnectionType::ADDR_FETCH:
                    case ConnectionType::FEELER:
                        setConnected.insert(pnode->addr.GetGroup(addrman.m_asmap));
                } // no default case, so the compiler can warn about missing cases
            }
        }

        ConnectionType conn_type = ConnectionType::OUTBOUND_FULL_RELAY;
        auto now = GetTime<std::chrono::microseconds>();
        bool anchor = false;
        bool fFeeler = false;

        // Determine what type of connection to open. Opening
        // BLOCK_RELAY connections to addresses from anchors.dat gets the highest
        // priority. Then we open OUTBOUND_FULL_RELAY priority until we
        // meet our full-relay capacity. Then we open BLOCK_RELAY connection
        // until we hit our block-relay-only peer limit.
        // GetTryNewOutboundPeer() gets set when a stale tip is detected, so we
        // try opening an additional OUTBOUND_FULL_RELAY connection. If none of
        // these conditions are met, check to see if it's time to try an extra
        // block-relay-only peer (to confirm our tip is current, see below) or the next_feeler
        // timer to decide if we should open a FEELER.

        if (!m_anchors.empty() && (nOutboundBlockRelay < m_max_outbound_block_relay)) {
            conn_type = ConnectionType::BLOCK_RELAY;
            anchor = true;
        } else if (nOutboundFullRelay < m_max_outbound_full_relay) {
            // OUTBOUND_FULL_RELAY
        } else if (nOutboundBlockRelay < m_max_outbound_block_relay) {
            conn_type = ConnectionType::BLOCK_RELAY;
        } else if (GetTryNewOutboundPeer()) {
            // OUTBOUND_FULL_RELAY
        } else if (now > next_extra_block_relay && m_start_extra_block_relay_peers) {
            // Periodically connect to a peer (using regular outbound selection
            // methodology from addrman) and stay connected long enough to sync
            // headers, but not much else.
            //
            // Then disconnect the peer, if we haven't learned anything new.
            //
            // The idea is to make eclipse attacks very difficult to pull off,
            // because every few minutes we're finding a new peer to learn headers
            // from.
            //
            // This is similar to the logic for trying extra outbound (full-relay)
            // peers, except:
            // - we do this all the time on a poisson timer, rather than just when
            //   our tip is stale
            // - we potentially disconnect our next-youngest block-relay-only peer, if our
            //   newest block-relay-only peer delivers a block more recently.
            //   See the eviction logic in net_processing.cpp.
            //
            // Because we can promote these connections to block-relay-only
            // connections, they do not get their own ConnectionType enum
            // (similar to how we deal with extra outbound peers).
            next_extra_block_relay = PoissonNextSend(now, EXTRA_BLOCK_RELAY_ONLY_PEER_INTERVAL);
            conn_type = ConnectionType::BLOCK_RELAY;
        } else if (now > next_feeler) {
            next_feeler = PoissonNextSend(now, FEELER_INTERVAL);
            conn_type = ConnectionType::FEELER;
            fFeeler = true;
        } else {
            // skip to next iteration of while loop
            continue;
        }

        addrman.ResolveCollisions();

        int64_t nANow = GetAdjustedTime();
        int nTries = 0;
        while (!interruptNet)
        {
            if (anchor && !m_anchors.empty()) {
                const CAddress addr = m_anchors.back();
                m_anchors.pop_back();
                if (!addr.IsValid() || IsLocal(addr) || !IsReachable(addr) ||
                    !HasAllDesirableServiceFlags(addr.nServices) ||
                    setConnected.count(addr.GetGroup(addrman.m_asmap))) continue;
                addrConnect = addr;
                LogPrint(BCLog::NET, "Trying to make an anchor connection to %s\n", addrConnect.ToString());
                break;
            }

            // If we didn't find an appropriate destination after trying 100 addresses fetched from addrman,
            // stop this loop, and let the outer loop run again (which sleeps, adds seed nodes, recalculates
            // already-connected network ranges, ...) before trying new addrman addresses.
            nTries++;
            if (nTries > 100)
                break;

            CAddrInfo addr;

            if (fFeeler) {
                // First, try to get a tried table collision address. This returns
                // an empty (invalid) address if there are no collisions to try.
                addr = addrman.SelectTriedCollision();

                if (!addr.IsValid()) {
                    // No tried table collisions. Select a new table address
                    // for our feeler.
                    addr = addrman.Select(true);
                } else if (AlreadyConnectedToAddress(addr)) {
                    // If test-before-evict logic would have us connect to a
                    // peer that we're already connected to, just mark that
                    // address as Good(). We won't be able to initiate the
                    // connection anyway, so this avoids inadvertently evicting
                    // a currently-connected peer.
                    addrman.Good(addr);
                    // Select a new table address for our feeler instead.
                    addr = addrman.Select(true);
                }
            } else {
                // Not a feeler
                addr = addrman.Select();
            }

            // Require outbound connections, other than feelers, to be to distinct network groups
            if (!fFeeler && setConnected.count(addr.GetGroup(addrman.m_asmap))) {
                break;
            }

            // if we selected an invalid or local address, restart
            if (!addr.IsValid() || IsLocal(addr)) {
                break;
            }

            if (!IsReachable(addr))
                continue;

            // only consider very recently tried nodes after 30 failed attempts
            if (nANow - addr.nLastTry < 600 && nTries < 30)
                continue;

            // for non-feelers, require all the services we'll want,
            // for feelers, only require they be a full node (only because most
            // SPV clients don't have a good address DB available)
            if (!fFeeler && !HasAllDesirableServiceFlags(addr.nServices)) {
                continue;
            } else if (fFeeler && !MayHaveUsefulAddressDB(addr.nServices)) {
                continue;
            }

            // Do not allow non-default ports, unless after 50 invalid
            // addresses selected already. This is to prevent malicious peers
            // from advertising themselves as a service on another host and
            // port, causing a DoS attack as nodes around the network attempt
            // to connect to it fruitlessly.
            if (addr.GetPort() != Params().GetDefaultPort() && nTries < 50)
                continue;

            addrConnect = addr;
            break;
        }

        if (addrConnect.IsValid()) {

            if (fFeeler) {
                // Add small amount of random noise before connection to avoid synchronization.
                int randsleep = GetRandInt(FEELER_SLEEP_WINDOW * 1000);
                if (!interruptNet.sleep_for(std::chrono::milliseconds(randsleep)))
                    return;
                LogPrint(BCLog::NET, "Making feeler connection to %s\n", addrConnect.ToString());
            }

            OpenNetworkConnection(addrConnect, (int)setConnected.size() >= std::min(nMaxConnections - 1, 2), &grant, nullptr, conn_type);
        }
    }
}

std::vector<CAddress> CConnman::GetCurrentBlockRelayOnlyConns() const
{
    std::vector<CAddress> ret;
    LOCK(cs_vNodes);
    for (const CNode* pnode : vNodes) {
        if (pnode->IsBlockOnlyConn()) {
            ret.push_back(pnode->addr);
        }
    }

    return ret;
}

std::vector<AddedNodeInfo> CConnman::GetAddedNodeInfo() const
{
    std::vector<AddedNodeInfo> ret;

    std::list<std::string> lAddresses(0);
    {
        LOCK(cs_vAddedNodes);
        ret.reserve(vAddedNodes.size());
        std::copy(vAddedNodes.cbegin(), vAddedNodes.cend(), std::back_inserter(lAddresses));
    }


    // Build a map of all already connected addresses (by IP:port and by name) to inbound/outbound and resolved CService
    std::map<CService, bool> mapConnected;
    std::map<std::string, std::pair<bool, CService>> mapConnectedByName;
    {
        LOCK(cs_vNodes);
        for (const CNode* pnode : vNodes) {
            if (pnode->addr.IsValid()) {
                mapConnected[pnode->addr] = pnode->IsInboundConn();
            }
            std::string addrName = pnode->GetAddrName();
            if (!addrName.empty()) {
                mapConnectedByName[std::move(addrName)] = std::make_pair(pnode->IsInboundConn(), static_cast<const CService&>(pnode->addr));
            }
        }
    }

    for (const std::string& strAddNode : lAddresses) {
        CService service(LookupNumeric(strAddNode, Params().GetDefaultPort()));
        AddedNodeInfo addedNode{strAddNode, CService(), false, false};
        if (service.IsValid()) {
            // strAddNode is an IP:port
            auto it = mapConnected.find(service);
            if (it != mapConnected.end()) {
                addedNode.resolvedAddress = service;
                addedNode.fConnected = true;
                addedNode.fInbound = it->second;
            }
        } else {
            // strAddNode is a name
            auto it = mapConnectedByName.find(strAddNode);
            if (it != mapConnectedByName.end()) {
                addedNode.resolvedAddress = it->second.second;
                addedNode.fConnected = true;
                addedNode.fInbound = it->second.first;
            }
        }
        ret.emplace_back(std::move(addedNode));
    }

    return ret;
}

void CConnman::ThreadOpenAddedConnections()
{
    while (true)
    {
        CSemaphoreGrant grant(*semAddnode);
        std::vector<AddedNodeInfo> vInfo = GetAddedNodeInfo();
        bool tried = false;
        for (const AddedNodeInfo& info : vInfo) {
            if (!info.fConnected) {
                if (!grant.TryAcquire()) {
                    // If we've used up our semaphore and need a new one, let's not wait here since while we are waiting
                    // the addednodeinfo state might change.
                    break;
                }
                tried = true;
                CAddress addr(CService(), NODE_NONE);
                OpenNetworkConnection(addr, false, &grant, info.strAddedNode.c_str(), ConnectionType::MANUAL);
                if (!interruptNet.sleep_for(std::chrono::milliseconds(500)))
                    return;
            }
        }
        // Retry every 60 seconds if a connection was attempted, otherwise two seconds
        if (!interruptNet.sleep_for(std::chrono::seconds(tried ? 60 : 2)))
            return;
    }
}

//RANDY COMMENT
//TODO: COMMENT
// if successful, this moves the passed grant to the constructed node
void CConnman::OpenNetworkConnection(const CAddress& addrConnect, bool fCountFailure, CSemaphoreGrant *grantOutbound, const char *pszDest, ConnectionType conn_type)
{
    assert(conn_type != ConnectionType::INBOUND);

    //
    // Initiate outbound network connection
    //
    if (interruptNet) {
        return;
    }
    if (!fNetworkActive) {
        return;
    }
    if (!pszDest) {
        bool banned_or_discouraged = m_banman && (m_banman->IsDiscouraged(addrConnect) || m_banman->IsBanned(addrConnect));
        if (IsLocal(addrConnect) || banned_or_discouraged || AlreadyConnectedToAddress(addrConnect)) {
            return;
        }
    } else if (FindNode(std::string(pszDest)))
        return;

    CNode* pnode = ConnectNode(addrConnect, pszDest, fCountFailure, conn_type);

    if (!pnode)
        return;
    if (grantOutbound)
        grantOutbound->MoveTo(pnode->grantOutbound);

    m_msgproc->InitializeNode(pnode);
    {
        LOCK(cs_vNodes);
        vNodes.push_back(pnode);
    }
}

void CConnman::ThreadMessageHandler()
{
    while (!flagInterruptMsgProc)
    {
        std::vector<CNode*> vNodesCopy;
        {
            LOCK(cs_vNodes);
            vNodesCopy = vNodes;
            for (CNode* pnode : vNodesCopy) {
                pnode->AddRef();
            }
        }

        bool fMoreWork = false;

        for (CNode* pnode : vNodesCopy)
        {
            if (pnode->fDisconnect)
                continue;

            // Receive messages
            bool fMoreNodeWork = m_msgproc->ProcessMessages(pnode, flagInterruptMsgProc);
            fMoreWork |= (fMoreNodeWork && !pnode->fPauseSend);
            if (flagInterruptMsgProc)
                return;
            // Send messages
            {
                LOCK(pnode->cs_sendProcessing);
                m_msgproc->SendMessages(pnode);
            }

            if (flagInterruptMsgProc)
                return;
        }

        {
            LOCK(cs_vNodes);
            for (CNode* pnode : vNodesCopy)
                pnode->Release();
        }

        WAIT_LOCK(mutexMsgProc, lock);
        if (!fMoreWork) {
            condMsgProc.wait_until(lock, std::chrono::steady_clock::now() + std::chrono::milliseconds(100), [this]() EXCLUSIVE_LOCKS_REQUIRED(mutexMsgProc) { return fMsgProcWake; });
        }
        fMsgProcWake = false;
    }
}

void CConnman::ThreadI2PAcceptIncoming()
{
    static constexpr auto err_wait_begin = 1s;
    static constexpr auto err_wait_cap = 5min;
    auto err_wait = err_wait_begin;

    bool advertising_listen_addr = false;
    i2p::Connection conn;

    while (!interruptNet) {

        if (!m_i2p_sam_session->Listen(conn)) {
            if (advertising_listen_addr && conn.me.IsValid()) {
                RemoveLocal(conn.me);
                advertising_listen_addr = false;
            }

            interruptNet.sleep_for(err_wait);
            if (err_wait < err_wait_cap) {
                err_wait *= 2;
            }

            continue;
        }

        if (!advertising_listen_addr) {
            AddLocal(conn.me, LOCAL_MANUAL);
            advertising_listen_addr = true;
        }

        if (!m_i2p_sam_session->Accept(conn)) {
            continue;
        }

        CreateNodeFromAcceptedSocket(conn.sock->Release(), NetPermissionFlags::PF_NONE,
                                     CAddress{conn.me, NODE_NONE}, CAddress{conn.peer, NODE_NONE});
    }
}

bool CConnman::BindListenPort(const CService& addrBind, bilingual_str& strError, NetPermissionFlags permissions)
{
    int nOne = 1;

    // Create socket for listening for incoming connections
    struct sockaddr_storage sockaddr;
    socklen_t len = sizeof(sockaddr);
    if (!addrBind.GetSockAddr((struct sockaddr*)&sockaddr, &len))
    {
        strError = strprintf(Untranslated("Error: Bind address family for %s not supported"), addrBind.ToString());
        LogPrintf("%s\n", strError.original);
        return false;
    }

    std::unique_ptr<Sock> sock = CreateSock(addrBind);
    if (!sock) {
        strError = strprintf(Untranslated("Error: Couldn't open socket for incoming connections (socket returned error %s)"), NetworkErrorString(WSAGetLastError()));
        LogPrintf("%s\n", strError.original);
        return false;
    }

    // Allow binding if the port is still in TIME_WAIT state after
    // the program was closed and restarted.
    setsockopt(sock->Get(), SOL_SOCKET, SO_REUSEADDR, (sockopt_arg_type)&nOne, sizeof(int));

    // some systems don't have IPV6_V6ONLY but are always v6only; others do have the option
    // and enable it by default or not. Try to enable it, if possible.
    if (addrBind.IsIPv6()) {
#ifdef IPV6_V6ONLY
        setsockopt(sock->Get(), IPPROTO_IPV6, IPV6_V6ONLY, (sockopt_arg_type)&nOne, sizeof(int));
#endif
#ifdef WIN32
        int nProtLevel = PROTECTION_LEVEL_UNRESTRICTED;
        setsockopt(sock->Get(), IPPROTO_IPV6, IPV6_PROTECTION_LEVEL, (const char*)&nProtLevel, sizeof(int));
#endif
    }

    if (::bind(sock->Get(), (struct sockaddr*)&sockaddr, len) == SOCKET_ERROR)
    {
        int nErr = WSAGetLastError();
        if (nErr == WSAEADDRINUSE)
            strError = strprintf(_("Unable to bind to %s on this computer. %s is probably already running."), addrBind.ToString(), PACKAGE_NAME);
        else
            strError = strprintf(_("Unable to bind to %s on this computer (bind returned error %s)"), addrBind.ToString(), NetworkErrorString(nErr));
        LogPrintf("%s\n", strError.original);
        return false;
    }
    LogPrintf("Bound to %s\n", addrBind.ToString());

    // Listen for incoming connections
    if (listen(sock->Get(), SOMAXCONN) == SOCKET_ERROR)
    {
        strError = strprintf(_("Error: Listening for incoming connections failed (listen returned error %s)"), NetworkErrorString(WSAGetLastError()));
        LogPrintf("%s\n", strError.original);
        return false;
    }

    vhListenSocket.push_back(ListenSocket(sock->Release(), permissions));
    return true;
}

void Discover()
{
    if (!fDiscover)
        return;

#ifdef WIN32
    // Get local host IP
    char pszHostName[256] = "";
    if (gethostname(pszHostName, sizeof(pszHostName)) != SOCKET_ERROR)
    {
        std::vector<CNetAddr> vaddr;
        if (LookupHost(pszHostName, vaddr, 0, true))
        {
            for (const CNetAddr &addr : vaddr)
            {
                if (AddLocal(addr, LOCAL_IF))
                    LogPrintf("%s: %s - %s\n", __func__, pszHostName, addr.ToString());
            }
        }
    }
#elif (HAVE_DECL_GETIFADDRS && HAVE_DECL_FREEIFADDRS)
    // Get local host ip
    struct ifaddrs* myaddrs;
    if (getifaddrs(&myaddrs) == 0)
    {
        for (struct ifaddrs* ifa = myaddrs; ifa != nullptr; ifa = ifa->ifa_next)
        {
            if (ifa->ifa_addr == nullptr) continue;
            if ((ifa->ifa_flags & IFF_UP) == 0) continue;
            if (strcmp(ifa->ifa_name, "lo") == 0) continue;
            if (strcmp(ifa->ifa_name, "lo0") == 0) continue;
            if (ifa->ifa_addr->sa_family == AF_INET)
            {
                struct sockaddr_in* s4 = (struct sockaddr_in*)(ifa->ifa_addr);
                CNetAddr addr(s4->sin_addr);
                if (AddLocal(addr, LOCAL_IF))
                    LogPrintf("%s: IPv4 %s: %s\n", __func__, ifa->ifa_name, addr.ToString());
            }
            else if (ifa->ifa_addr->sa_family == AF_INET6)
            {
                struct sockaddr_in6* s6 = (struct sockaddr_in6*)(ifa->ifa_addr);
                CNetAddr addr(s6->sin6_addr);
                if (AddLocal(addr, LOCAL_IF))
                    LogPrintf("%s: IPv6 %s: %s\n", __func__, ifa->ifa_name, addr.ToString());
            }
        }
        freeifaddrs(myaddrs);
    }
#endif
}

void CConnman::SetNetworkActive(bool active)
{
    LogPrintf("%s: %s\n", __func__, active);

    if (fNetworkActive == active) {
        return;
    }

    fNetworkActive = active;

    uiInterface.NotifyNetworkActiveChanged(fNetworkActive);
}

CConnman::CConnman(uint64_t nSeed0In, uint64_t nSeed1In, CAddrMan& addrman_in, bool network_active)
    : addrman(addrman_in), nSeed0(nSeed0In), nSeed1(nSeed1In)
{
    SetTryNewOutboundPeer(false);

    Options connOptions;
    Init(connOptions);
    SetNetworkActive(network_active);
}

NodeId CConnman::GetNewNodeId()
{
    return nLastNodeId.fetch_add(1, std::memory_order_relaxed);
}


bool CConnman::Bind(const CService &addr, unsigned int flags, NetPermissionFlags permissions) {
    if (!(flags & BF_EXPLICIT) && !IsReachable(addr)) {
        return false;
    }
    bilingual_str strError;
    if (!BindListenPort(addr, strError, permissions)) {
        if ((flags & BF_REPORT_ERROR) && clientInterface) {
            clientInterface->ThreadSafeMessageBox(strError, "", CClientUIInterface::MSG_ERROR);
        }
        return false;
    }

    if (addr.IsRoutable() && fDiscover && !(flags & BF_DONT_ADVERTISE) && !NetPermissions::HasFlag(permissions, NetPermissionFlags::PF_NOBAN)) {
        AddLocal(addr, LOCAL_BIND);
    }

    return true;
}

bool CConnman::InitBinds(
    const std::vector<CService>& binds,
    const std::vector<NetWhitebindPermissions>& whiteBinds,
    const std::vector<CService>& onion_binds)
{
    bool fBound = false;
    for (const auto& addrBind : binds) {
        fBound |= Bind(addrBind, (BF_EXPLICIT | BF_REPORT_ERROR), NetPermissionFlags::PF_NONE);
    }
    for (const auto& addrBind : whiteBinds) {
        fBound |= Bind(addrBind.m_service, (BF_EXPLICIT | BF_REPORT_ERROR), addrBind.m_flags);
    }
    if (binds.empty() && whiteBinds.empty()) {
        struct in_addr inaddr_any;
        inaddr_any.s_addr = htonl(INADDR_ANY);
        struct in6_addr inaddr6_any = IN6ADDR_ANY_INIT;
        fBound |= Bind(CService(inaddr6_any, GetListenPort()), BF_NONE, NetPermissionFlags::PF_NONE);
        fBound |= Bind(CService(inaddr_any, GetListenPort()), !fBound ? BF_REPORT_ERROR : BF_NONE, NetPermissionFlags::PF_NONE);
    }

    for (const auto& addr_bind : onion_binds) {
        fBound |= Bind(addr_bind, BF_EXPLICIT | BF_DONT_ADVERTISE, NetPermissionFlags::PF_NONE);
    }

    return fBound;
}

bool CConnman::Start(CScheduler& scheduler, const Options& connOptions)
{
    Init(connOptions);

    if (fListen && !InitBinds(connOptions.vBinds, connOptions.vWhiteBinds, connOptions.onion_binds)) {
        if (clientInterface) {
            clientInterface->ThreadSafeMessageBox(
                _("Failed to listen on any port. Use -listen=0 if you want this."),
                "", CClientUIInterface::MSG_ERROR);
        }
        return false;
    }

    proxyType i2p_sam;
    if (GetProxy(NET_I2P, i2p_sam)) {
        m_i2p_sam_session = std::make_unique<i2p::sam::Session>(GetDataDir() / "i2p_private_key",
                                                                i2p_sam.proxy, &interruptNet);
    }

    for (const auto& strDest : connOptions.vSeedNodes) {
        AddAddrFetch(strDest);
    }

    if (clientInterface) {
        clientInterface->InitMessage(_("Loading P2P addresses…").translated);
    }
    // Load addresses from peers.dat
    int64_t nStart = GetTimeMillis();
    {
        CAddrDB adb;
        if (adb.Read(addrman))
            LogPrintf("Loaded %i addresses from peers.dat  %dms\n", addrman.size(), GetTimeMillis() - nStart);
        else {
            addrman.Clear(); // Addrman can be in an inconsistent state after failure, reset it
            LogPrintf("Recreating peers.dat\n");
            DumpAddresses();
        }
    }

    if (m_use_addrman_outgoing) {
        // Load addresses from anchors.dat
        m_anchors = ReadAnchors(GetDataDir() / ANCHORS_DATABASE_FILENAME);
        if (m_anchors.size() > MAX_BLOCK_RELAY_ONLY_ANCHORS) {
            m_anchors.resize(MAX_BLOCK_RELAY_ONLY_ANCHORS);
        }
        LogPrintf("%i block-relay-only anchors will be tried for connections.\n", m_anchors.size());
    }

    uiInterface.InitMessage(_("Starting network threads…").translated);

    fAddressesInitialized = true;

    if (semOutbound == nullptr) {
        // initialize semaphore
        semOutbound = std::make_unique<CSemaphore>(std::min(m_max_outbound, nMaxConnections));
    }
    if (semAddnode == nullptr) {
        // initialize semaphore
        semAddnode = std::make_unique<CSemaphore>(nMaxAddnode);
    }

    //
    // Start threads
    //
    assert(m_msgproc);
    InterruptSocks5(false);
    interruptNet.reset();
    flagInterruptMsgProc = false;

    {
        LOCK(mutexMsgProc);
        fMsgProcWake = false;
    }

    // Send and receive from sockets, accept connections
    threadSocketHandler = std::thread(&util::TraceThread, "net", [this] { ThreadSocketHandler(); });

    if (!gArgs.GetBoolArg("-dnsseed", DEFAULT_DNSSEED))
        LogPrintf("DNS seeding disabled\n");
    else
        threadDNSAddressSeed = std::thread(&util::TraceThread, "dnsseed", [this] { ThreadDNSAddressSeed(); });

    // Initiate manual connections
    threadOpenAddedConnections = std::thread(&util::TraceThread, "addcon", [this] { ThreadOpenAddedConnections(); });

    if (connOptions.m_use_addrman_outgoing && !connOptions.m_specified_outgoing.empty()) {
        if (clientInterface) {
            clientInterface->ThreadSafeMessageBox(
                _("Cannot provide specific connections and have addrman find outgoing connections at the same."),
                "", CClientUIInterface::MSG_ERROR);
        }
        return false;
    }
    if (connOptions.m_use_addrman_outgoing || !connOptions.m_specified_outgoing.empty()) {
        threadOpenConnections = std::thread(
            &util::TraceThread, "opencon",
            [this, connect = connOptions.m_specified_outgoing] { ThreadOpenConnections(connect); });
    }

    // Process messages
    threadMessageHandler = std::thread(&util::TraceThread, "msghand", [this] { ThreadMessageHandler(); });

    if (connOptions.m_i2p_accept_incoming && m_i2p_sam_session.get() != nullptr) {
        threadI2PAcceptIncoming =
            std::thread(&util::TraceThread, "i2paccept", [this] { ThreadI2PAcceptIncoming(); });
    }

    // Dump network addresses
    scheduler.scheduleEvery([this] { DumpAddresses(); }, DUMP_PEERS_INTERVAL);

    return true;
}

class CNetCleanup
{
public:
    CNetCleanup() {}

    ~CNetCleanup()
    {
#ifdef WIN32
        // Shutdown Windows Sockets
        WSACleanup();
#endif
    }
};
static CNetCleanup instance_of_cnetcleanup;

void CConnman::Interrupt()
{
    {
        LOCK(mutexMsgProc);
        flagInterruptMsgProc = true;
    }
    condMsgProc.notify_all();

    interruptNet();
    InterruptSocks5(true);

    if (semOutbound) {
        for (int i=0; i<m_max_outbound; i++) {
            semOutbound->post();
        }
    }

    if (semAddnode) {
        for (int i=0; i<nMaxAddnode; i++) {
            semAddnode->post();
        }
    }
}

void CConnman::StopThreads()
{
    if (threadI2PAcceptIncoming.joinable()) {
        threadI2PAcceptIncoming.join();
    }
    if (threadMessageHandler.joinable())
        threadMessageHandler.join();
    if (threadOpenConnections.joinable())
        threadOpenConnections.join();
    if (threadOpenAddedConnections.joinable())
        threadOpenAddedConnections.join();
    if (threadDNSAddressSeed.joinable())
        threadDNSAddressSeed.join();
    if (threadSocketHandler.joinable())
        threadSocketHandler.join();
}

void CConnman::StopNodes()
{
    if (fAddressesInitialized) {
        DumpAddresses();
        fAddressesInitialized = false;

        if (m_use_addrman_outgoing) {
            // Anchor connections are only dumped during clean shutdown.
            std::vector<CAddress> anchors_to_dump = GetCurrentBlockRelayOnlyConns();
            if (anchors_to_dump.size() > MAX_BLOCK_RELAY_ONLY_ANCHORS) {
                anchors_to_dump.resize(MAX_BLOCK_RELAY_ONLY_ANCHORS);
            }
            DumpAnchors(GetDataDir() / ANCHORS_DATABASE_FILENAME, anchors_to_dump);
        }
    }

    // Delete peer connections.
    std::vector<CNode*> nodes;
    WITH_LOCK(cs_vNodes, nodes.swap(vNodes));
    for (CNode* pnode : nodes) {
        pnode->CloseSocketDisconnect();
        DeleteNode(pnode);
    }

    // Close listening sockets.
    for (ListenSocket& hListenSocket : vhListenSocket) {
        if (hListenSocket.socket != INVALID_SOCKET) {
            if (!CloseSocket(hListenSocket.socket)) {
                LogPrintf("CloseSocket(hListenSocket) failed with error %s\n", NetworkErrorString(WSAGetLastError()));
            }
        }
    }

    for (CNode* pnode : vNodesDisconnected) {
        DeleteNode(pnode);
    }
    vNodesDisconnected.clear();
    vhListenSocket.clear();
    semOutbound.reset();
    semAddnode.reset();
}

void CConnman::DeleteNode(CNode* pnode)
{
    assert(pnode);
    m_msgproc->FinalizeNode(*pnode);
    delete pnode;
}

CConnman::~CConnman()
{
    Interrupt();
    Stop();
}

std::vector<CAddress> CConnman::GetAddresses(size_t max_addresses, size_t max_pct) const
{
    std::vector<CAddress> addresses = addrman.GetAddr(max_addresses, max_pct);
    if (m_banman) {
        addresses.erase(std::remove_if(addresses.begin(), addresses.end(),
                        [this](const CAddress& addr){return m_banman->IsDiscouraged(addr) || m_banman->IsBanned(addr);}),
                        addresses.end());
    }
    return addresses;
}

std::vector<CAddress> CConnman::GetAddresses(CNode& requestor, size_t max_addresses, size_t max_pct)
{
    auto local_socket_bytes = requestor.addrBind.GetAddrBytes();
    uint64_t cache_id = GetDeterministicRandomizer(RANDOMIZER_ID_ADDRCACHE)
        .Write(requestor.addr.GetNetwork())
        .Write(local_socket_bytes.data(), local_socket_bytes.size())
        .Finalize();
    const auto current_time = GetTime<std::chrono::microseconds>();
    auto r = m_addr_response_caches.emplace(cache_id, CachedAddrResponse{});
    CachedAddrResponse& cache_entry = r.first->second;
    if (cache_entry.m_cache_entry_expiration < current_time) { // If emplace() added new one it has expiration 0.
        cache_entry.m_addrs_response_cache = GetAddresses(max_addresses, max_pct);
        // Choosing a proper cache lifetime is a trade-off between the privacy leak minimization
        // and the usefulness of ADDR responses to honest users.
        //
        // Longer cache lifetime makes it more difficult for an attacker to scrape
        // enough AddrMan data to maliciously infer something useful.
        // By the time an attacker scraped enough AddrMan records, most of
        // the records should be old enough to not leak topology info by
        // e.g. analyzing real-time changes in timestamps.
        //
        // It takes only several hundred requests to scrape everything from an AddrMan containing 100,000 nodes,
        // so ~24 hours of cache lifetime indeed makes the data less inferable by the time
        // most of it could be scraped (considering that timestamps are updated via
        // ADDR self-announcements and when nodes communicate).
        // We also should be robust to those attacks which may not require scraping *full* victim's AddrMan
        // (because even several timestamps of the same handful of nodes may leak privacy).
        //
        // On the other hand, longer cache lifetime makes ADDR responses
        // outdated and less useful for an honest requestor, e.g. if most nodes
        // in the ADDR response are no longer active.
        //
        // However, the churn in the network is known to be rather low. Since we consider
        // nodes to be "terrible" (see IsTerrible()) if the timestamps are older than 30 days,
        // max. 24 hours of "penalty" due to cache shouldn't make any meaningful difference
        // in terms of the freshness of the response.
        cache_entry.m_cache_entry_expiration = current_time + std::chrono::hours(21) + GetRandMillis(std::chrono::hours(6));
    }
    return cache_entry.m_addrs_response_cache;
}

bool CConnman::AddNode(const std::string& strNode)
{
    LOCK(cs_vAddedNodes);
    for (const std::string& it : vAddedNodes) {
        if (strNode == it) return false;
    }

    vAddedNodes.push_back(strNode);
    return true;
}

bool CConnman::RemoveAddedNode(const std::string& strNode)
{
    LOCK(cs_vAddedNodes);
    for(std::vector<std::string>::iterator it = vAddedNodes.begin(); it != vAddedNodes.end(); ++it) {
        if (strNode == *it) {
            vAddedNodes.erase(it);
            return true;
        }
    }
    return false;
}

size_t CConnman::GetNodeCount(ConnectionDirection flags) const
{
    LOCK(cs_vNodes);
    if (flags == ConnectionDirection::Both) // Shortcut if we want total
        return vNodes.size();

    int nNum = 0;
    for (const auto& pnode : vNodes) {
        if (flags & (pnode->IsInboundConn() ? ConnectionDirection::In : ConnectionDirection::Out)) {
            nNum++;
        }
    }

    return nNum;
}

void CConnman::GetNodeStats(std::vector<CNodeStats>& vstats) const
{
    vstats.clear();
    LOCK(cs_vNodes);
    vstats.reserve(vNodes.size());
    for (CNode* pnode : vNodes) {
        vstats.emplace_back();
        pnode->copyStats(vstats.back(), addrman.m_asmap);
    }
}

bool CConnman::DisconnectNode(const std::string& strNode)
{
    LOCK(cs_vNodes);
    if (CNode* pnode = FindNode(strNode)) {
        LogPrint(BCLog::NET, "disconnect by address%s matched peer=%d; disconnecting\n", (fLogIPs ? strprintf("=%s", strNode) : ""), pnode->GetId());
        pnode->fDisconnect = true;
        return true;
    }
    return false;
}

bool CConnman::DisconnectNode(const CSubNet& subnet)
{
    bool disconnected = false;
    LOCK(cs_vNodes);
    for (CNode* pnode : vNodes) {
        if (subnet.Match(pnode->addr)) {
            LogPrint(BCLog::NET, "disconnect by subnet%s matched peer=%d; disconnecting\n", (fLogIPs ? strprintf("=%s", subnet.ToString()) : ""), pnode->GetId());
            pnode->fDisconnect = true;
            disconnected = true;
        }
    }
    return disconnected;
}

bool CConnman::DisconnectNode(const CNetAddr& addr)
{
    return DisconnectNode(CSubNet(addr));
}

bool CConnman::DisconnectNode(NodeId id)
{
    LOCK(cs_vNodes);
    for(CNode* pnode : vNodes) {
        if (id == pnode->GetId()) {
            LogPrint(BCLog::NET, "disconnect by id peer=%d; disconnecting\n", pnode->GetId());
            pnode->fDisconnect = true;
            return true;
        }
    }
    return false;
}

void CConnman::RecordBytesRecv(uint64_t bytes)
{
    LOCK(cs_totalBytesRecv);
    nTotalBytesRecv += bytes;
}

void CConnman::RecordBytesSent(uint64_t bytes)
{
    LOCK(cs_totalBytesSent);
    nTotalBytesSent += bytes;

    const auto now = GetTime<std::chrono::seconds>();
    if (nMaxOutboundCycleStartTime + MAX_UPLOAD_TIMEFRAME < now)
    {
        // timeframe expired, reset cycle
        nMaxOutboundCycleStartTime = now;
        nMaxOutboundTotalBytesSentInCycle = 0;
    }

    // TODO, exclude peers with download permission
    nMaxOutboundTotalBytesSentInCycle += bytes;
}

uint64_t CConnman::GetMaxOutboundTarget() const
{
    LOCK(cs_totalBytesSent);
    return nMaxOutboundLimit;
}

std::chrono::seconds CConnman::GetMaxOutboundTimeframe() const
{
    return MAX_UPLOAD_TIMEFRAME;
}

std::chrono::seconds CConnman::GetMaxOutboundTimeLeftInCycle() const
{
    LOCK(cs_totalBytesSent);
    if (nMaxOutboundLimit == 0)
        return 0s;

    if (nMaxOutboundCycleStartTime.count() == 0)
        return MAX_UPLOAD_TIMEFRAME;

    const std::chrono::seconds cycleEndTime = nMaxOutboundCycleStartTime + MAX_UPLOAD_TIMEFRAME;
    const auto now = GetTime<std::chrono::seconds>();
    return (cycleEndTime < now) ? 0s : cycleEndTime - now;
}

bool CConnman::OutboundTargetReached(bool historicalBlockServingLimit) const
{
    LOCK(cs_totalBytesSent);
    if (nMaxOutboundLimit == 0)
        return false;

    if (historicalBlockServingLimit)
    {
        // keep a large enough buffer to at least relay each block once
        const std::chrono::seconds timeLeftInCycle = GetMaxOutboundTimeLeftInCycle();
        const uint64_t buffer = timeLeftInCycle / std::chrono::minutes{10} * MAX_BLOCK_SERIALIZED_SIZE;
        if (buffer >= nMaxOutboundLimit || nMaxOutboundTotalBytesSentInCycle >= nMaxOutboundLimit - buffer)
            return true;
    }
    else if (nMaxOutboundTotalBytesSentInCycle >= nMaxOutboundLimit)
        return true;

    return false;
}

uint64_t CConnman::GetOutboundTargetBytesLeft() const
{
    LOCK(cs_totalBytesSent);
    if (nMaxOutboundLimit == 0)
        return 0;

    return (nMaxOutboundTotalBytesSentInCycle >= nMaxOutboundLimit) ? 0 : nMaxOutboundLimit - nMaxOutboundTotalBytesSentInCycle;
}

uint64_t CConnman::GetTotalBytesRecv() const
{
    LOCK(cs_totalBytesRecv);
    return nTotalBytesRecv;
}

uint64_t CConnman::GetTotalBytesSent() const
{
    LOCK(cs_totalBytesSent);
    return nTotalBytesSent;
}

ServiceFlags CConnman::GetLocalServices() const
{
    return nLocalServices;
}

unsigned int CConnman::GetReceiveFloodSize() const { return nReceiveFloodSize; }

CNode::CNode(NodeId idIn, ServiceFlags nLocalServicesIn, SOCKET hSocketIn, const CAddress& addrIn, uint64_t nKeyedNetGroupIn, uint64_t nLocalHostNonceIn, const CAddress& addrBindIn, const std::string& addrNameIn, ConnectionType conn_type_in, bool inbound_onion)
    : nTimeConnected(GetSystemTimeInSeconds()),
      addr(addrIn),
      addrBind(addrBindIn),
      m_inbound_onion(inbound_onion),
      nKeyedNetGroup(nKeyedNetGroupIn),
      id(idIn),
      nLocalHostNonce(nLocalHostNonceIn),
      m_conn_type(conn_type_in),
      nLocalServices(nLocalServicesIn)
{
    if (inbound_onion) assert(conn_type_in == ConnectionType::INBOUND);
    hSocket = hSocketIn;
    addrName = addrNameIn == "" ? addr.ToStringIPPort() : addrNameIn;
    if (conn_type_in != ConnectionType::BLOCK_RELAY) {
        m_tx_relay = std::make_unique<TxRelay>();
    }

    if (RelayAddrsWithConn()) {
        m_addr_known = std::make_unique<CRollingBloomFilter>(5000, 0.001);
    }

    for (const std::string &msg : getAllNetMessageTypes())
        mapRecvBytesPerMsgCmd[msg] = 0;
    mapRecvBytesPerMsgCmd[NET_MESSAGE_COMMAND_OTHER] = 0;

    if (fLogIPs) {
        LogPrint(BCLog::NET, "Added connection to %s peer=%d\n", addrName, id);
    } else {
        LogPrint(BCLog::NET, "Added connection peer=%d\n", id);
    }

    m_deserializer = std::make_unique<V1TransportDeserializer>(V1TransportDeserializer(Params(), GetId(), SER_NETWORK, INIT_PROTO_VERSION));
    m_serializer = std::make_unique<V1TransportSerializer>(V1TransportSerializer());
}

CNode::~CNode()
{
    CloseSocket(hSocket);
}

bool CConnman::NodeFullyConnected(const CNode* pnode)
{
    return pnode && pnode->fSuccessfullyConnected && !pnode->fDisconnect;
}

void CConnman::PushMessage(CNode* pnode, CSerializedNetMsg&& msg)
{
    size_t nMessageSize = msg.data.size();
    LogPrint(BCLog::NET, "sending %s (%d bytes) peer=%d\n",  SanitizeString(msg.m_type), nMessageSize, pnode->GetId());
    if (gArgs.GetBoolArg("-capturemessages", false)) {
        CaptureMessage(pnode->addr, msg.m_type, msg.data, /* incoming */ false);
    }

    // make sure we use the appropriate network transport format
    std::vector<unsigned char> serializedHeader;
    pnode->m_serializer->prepareForTransport(msg, serializedHeader);
    size_t nTotalSize = nMessageSize + serializedHeader.size();

    size_t nBytesSent = 0;
    {
        LOCK(pnode->cs_vSend);
        bool optimisticSend(pnode->vSendMsg.empty());

        //log total amount of bytes per message type
        pnode->mapSendBytesPerMsgCmd[msg.m_type] += nTotalSize;
        pnode->nSendSize += nTotalSize;

        if (pnode->nSendSize > nSendBufferMaxSize) pnode->fPauseSend = true;
        pnode->vSendMsg.push_back(std::move(serializedHeader));
        if (nMessageSize) pnode->vSendMsg.push_back(std::move(msg.data));

        // If write queue empty, attempt "optimistic write"
        if (optimisticSend) nBytesSent = SocketSendData(*pnode);
    }
    if (nBytesSent) RecordBytesSent(nBytesSent);
}

bool CConnman::ForNode(NodeId id, std::function<bool(CNode* pnode)> func)
{
    CNode* found = nullptr;
    LOCK(cs_vNodes);
    for (auto&& pnode : vNodes) {
        if(pnode->GetId() == id) {
            found = pnode;
            break;
        }
    }
    return found != nullptr && NodeFullyConnected(found) && func(found);
}

std::chrono::microseconds CConnman::PoissonNextSendInbound(std::chrono::microseconds now, std::chrono::seconds average_interval)
{
    if (m_next_send_inv_to_incoming.load() < now) {
        // If this function were called from multiple threads simultaneously
        // it would possible that both update the next send variable, and return a different result to their caller.
        // This is not possible in practice as only the net processing thread invokes this function.
        m_next_send_inv_to_incoming = PoissonNextSend(now, average_interval);
    }
    return m_next_send_inv_to_incoming;
}

std::chrono::microseconds PoissonNextSend(std::chrono::microseconds now, std::chrono::seconds average_interval)
{
    double unscaled = -log1p(GetRand(1ULL << 48) * -0.0000000000000035527136788 /* -1/2^48 */);
    return now + std::chrono::duration_cast<std::chrono::microseconds>(unscaled * average_interval + 0.5us);
}

CSipHasher CConnman::GetDeterministicRandomizer(uint64_t id) const
{
    return CSipHasher(nSeed0, nSeed1).Write(id);
}

uint64_t CConnman::CalculateKeyedNetGroup(const CAddress& ad) const
{
    std::vector<unsigned char> vchNetGroup(ad.GetGroup(addrman.m_asmap));

    return GetDeterministicRandomizer(RANDOMIZER_ID_NETGROUP).Write(vchNetGroup.data(), vchNetGroup.size()).Finalize();
}

void CaptureMessage(const CAddress& addr, const std::string& msg_type, const Span<const unsigned char>& data, bool is_incoming)
{
    // Note: This function captures the message at the time of processing,
    // not at socket receive/send time.
    // This ensures that the messages are always in order from an application
    // layer (processing) perspective.
    auto now = GetTime<std::chrono::microseconds>();

    // Windows folder names can not include a colon
    std::string clean_addr = addr.ToString();
    std::replace(clean_addr.begin(), clean_addr.end(), ':', '_');

    fs::path base_path = GetDataDir() / "message_capture" / clean_addr;
    fs::create_directories(base_path);

    fs::path path = base_path / (is_incoming ? "msgs_recv.dat" : "msgs_sent.dat");
    CAutoFile f(fsbridge::fopen(path, "ab"), SER_DISK, CLIENT_VERSION);

    ser_writedata64(f, now.count());
    f.write(msg_type.data(), msg_type.length());
    for (auto i = msg_type.length(); i < CMessageHeader::COMMAND_SIZE; ++i) {
        f << '\0';
    }
    uint32_t size = data.size();
    ser_writedata32(f, size);
    f.write((const char*)data.data(), data.size());
}
