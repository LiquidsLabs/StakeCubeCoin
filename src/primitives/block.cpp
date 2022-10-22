// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <primitives/block.h>
#include <consensus/params.h>
#include <chainparams.h>
#include "crypto/progpow.h"
#include <util/system.h>

#include <hash.h>
#include <streams.h>
#include <tinyformat.h>

uint256 CBlockHeader::GetHashFull(uint256& mix_hash) const {
    if (IsProgPow()) {
        return GetProgPowHashFull(mix_hash);
    }
    return GetHash();
}

uint256 CBlockHeader::GetPoWHash(int nHeight) const
{
    uint256 powHash, mix_hash;
    std::vector<unsigned char> vch(80);
    CVectorWriter ss(SER_GETHASH, PROTOCOL_VERSION, vch, 0);
    ss << *this;
    if(nHeight == 0) {
        return HashX11((const char *)vch.data(), (const char *)vch.data() + vch.size());
    }
    if (IsFirstProgPow()) {
        powHash = progpow_hash_full(GetProgPowHeader(), mix_hash);
        return powHash;
    } else if (IsProgPow()) {
        powHash = progpow_hash_light(GetProgPowHeader());
        return powHash;
    } else {
        return HashX11((const char *)vch.data(), (const char *)vch.data() + vch.size());
    }
}

bool CBlockHeader::IsProgPow() const {
    // In case if nTime == SCC_GEN_TIME we're being called from CChainParams() constructor and
    // it is not possible to get Params()
    return (nTime > SCC_GEN_TIME && nTime >= Params().GetConsensus().nPPSwitchTime);
}

bool CBlockHeader::IsFirstProgPow() const {
    return (IsProgPow() && nTime <= (Params().GetConsensus().nPPSwitchTime + 432000)); //1 hr 45 mins ish
}

CProgPowHeader CBlockHeader::GetProgPowHeader() const {
    return CProgPowHeader {
        nVersion,
        hashPrevBlock,
        hashMerkleRoot,
        nTime,
        nBits,
        nHeight,
        nNonce64,
        mix_hash
    };
}

uint256 CBlockHeader::GetProgPowHeaderHash() const
{
    return SerializeHash(GetProgPowHeader());
}

uint256 CBlockHeader::GetProgPowHashFull(uint256& mix_hash) const {
    return progpow_hash_full(GetProgPowHeader(), mix_hash);
}

uint256 CBlockHeader::GetProgPowHashLight() const {
    return progpow_hash_light(GetProgPowHeader());
}

uint256 CBlockHeader::GetHash() const {
    uint256 powHash;
    if (IsProgPow()) {
        if(IsFirstProgPow()) {
            uint256 mix_hash = Params().GetConsensus().powLimit;
            powHash = progpow_hash_full(GetProgPowHeader(), mix_hash);
        } else {
            powHash = progpow_hash_light(GetProgPowHeader());
        }
	return powHash;
    } else {
        std::vector<unsigned char> vch(80);
        CVectorWriter ss(SER_GETHASH, PROTOCOL_VERSION, vch, 0);
        ss << *this;
        return HashX11((const char *)vch.data(), (const char *)vch.data() + vch.size());
    }
}

std::string CBlock::ToString() const
{
    std::stringstream s;
    s << strprintf("CBlock(hash=%s, ver=0x%08x, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce=%u, nNonce64=%u, vtx=%u)\n",
        GetHash().ToString(),
        nVersion,
        hashPrevBlock.ToString(),
        hashMerkleRoot.ToString(),
        nTime, nBits, nNonce, nNonce64,
        vtx.size());
    for (const auto& tx : vtx) {
        s << "  " << tx->ToString() << "\n";
    }
    return s.str();
}
