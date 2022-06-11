// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <primitives/block.h>

#include <chainparams.h>
#include <consensus/params.h>
#include <hash.h>
#include <streams.h>
#include <tinyformat.h>

// Macros for hashing
#define BEGIN(a)            ((char*)&(a))
#define END(a)              ((char*)&((&(a))[1]))

uint256 CBlockHeader::GetHash() const
{
    std::vector<unsigned char> vch(80);
    CVectorWriter ss(SER_GETHASH, PROTOCOL_VERSION, vch, 0);
    ss << *this;
    if ((Params().NetworkIDString() == CBaseChainParams::TESTNET && nTime <= 1655064738) || //June 12th 20:12
        Params().NetworkIDString() != CBaseChainParams::TESTNET && nTime <=1656619938) { //June 30th 20:12
            return HashX11((const char *)vch.data(), (const char *)vch.data() + vch.size());
        } else {
            return HashX25X(BEGIN(nVersion), END(nNonce));
            //return HashX22I(BEGIN(nVersion), END(nNonce));
    }
}

std::string CBlock::ToString() const
{
    std::stringstream s;
    s << strprintf("CBlock(hash=%s, ver=0x%08x, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce=%u, vtx=%u)\n",
        GetHash().ToString(),
        nVersion,
        hashPrevBlock.ToString(),
        hashMerkleRoot.ToString(),
        nTime, nBits, nNonce,
        vtx.size());
    for (const auto& tx : vtx) {
        s << "  " << tx->ToString() << "\n";
    }
    return s.str();
}
