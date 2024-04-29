#pragma once

#define BLS_ETH
#define MCLBN_FP_UNIT_SIZE 4
#define MCLBN_FR_UNIT_SIZE 4

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wold-style-cast"
#pragma GCC diagnostic ignored "-Wshadow"
#pragma GCC diagnostic ignored "-Wconversion"
#pragma GCC diagnostic ignored "-Wsign-conversion"
#include <bls/bls.hpp>
#include <mcl/bn.hpp>
#undef MCLBN_NO_AUTOLINK
#pragma GCC diagnostic pop

#include <memory>
#include <oxenmq/oxenmq.h>
#include "cryptonote_config.h"
#include "common/fs.h"

class BLSSigner {
private:
    bls::SecretKey secretKey;

    uint32_t chainID;
    std::string contractAddress;

    void initCurve();

public:
    BLSSigner(const cryptonote::network_type nettype, fs::path key_filepath);

    bls::Signature signHash(const std::array<unsigned char, 32>& hash);
    std::string proofOfPossession(const std::string& senderEthAddress, const std::string& serviceNodePubkey);
    std::string getPublicKeyHex();
    bls::PublicKey getPublicKey();

    static std::string buildTag(const std::string_view& baseTag, uint32_t chainID, const std::string& contractAddress);
    std::string buildTag(const std::string_view& baseTag);

    static std::array<unsigned char, 32> hash(std::string in);
    static std::array<unsigned char, 32> hashModulus(std::string message);

    static constexpr std::string_view proofOfPossessionTag = "BLS_SIG_TRYANDINCREMENT_POP"sv;
    static constexpr std::string_view rewardTag = "BLS_SIG_TRYANDINCREMENT_REWARD"sv;
    static constexpr std::string_view removalTag = "BLS_SIG_TRYANDINCREMENT_REMOVE"sv;
    static constexpr std::string_view liquidateTag = "BLS_SIG_TRYANDINCREMENT_LIQUIDATE"sv;


private:

// END
};

