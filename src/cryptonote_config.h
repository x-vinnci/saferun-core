// Copyright (c) 2014-2019, The Monero Project
// 
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
// 
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
// 
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
// 
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
// 
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#pragma once

#include <cstdint>
#include <cstddef>
#include <stdexcept>
#include <string>
#include <string_view>
#include <boost/uuid/uuid.hpp>
#include <stdexcept>
#include <chrono>
#include <array>
#include <ratio>

using namespace std::literals;

namespace cryptonote {

/// Cryptonote protocol related constants:

inline constexpr uint64_t MAX_BLOCK_NUMBER                     = 500000000;
inline constexpr size_t   MAX_TX_SIZE                          = 1000000;
inline constexpr uint64_t MAX_TX_PER_BLOCK                     = 0x10000000;
inline constexpr uint64_t MINED_MONEY_UNLOCK_WINDOW            = 30;
inline constexpr uint64_t DEFAULT_TX_SPENDABLE_AGE             = 10;
inline constexpr uint64_t TX_OUTPUT_DECOYS                     = 9;
inline constexpr size_t   TX_BULLETPROOF_MAX_OUTPUTS           = 16;

inline constexpr uint64_t BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW    = 11;

inline constexpr uint64_t REWARD_BLOCKS_WINDOW                 = 100;
inline constexpr uint64_t BLOCK_GRANTED_FULL_REWARD_ZONE_V1    = 20000;  // NOTE(oxen): For testing suite, //size of block (bytes) after which reward for block calculated using block size - before first fork
inline constexpr uint64_t BLOCK_GRANTED_FULL_REWARD_ZONE_V5    = 300000;  //size of block (bytes) after which reward for block calculated using block size - second change, from v5
inline constexpr uint64_t LONG_TERM_BLOCK_WEIGHT_WINDOW_SIZE   = 100000;  // size in blocks of the long term block weight median window
inline constexpr uint64_t SHORT_TERM_BLOCK_WEIGHT_SURGE_FACTOR = 50;
inline constexpr uint64_t COINBASE_BLOB_RESERVED_SIZE          = 600;

inline constexpr auto     TARGET_BLOCK_TIME = 2min;
inline constexpr uint64_t BLOCKS_PER_HOUR   = 1h / TARGET_BLOCK_TIME;
inline constexpr uint64_t BLOCKS_PER_DAY    = 24h / TARGET_BLOCK_TIME;

inline constexpr uint64_t LOCKED_TX_ALLOWED_DELTA_BLOCKS = 1;

inline constexpr auto MEMPOOL_TX_LIVETIME                    = 3 * 24h;
inline constexpr auto MEMPOOL_TX_FROM_ALT_BLOCK_LIVETIME     = 7 * 24h;
inline constexpr auto MEMPOOL_PRUNE_NON_STANDARD_TX_LIFETIME = 2h;
inline constexpr size_t DEFAULT_MEMPOOL_MAX_WEIGHT = 72h / TARGET_BLOCK_TIME * 300'000;  // 3 days worth of full 300kB blocks


inline constexpr uint64_t FEE_PER_BYTE_V13   = 215;   // Fallback used in wallet if no fee is available from RPC
inline constexpr uint64_t FEE_PER_OUTPUT_V18 = 5000000; // 0.005 OXEN per tx output (in addition to the per-byte fee), starting in v18
inline constexpr uint64_t DYNAMIC_FEE_REFERENCE_TRANSACTION_WEIGHT = 3000;
inline constexpr uint64_t FEE_QUANTIZATION_DECIMALS                = 8;


inline constexpr size_t BLOCKS_IDS_SYNCHRONIZING_DEFAULT_COUNT = 10000;  // by default, blocks ids count in synchronizing
inline constexpr size_t BLOCKS_SYNCHRONIZING_DEFAULT_COUNT     = 100;    // by default, blocks count in blocks downloading
inline constexpr size_t BLOCKS_SYNCHRONIZING_MAX_COUNT         = 2048;   //must be a power of 2, greater than 128, equal to SEEDHASH_EPOCH_BLOCKS in rx-slow-hash.c

inline constexpr size_t HASH_OF_HASHES_STEP = 256;

// Hash domain separators
namespace hashkey {
  inline constexpr std::string_view BULLETPROOF_EXPONENT = "bulletproof"sv;
  inline constexpr std::string_view RINGDB = "ringdsb\0"sv;
  inline constexpr std::string_view SUBADDRESS = "SubAddr\0"sv;
  inline constexpr unsigned char ENCRYPTED_PAYMENT_ID = 0x8d;
  inline constexpr unsigned char WALLET = 0x8c;
  inline constexpr unsigned char WALLET_CACHE = 0x8d;
  inline constexpr unsigned char RPC_PAYMENT_NONCE = 0x58;
  inline constexpr unsigned char MEMORY = 'k';
  inline constexpr std::string_view MULTISIG = "Multisig\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"sv;
  inline constexpr std::string_view CLSAG_ROUND = "CLSAG_round"sv;
  inline constexpr std::string_view CLSAG_AGG_0 = "CLSAG_agg_0"sv;
  inline constexpr std::string_view CLSAG_AGG_1 = "CLSAG_agg_1"sv;
}


// Maximum allowed stake contribution, as a fraction of the available contribution room.  This
// should generally be slightly larger than 1.  This is used to disallow large overcontributions
// which can happen when there are competing stakes submitted at the same time for the same
// service node.
using MAXIMUM_ACCEPTABLE_STAKE = std::ratio<101, 100>;

// In HF19+ registrations the fee amount is a relative value out of this (for older registrations
// the fee is a portion, i.e. value out of old::STAKING_PORTIONS).  For example a registration fee
// value of 1000 corresponds to 1000/10000 = 10%.  This also implicitly defines the maximum
// precision of HF19+ registrations (i.e. to a percentage with two decimal places of precision).
inline constexpr uint64_t STAKING_FEE_BASIS = 10'000;

// We calculate and store batch rewards in thousanths of atomic OXEN, to reduce the size of errors
// from integer division of rewards.
constexpr uint64_t BATCH_REWARD_FACTOR = 1000;


// see src/cryptonote_protocol/levin_notify.cpp
inline constexpr auto     NOISE_MIN_EPOCH   = 5min;
inline constexpr auto     NOISE_EPOCH_RANGE = 30s;
inline constexpr auto     NOISE_MIN_DELAY   = 10s;
inline constexpr auto     NOISE_DELAY_RANGE = 5s;
inline constexpr uint64_t NOISE_BYTES       = 3 * 1024;  // 3 kiB
inline constexpr size_t   NOISE_CHANNELS    = 2;
inline constexpr size_t   MAX_FRAGMENTS     = 20;  // ~20 * NOISE_BYTES max payload size for covert/noise send

// p2p-specific constants:
namespace p2p {

  inline constexpr size_t LOCAL_WHITE_PEERLIST_LIMIT             = 1000;
  inline constexpr size_t LOCAL_GRAY_PEERLIST_LIMIT              = 5000;

  inline constexpr int64_t DEFAULT_CONNECTIONS_COUNT_OUT         = 8;
  inline constexpr int64_t DEFAULT_CONNECTIONS_COUNT_IN          = 32;
  inline constexpr auto DEFAULT_HANDSHAKE_INTERVAL               = 60s;
  inline constexpr uint32_t DEFAULT_PACKET_MAX_SIZE              = 50000000;
  inline constexpr uint32_t DEFAULT_PEERS_IN_HANDSHAKE           = 250;
  inline constexpr auto DEFAULT_CONNECTION_TIMEOUT               = 5s;
  inline constexpr auto DEFAULT_SOCKS_CONNECT_TIMEOUT            = 45s;
  inline constexpr auto DEFAULT_PING_CONNECTION_TIMEOUT          = 2s;
  inline constexpr auto DEFAULT_INVOKE_TIMEOUT                   = 2min;
  inline constexpr auto DEFAULT_HANDSHAKE_INVOKE_TIMEOUT         = 5s;
  inline constexpr int DEFAULT_WHITELIST_CONNECTIONS_PERCENT     = 70;
  inline constexpr size_t DEFAULT_ANCHOR_CONNECTIONS_COUNT       = 2;
  inline constexpr size_t DEFAULT_SYNC_SEARCH_CONNECTIONS_COUNT  = 2;
  inline constexpr int64_t DEFAULT_LIMIT_RATE_UP                 = 2048;  // kB/s
  inline constexpr int64_t DEFAULT_LIMIT_RATE_DOWN               = 8192;  // kB/s
  inline constexpr auto FAILED_ADDR_FORGET                       = 1h;
  inline constexpr auto IP_BLOCK_TIME                            = 24h;
  inline constexpr size_t IP_FAILS_BEFORE_BLOCK                  = 10;
  inline constexpr auto IDLE_CONNECTION_KILL_INTERVAL            = 5min;
  inline constexpr uint32_t SUPPORT_FLAG_FLUFFY_BLOCKS           = 0x01;
  inline constexpr uint32_t SUPPORT_FLAGS                        = SUPPORT_FLAG_FLUFFY_BLOCKS;

}  // namespace p2p


// filename constants:
inline constexpr auto DATA_DIRNAME =
#ifdef _WIN32
    "saferun"sv; // Buried in some windows filesystem maze location
#else
    ".saferun"sv; // ~/.saferun
#endif
inline constexpr auto CONF_FILENAME = "saferun.conf"sv;
inline constexpr auto SOCKET_FILENAME = "saferund.sock"sv;
inline constexpr auto LOG_FILENAME = "saferun.log"sv;
inline constexpr auto POOLDATA_FILENAME = "poolstate.bin"sv;
inline constexpr auto BLOCKCHAINDATA_FILENAME = "data.mdb"sv;
inline constexpr auto BLOCKCHAINDATA_LOCK_FILENAME = "lock.mdb"sv;
inline constexpr auto P2P_NET_DATA_FILENAME = "p2pstate.bin"sv;
inline constexpr auto MINER_CONFIG_FILE_NAME = "miner_conf.json"sv;


inline constexpr uint64_t PRUNING_STRIPE_SIZE = 4096;  // the smaller, the smoother the increase
inline constexpr uint64_t PRUNING_LOG_STRIPES = 3;     // the higher, the more space saved
inline constexpr uint64_t PRUNING_TIP_BLOCKS  = 5500;  // the smaller, the more space saved
inline constexpr bool     PRUNING_DEBUG_SPOOF_SEED = false;  // For debugging only


// Constants for hardfork versions:
enum class hf : uint8_t
{
    hf7 = 7,
    hf8,
    hf9_service_nodes, // Proof Of Stake w/ Service Nodes
    hf10_bulletproofs, // Bulletproofs, Service Node Grace Registration Period, Batched Governance
    hf11_infinite_staking, // Infinite Staking, CN-Turtle
    hf12_checkpointing, // Checkpointing, Relaxed Deregistration, RandomXL, Oxen Storage Server
    hf13_enforce_checkpoints,
    hf14_blink,
    hf15_ons,
    hf16_pulse,
    hf17,
    hf18,
    hf19_reward_batching,
    hf20,
    hf21_saferun,

    _next,
    none = 0

    // `hf` serialization is in cryptonote_basic/cryptonote_basic.h
};
constexpr auto hf_max = static_cast<hf>(static_cast<uint8_t>(hf::_next) - 1);
constexpr auto hf_prev(hf x) {
    if (x <= hf::hf7 || x > hf_max) return hf::none;
    return static_cast<hf>(static_cast<uint8_t>(x) - 1);
}

// This is here to make sure the numeric value of the top hf enum value is correct (i.e.
// hf20 == 20 numerically); bump this when adding a new hf.
static_assert(static_cast<uint8_t>(hf_max) == 21);

// Constants for which hardfork activates various features:
namespace feature {
  constexpr auto PER_BYTE_FEE                           = hf::hf10_bulletproofs;
  constexpr auto SMALLER_BP                             = hf::hf11_infinite_staking;
  constexpr auto LONG_TERM_BLOCK_WEIGHT                 = hf::hf11_infinite_staking;
  constexpr auto INCREASE_FEE                           = hf::hf12_checkpointing;
  constexpr auto PER_OUTPUT_FEE                         = hf::hf13_enforce_checkpoints;
  constexpr auto ED25519_KEY                            = hf::hf13_enforce_checkpoints;
  constexpr auto FEE_BURNING                            = hf::hf14_blink;
  constexpr auto BLINK                                  = hf::hf14_blink;
  constexpr auto MIN_2_OUTPUTS                          = hf::hf16_pulse;
  constexpr auto REJECT_SIGS_IN_COINBASE                = hf::hf16_pulse;
  constexpr auto ENFORCE_MIN_AGE                        = hf::hf16_pulse;
  constexpr auto EFFECTIVE_SHORT_TERM_MEDIAN_IN_PENALTY = hf::hf16_pulse;
  constexpr auto PULSE                                  = hf::hf16_pulse;
  constexpr auto CLSAG                                  = hf::hf16_pulse;
  constexpr auto PROOF_BTENC                            = hf::hf18;
}


enum class network_type : uint8_t
{
  MAINNET = 0,
  TESTNET,
  DEVNET,
  FAKECHAIN,
  UNDEFINED = 255
};

// Constants for older hard-forks that are mostly irrelevant now, but are still needed to sync the
// older parts of the blockchain:
namespace old {

  // block time future time limit used in the mining difficulty algorithm:
  inline constexpr uint64_t BLOCK_FUTURE_TIME_LIMIT_V2 = 60*10;
  // Re-registration grace period (not used since HF11 infinite staking):
  inline constexpr uint64_t STAKING_REQUIREMENT_LOCK_BLOCKS_EXCESS = 20;
  // Before HF19, staking portions and fees (in SN registrations) are encoded as a numerator value
  // with this implied denominator:
  inline constexpr uint64_t STAKING_PORTIONS = UINT64_C(0xfffffffffffffffc);
  // Before HF19 signed registrations were only valid for two weeks:
  // TODO: After HF19 we eliminate the window-checking code entirely (as long as no expired
  // registration has ever been sent to the blockchain then it should still sync fine).
  inline constexpr std::chrono::seconds STAKING_AUTHORIZATION_EXPIRATION_WINDOW = 14 * 24h;

  inline constexpr uint64_t FEE_PER_BYTE_V12                             = 17200; // Higher fee in v12 (only, v13 switches back)
  inline constexpr uint64_t FEE_PER_OUTPUT_V13                           = 20000000; // 0.02 OXEN per tx output (in addition to the per-byte fee), HF13 until HF18
  inline constexpr uint64_t DYNAMIC_FEE_REFERENCE_TRANSACTION_WEIGHT_V12 = 240000; // Only v12 (v13 switches back)
  // Dynamic fee calculations used before HF10:
  inline constexpr uint64_t DYNAMIC_FEE_PER_KB_BASE_BLOCK_REWARD = UINT64_C(10000000000000); // 10 * pow(10,12)
  inline constexpr uint64_t DYNAMIC_FEE_PER_KB_BASE_FEE_V5       = 400000000;

  inline constexpr uint64_t DIFFICULTY_WINDOW       = 59;
  inline constexpr uint64_t DIFFICULTY_BLOCKS_COUNT(bool before_hf16)
  {
    // NOTE: We used to have a different setup here where,
    // DIFFICULTY_WINDOW       = 60
    // DIFFICULTY_BLOCKS_COUNT = 61
    // next_difficulty_v2's  N = DIFFICULTY_WINDOW - 1
    //
    // And we resized timestamps/difficulties to (N+1) (chopping off the latest timestamp).
    //
    // Now we re-adjust DIFFICULTY_WINDOW to 59. To preserve the old behaviour we
    // add +2. After HF16 we avoid trimming the top block and just add +1.
    //
    // Ideally, we just set DIFFICULTY_BLOCKS_COUNT to DIFFICULTY_WINDOW
    // + 1 for before and after HF16 (having one unified constant) but this
    // requires some more investigation to get it working with pre HF16 blocks and
    // alt chain code without bugs.
    uint64_t result = (before_hf16) ? DIFFICULTY_WINDOW + 2 : DIFFICULTY_WINDOW + 1;
    return result;
  }

  inline constexpr auto DATA_DIRNAME =
#ifdef _WIN32
    "loki"sv; // Buried in some windows filesystem maze location
#else
    ".loki"sv; // ~/.loki
#endif
  inline constexpr auto CONF_FILENAME = "loki.conf"sv;
  inline constexpr auto SOCKET_FILENAME = "lokid.sock"sv;

}  // namespace old




// Various configuration defaults and network-dependent settings
namespace config
{
  inline constexpr uint64_t DEFAULT_DUST_THRESHOLD = 2000000000; // 2 * pow(10, 9)

  // Used to estimate the blockchain height from a timestamp, with some grace time.  This can drift
  // slightly over time (because average block time is not typically *exactly*
  // DIFFICULTY_TARGET_V2).
  inline constexpr uint64_t HEIGHT_ESTIMATE_HEIGHT = 582088;
  inline constexpr time_t HEIGHT_ESTIMATE_TIMESTAMP = 1595359932;

  inline constexpr uint64_t PUBLIC_ADDRESS_BASE58_PREFIX = 114;
  inline constexpr uint64_t PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX = 115;
  inline constexpr uint64_t PUBLIC_SUBADDRESS_BASE58_PREFIX = 116;
  inline constexpr uint16_t P2P_DEFAULT_PORT = 11011;
  inline constexpr uint16_t RPC_DEFAULT_PORT = 11012;
  inline constexpr uint16_t ZMQ_RPC_DEFAULT_PORT = 11013;
  inline constexpr uint16_t QNET_DEFAULT_PORT = 11014;
  inline constexpr boost::uuids::uuid const NETWORK_ID = { {
        0xd1,0xe5,0x97,0x09,0x46,0x06,0x48,0x32,0x93,0x04,0x0d,0x6d,0xa4,0x72,0x15,0xce
    } }; // Bender's nightmare
  inline constexpr std::string_view GENESIS_TX = "03651e00e0a801c0d102a0fa0380a305e0cb06c0f407a09d0980c60ae0ee0bc0970da0c00e80e90fe09111c0ba12a0e313808c15e0b416c0dd17a0861980af1ae0d71bc0801da0a91e80d21fe0fa20c0a322a0cc2380f524e09d26c0c627a0ef2880982ae0c02bc0e92ca0922e80bb2fe0e330c08c32a0b53380de34e08636c0af37a0d83880813ae0a93bc0d23ca0fb3d80a43fe0cc4000e0a801c0d102a0fa0380a305e0cb06c0f407a09d0980c60ae0ee0bc0970da0c00e80e90fe09111c0ba12a0e313808c15e0b416c0dd17a0861980af1ae0d71bc0801da0a91e80d21fe0fa20c0a322a0cc2380f524e09d26c0c627a0ef2880982ae0c02bc0e92ca0922e80bb2fe0e330c08c32a0b53380de34e08636c0af37a0d83880813ae0a93bc0d23ca0fb3d80a43fe0cc40001e01ff006580c0dc8df9ecc5b80102b38bffc12081a9cb16e7a968486d25d14114b81e52f0590a24a7cf9aa9cc65bc80e09bf2ec8dda0202577eb3dae136d120b7bc4939df7d14666a3e9ba76bb4465867bad40c217b3cc280e09bf2ec8dda0202f9106662b66cd8d9d8f12ffbc78043879cee99298476f4a12eb5d9829acc94b680e09bf2ec8dda02024b95b4443a98356f525e57f976189634bf7c90fe2cb3e50ec87610c04db33d0b80e09bf2ec8dda02023ac5c780081579a540661a26b9a029b0611302aa6e5d5c5da4e4574a80dd47a480e09bf2ec8dda02024e12177096f3ba2f7d74c4c56cb1eecb74d43bae714f30dc98943fe671e748f680e09bf2ec8dda02020ef64fe32752fcbb3155c868fb810f711502daec49db9561741af53ffce21b5780e09bf2ec8dda020262ecabf3f5651174950c5ab28d1cb1f2f34ddf522eae8512675aa41027bdc4ed80e09bf2ec8dda0202c46d3fc50838964c83b123ab1a8dc4373373faf4c6eb1e2738cfbc0e44933c0480e09bf2ec8dda020233f5511bbc6d680cdec63697b179cd9a9faf0ec9acbcec617f55ebe0f13d2acd80e09bf2ec8dda02029086b38567a750eefdd15ffb4bbc1a3829b2d82b95dd4a8b35cd95a47d5235d280e09bf2ec8dda0202d89febcced4742898e0294ce168d5257d2ea74aff3a435af6d0c7ba8ca61f06780e09bf2ec8dda0202d3123ce7575430286cf77d675d155025ab0309f5cc4eaf1efbf12681011a991280e09bf2ec8dda020278f8f284c58302880c3b5a4bdba986d8db458adba930b4ef57f7189b3012631480e09bf2ec8dda0202b4c38e91240fe584d46861bf2289f597a5703fa454b454cc2cd17a00277e98d180e09bf2ec8dda020270afefa86ca1698ff1346113d35f56f84b5f1c4e0059d15cac236ec6a0a6b5f380e09bf2ec8dda0202a0729c648ca2c3503f54d141c8f42378977d6e0ab50ccad2242e183837df891680e09bf2ec8dda0202d4446659817cec48fad4c00cc410500a219f764e0f3d6944472a766b128e96d680e09bf2ec8dda02022f83a44e7adc742c34d12688dfdc60eafc711fe7c0450989fb6117c5150ee9fc80e09bf2ec8dda020233701b8597c3871ea382d4056137f507cb21f8330dc9cf0ae68e18178bd8a9ef80e09bf2ec8dda0202b5d387b39ddbfe2d60920ff3bb31b0ef6dfe2fc753d342ee12d5b02a31ed4c3480e09bf2ec8dda02029e4488cdb9a82e772029879062d483d49ba9c6fc209fddb3dee54d375ef7416180e09bf2ec8dda020285c07bd0c54c39d05e363950971f732fcf2e0f04eed7c425576709b080d43daa80e09bf2ec8dda0202d7e1c70f75a0290ce63fb803848a163bc50e898b8c65e0fcde72c2517415d8ae80e09bf2ec8dda020207a9d466ad844d8cc8ec8f403da0f060792d68fe36d5cf8142ca712c1dc8bcb880e09bf2ec8dda02026d5a14cd16f376a85e3dc833e12a2c3d654650b7319471ac19a30f7ee3d5296980e09bf2ec8dda02027a5c853a7ccc68fee2c49209332eed3c22ebab54598f187716086d36e7483cd380e09bf2ec8dda0202cd2595f624eeb7cfaab3484eb74fb6b48c5b1797aaf347b7b440ac1778b89a8180e09bf2ec8dda02020adb4f9277ee075df5a6e6356a926a9ebaf7f750c505b1239668c4d81c8fea6e80e09bf2ec8dda02026f998daf49d1746a7fd9c5a8275a47e66dbadf3788da3fb2ff29d5cf029fa0ef80e09bf2ec8dda0202b5079363249a2ad198cc2e56b895b7f11e94cbf1c5eb67d45a8920f43753317480e09bf2ec8dda02021c3fec2b0f54b857c688f7661cb36c5ce0a4e57a923c757ceab222abd81d98d380e09bf2ec8dda0202d77197ef90314f15418fb2d85fd9b6276a4cf1390da1ec3061b506066cd0df9c80e09bf2ec8dda0202106ab3748d36d37e74faa2ab3d81efa98c1f93c9329cb8d48ffe20589b4a47dc80e09bf2ec8dda0202b4ddb327e15e7321fea1034f5cf1b0d30e501d8261aa4eb2bbea3b24b00dc55580e09bf2ec8dda0202de3984ab3b7ce7ed9c04550599d21b9ad490898dc5eccd904ff8e23f5c94ac6f80e09bf2ec8dda0202fc86586f7b3775963bd29b48756ac76f1e127b4b8116f1eba34d3a51498f3adf80e09bf2ec8dda0202114e56c376a452228f425b466368df8438782f9d5e03963d6512dc221bd059b680e09bf2ec8dda02020fb5e7e2172d140c73089a0d7e984e49bc2ba19d159fe467e6bd624e435c5b5e80e09bf2ec8dda0202721713c52874cb885983d4686e9a7bca3ad0855ce584c2c68bcebfbad5993a4880e09bf2ec8dda0202b4b4e9348773ebb15801f613ea1cbd8fb9922f094258473b44b48733c50b04d780e09bf2ec8dda02024100fca6646fb9216bcef5d5b83cf8fa7098a1288f4f48f168bcbee6da1f180080e09bf2ec8dda020279a017896a1fd5308a078d3998748ab574dd5ba70eb3b5724c5ee1e792dcd6ce80e09bf2ec8dda0202f7a6f2e4ee2c0d1c2031cb934302c6d7aef174efc3e0fac67490f17ce8d6037880e09bf2ec8dda0202dd1fb0139dac7bc528dfa03e8285016625637549814232c4e12467f8e196417780e09bf2ec8dda0202006fca857bf19f4355e17b67de799aaa2b3e1adf8afa6fdfe4ae3423fb5a4d1780e09bf2ec8dda020216c1d98bc106593abe71a0a7b5cde17a8483a536852d3ef17e002245c220dc8580e09bf2ec8dda0202e39c699e1269fbc34d38b4b4839f493f62d83b5472f10f4d5ce9eb4abd7e239580e09bf2ec8dda020229e13f713b19666dfd3fca041819e6512ccc9cd8851ef695090688b768ca785f80e09bf2ec8dda02024f4cdb8b2398a2bd970ef458b7b4bc9b6b1946544427c4482106a508b6ac967780e09bf2ec8dda0202385de186148eb22d7a2768dc2ac2ce82224eeff44767fc59c032b49f96ffc86d8080f696a6b68801025b0ed96cde31d9fe12b6750a08f416a333e560329b41e21b84810df08474df2f8080f696a6b6880102e24dd667efc507c8904440f8f30c6eecaf7e07293503fd7f830e1debb6c5baaa8080f696a6b6880102685ae97f8e0f01765593f61660515874ff0237b8af4ae709f0ef91bfbad1b6af8080f696a6b6880102f17dfb33c448b13fdf77b3df4fc4b87a0827d10742dfa373b02bcc0bb35a2b578080f696a6b68801021b11df8f88e24ac0bae3cbdd178e127ce84f707461887b7f1109379a03ec0c4a8080f696a6b68801026fec904644c78d868e99020f8d3897ed1bf923d06fa0287c4654ff3b482db0cd8080f696a6b6880102f9b0b946138ec1d52a7fa2175b7aba439b867efc283d5b1b43f4f5eec3fecb558080f696a6b68801023590a1430acfa6d731fcf49c62255d61092596d22a55d18f408c1c75f1457dae8080f696a6b6880102ec8f121b18102b305adf0253f9dcc1c924318837f85216bce86b3c929d06dc288080f696a6b68801022ca147b57dbd28fee7cf134a223245e8c30c3c8d52cfa8f1bf7adec30919641b8080f696a6b6880102d8b4523ba972d1a7a2efc50e41c7bda23564513301e05c9c5f528dee727aeec98080f696a6b68801025ea5fed212000c25cfd919caaf512c5adfb7646bbd484bb8e179acb62ee866cb8080f696a6b6880102bbe12a31e60e92257875a33f8eda768432e35cbe3bdc4f46b79dc4ed7336fa4c8080f696a6b68801023b270d1e4a38fd499ba4b4dcbc96a3759b0c605af72e5589116edc35cbb67c038080f696a6b6880102591e4e1ec1665562cd95b2533c0f2612b8739e17e3d40172b5c8f3ec32488b9f8080f696a6b68801027b10377882a800ab94cb90a1e5ee943ce48dbb4e2f9dec590a667836e9c1742e8080f696a6b688010240d246d74f806e912f38f69708a92095cc39a5f089b5bfa6042e279c9c0032798080f696a6b6880102a91c39869f63324b2c390dfa7d00cb5f04685392ac4b3cf320a48a4f5145c3c48080f696a6b6880102be05ca37fb37348dbf395a1cfe799e8a5813aa5e5fc606fbac60182a765171fb8080f696a6b6880102610399f0e8351d9ad95a5e66cfc5b467969eb83900d4bcde068205a2ae255baa8080f696a6b688010274bd6cd97e484011c6c73b418836c8c8955605f7e915459f1d2e42ea246021048080f696a6b68801023bbc90ca206a88bae6d44cdd4cd256ab4a261cffaa29db87d6cbf14764b0a7008080f696a6b6880102ae401c1b7bbf2efba42537a5083aab5dea96ae8071b79132fcb76b60f1bb8a5e8080f696a6b6880102075db00a0585c3de594a972ed1092743b364f1b42d10ebf0855fe406438d66008080f696a6b68801025d8c22138f59ad238f471269e5d64b8506b6880db34451822e614440876e475d8080f696a6b688010236d665ef0e1f2611f23b928db7835c801471ad090257ba7c59e87c12736fc9c98080f696a6b688010233c2c716bb0ed03218ac09c68b91b4abd0ee2e121705a982eecc316768a7205a8080f696a6b6880102ac231c92b91e231b87281c6848f2e6061320b930b13a08cf60767470c654cb8b8080f696a6b688010203dff836ff02ac10940bf57fa700e83af3a6dc009f8d298ef1de225c7454da508080f696a6b6880102c01887465ba61b71197670939c5a3758b28efd73629cd1df49c1aa19e6d906478080f696a6b6880102aa93874738fb705c5bb99caa83d5d61f1ca26b029566841a4f4afa2c0f39e8b58080f696a6b68801029881f134b8f0689bb2ac8b53b3b20ed3e803b3f636d1129cec8dad4f8564f7fd8080f696a6b68801027ff82cafa6f3ce525f2a951ce65bccb3bc59674e9f9500ba81d11d0413d7ba0a8080f696a6b6880102f0f39e2a3566f1fe8c8d9406f55549cb7b780d7c88bffdaceb5a1df58af28d548080f696a6b688010295f5b04b21d62e0b88363100a949730cbe4ac846a88a852725ac44dcda3775e18080f696a6b6880102a6c687505dcf27d48e3078aaa929dd6a95d5f26ba4a4dac6e7f26a80a75dbe0a8080f696a6b68801025fdc0368ebb7d173cfb9c4c98e2e69d36377d5d282c95740e7a426ca4d3624748080f696a6b6880102480201ed821dcbec37bb8115370933226c05c9a8a931fd3b4a6f49abee58047d8080f696a6b68801021535c3a2953820e696291f794958049ff1a2c5910faa8689cd44af2fd9e1c7988080f696a6b6880102e4bcb02665386968e919149cd7ed6d9fd11423ff671cebfabfb21fd62ff7b5ac8080f696a6b6880102aab8e87221342c97cbd2b2c25b8f190fefb272ad4855fd352e4c97431be0f65e8080f696a6b6880102517de83988f36165ba5b495ee961579ac7979a8d0e596d01fc4b8ab13af4a14b8080f696a6b6880102b1b72e239a952e14b1e6592571026846ab34094ab13d8c7074a4d40856a0c9fa8080f696a6b68801024ac3c53797712ec726546100b731547ea3d1c9114247c6b2e49fa79e387ba8cc8080f696a6b68801024e8f171b7630f3c6fe6c73daa64da316f46a39bae143c776aaa46249c69db67b8080f696a6b688010275f566b7ab9e4aa22e19fbb2497dc3ae196fa9be99b3ba4534a5bffc28bca7c78080f696a6b68801021ae5690294081e8f18cfff29b5fa6cd2ecd0c182f017d1959fc38cb672cbf4ee8080f696a6b68801027917e5eb5dfc372aa56218cbb5a0fa72614ec0a1a56584cb6ef1f8043f8b4db38080f696a6b6880102c61b663e5a5cc4f089486805d295bd199c324d68d21cc4121b29e2edca7d8aa48080f696a6b68801021296f13ff57eb1b37e39e66d6b6477934cc3733c4188c757038065698275c7cf2101e57628a9db245a53156965be51e0c15b7007bcc0c93709301cf29da520dfd71300"sv;
  inline constexpr uint32_t GENESIS_NONCE = 3141592;

  inline constexpr uint64_t GOVERNANCE_REWARD_INTERVAL_IN_BLOCKS = 7 * cryptonote::BLOCKS_PER_DAY;
  inline constexpr std::array GOVERNANCE_WALLET_ADDRESS =
  {
    "L77i3zCRuHv8jJn9E5M6eyKJw1R5BtWENNHFbnojeNJbMm4n8dQCr1h94ixNUFG8NwKJ4uLBZmreoLHiN37BvASqMj1pQzf"sv, // hardfork v7-10
    "L77i3zCRuHv8jJn9E5M6eyKJw1R5BtWENNHFbnojeNJbMm4n8dQCr1h94ixNUFG8NwKJ4uLBZmreoLHiN37BvASqMj1pQzf"sv, // hardfork v11
  };

  inline constexpr uint64_t HARDFORK_DEREGISTRATION_GRACE_PERIOD = 7 * cryptonote::BLOCKS_PER_DAY; // After a hardfork we will decommission sns but wont dereg, allowing time to update

  inline constexpr auto UPTIME_PROOF_TOLERANCE = 5min; // How much an uptime proof timestamp can deviate from our timestamp before we refuse it
  inline constexpr auto UPTIME_PROOF_STARTUP_DELAY = 30s; // How long to wait after startup before broadcasting a proof
  inline constexpr auto UPTIME_PROOF_CHECK_INTERVAL = 30s; // How frequently to check whether we need to broadcast a proof
  inline constexpr auto UPTIME_PROOF_FREQUENCY = 1h; // How often to send proofs out to the network since the last proof we successfully sent.  (Approximately; this can be up to CHECK_INTERFACE/2 off in either direction).  The minimum accepted time between proofs is half of this.
  inline constexpr auto UPTIME_PROOF_VALIDITY = 2h + 5min; // The maximum time that we consider an uptime proof to be valid (i.e. after this time since the last proof we consider the SN to be down)
  inline constexpr auto REACHABLE_MAX_FAILURE_VALIDITY = 5min; // If we don't hear any SS ping/lokinet session test failures for more than this long then we start considering the SN as passing for the purpose of obligation testing until we get another test result.  This should be somewhat larger than SS/lokinet's max re-test backoff (2min).

  //Batching SN Rewards
  inline constexpr uint64_t BATCHING_INTERVAL = 2520;
  inline constexpr uint64_t MIN_BATCH_PAYMENT_AMOUNT = 1'000'000'000;  // 1 OXEN (in atomic units)
  inline constexpr uint64_t LIMIT_BATCH_OUTPUTS = 15;
  // If a node has been online for this amount of blocks they will receive SN rewards
  inline constexpr uint64_t SERVICE_NODE_PAYABLE_AFTER_BLOCKS = 720;

  // batching and SNL will save the state every STORE_LONG_TERM_STATE_INTERVAL blocks
  inline constexpr uint64_t STORE_LONG_TERM_STATE_INTERVAL = 10000;

  namespace testnet
  {
    inline constexpr uint64_t HEIGHT_ESTIMATE_HEIGHT = 339767;
    inline constexpr time_t HEIGHT_ESTIMATE_TIMESTAMP = 1595360006;
    inline constexpr uint64_t PUBLIC_ADDRESS_BASE58_PREFIX = 156;
    inline constexpr uint64_t PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX = 157;
    inline constexpr uint64_t PUBLIC_SUBADDRESS_BASE58_PREFIX = 158;
    inline constexpr uint16_t P2P_DEFAULT_PORT = 12011;
    inline constexpr uint16_t RPC_DEFAULT_PORT = 12012;
    inline constexpr uint16_t ZMQ_RPC_DEFAULT_PORT = 12013;
    inline constexpr uint16_t QNET_DEFAULT_PORT = 12014;
    inline constexpr boost::uuids::uuid const NETWORK_ID = { {
        0xc7,0x58,0x1a,0xa3,0x7b,0xdf,0x4a,0xb3,0x9d,0x53,0xfd,0x12,0x1d,0xd6,0xf9,0xb8
      } }; 
    inline constexpr std::string_view GENESIS_TX = "03651e00e0a801c0d102a0fa0380a305e0cb06c0f407a09d0980c60ae0ee0bc0970da0c00e80e90fe09111c0ba12a0e313808c15e0b416c0dd17a0861980af1ae0d71bc0801da0a91e80d21fe0fa20c0a322a0cc2380f524e09d26c0c627a0ef2880982ae0c02bc0e92ca0922e80bb2fe0e330c08c32a0b53380de34e08636c0af37a0d83880813ae0a93bc0d23ca0fb3d80a43fe0cc4000e0a801c0d102a0fa0380a305e0cb06c0f407a09d0980c60ae0ee0bc0970da0c00e80e90fe09111c0ba12a0e313808c15e0b416c0dd17a0861980af1ae0d71bc0801da0a91e80d21fe0fa20c0a322a0cc2380f524e09d26c0c627a0ef2880982ae0c02bc0e92ca0922e80bb2fe0e330c08c32a0b53380de34e08636c0af37a0d83880813ae0a93bc0d23ca0fb3d80a43fe0cc40001e01ff006580c0dc8df9ecc5b80102fcbeb329cf69f3f8362e52e35ed262d99b13b231848173420066f1ccb29b86ab80e09bf2ec8dda0202228fc799e7c4501bf773653f27ce31c9457d3ffb1f10328e7f5e3d6b2e00374e80e09bf2ec8dda0202e76aeef10e4c15079f05d9b7b46b58dad87e92eb1772804e133146bab5f2307e80e09bf2ec8dda0202af017de9c8d17c21b7d3b59396d8f1cef5c49c9dbdf052dc127ab42de03ad46d80e09bf2ec8dda020239d76e90b122ddf2176d5935e42805300cdcb9c45ab902b14e4828622c33d87c80e09bf2ec8dda0202110680b9b68b7ebc3f3b6f8bb8c14067dfcbd8ab9fd2c9b540ad1cb6ba72001d80e09bf2ec8dda02024b25a2186682d8b37ec10dcf373a733cdc3ff2a3f43e0c1998e9274e53ceb74580e09bf2ec8dda020260a9eb8c6faf67f8a73a2c3ece62643c62b4fdb4873fb4e4242eed1a966dcbea80e09bf2ec8dda0202fb9b1303cdc55116d20112103ddc71dd25983e0857183e77298a73659443c63a80e09bf2ec8dda02025236e15aaddfee226cde3e46798d9d207fad3214529aae99a1f5547c15753b4980e09bf2ec8dda02028cfd564166c0406ddd5cfa72e504882a99678bdd02317b0d2c9a6f511967193b80e09bf2ec8dda0202df4a49796dd9f4cee09fe55b6d140c38be868b2fba8f9ff74fd940db3b9a57ca80e09bf2ec8dda020227ccb1ede8d5c76677a18017429bb82bacfe910294480ea1d6d299f6ff5f298180e09bf2ec8dda0202d8d0e8654d36565d9fe7ff19f055501b3cdc74370e08bc1d9a41ced8d346c8e580e09bf2ec8dda0202add201103d33df6df4a5b1aba7de3e716100bca92af196d9c0f428b64f978b3f80e09bf2ec8dda020281a86b1416bf010d1446b8a6bbe23f9aa5538b70d4379ad390ce68e9052635a280e09bf2ec8dda0202b54fd6b981bbda87bea137845975d76e625cd7952a2f732df9817f714d45700080e09bf2ec8dda020257d6743e5fa6f8619d7141977a46a7d3ae1ccbcd85f73f4d0045096a58d2cda580e09bf2ec8dda0202f07c9977774aa5bf9459356ccfe8065115d387d054b0b191fcdaafa3542a27fc80e09bf2ec8dda0202b6b3d3769c74f5a61ea51270685f9979235f457b0eeb886cd00f0ed7a7ebfd4980e09bf2ec8dda020223361a1a7222ce558418e145ce4869cb9da66c71fd39acf69ef3c49aea9cceff80e09bf2ec8dda0202137a489ddb2c2dbc50bfbff9c91da186485974ba66b33168e44f1549f962759480e09bf2ec8dda02029f626d208cf7b9d28210e5d9decb8176f5e96e88c5a80f5f383ca79bcb7e868580e09bf2ec8dda0202565f8af03329b699b4ea3f43dde922ae891216d07064d0a78d74cb0e8f5cc42d80e09bf2ec8dda0202afffb87a31b7ca988f838665827a7817bfd4096d164c9c61ea150c73a49841ef80e09bf2ec8dda0202268da6dd037197bff32c0b06920c917d5ba54e204e5564fb0c8770b3fff5e52280e09bf2ec8dda0202fcf55b7d3292a71c39709419792e4abf2d3ff78e8d38f0b0f5e01d278711959980e09bf2ec8dda0202980c9e4becae7225ae86029dfb376029df3bfa0303a2fd6850de325084f07a4480e09bf2ec8dda020286229d34b400cffab633f0c09ff154ce49a7d72ef8c4574ec15b5ffdb319bb6580e09bf2ec8dda0202848fdfa9a63157addc69ab6826671260a4417e2ece21cb7e163e34e4cef7a64080e09bf2ec8dda02027640e425324d6a60ac64b5e254135142b258e00e8671a8bf6784d4881cb4645e80e09bf2ec8dda02020a177336dca9719f0e87cdbcf49bf96252f804267a4a8038b881d591ec6ddff880e09bf2ec8dda02020c5af4daab713c5934999841fffa17bad525510cef3409bb0c88945cd2517ab980e09bf2ec8dda020291f96b87a544b2a7720ad14689816fb3163564d075c6c1c734c0bd0f8c42a11880e09bf2ec8dda02025293d305015f631bc767985f5379934e88e363312f252b5dadb7b43c497a3c9c80e09bf2ec8dda0202d93e05b8f61dd9cfb2dea210ef0d5c417bddb49fb78833e3c61095c7c230dce480e09bf2ec8dda0202d1969403bd547399cb809d81186d00b3fe9b2585c991961ec0b1a10747629dea80e09bf2ec8dda02028416eb589610271770f3882f28b1d08f5ca2dca88605964f1f11b56cf672c6bc80e09bf2ec8dda02021e5b75f000d727e75539d157b7936394d153759ddedc946c401ecdc0c41274aa80e09bf2ec8dda0202fbb983d778680af166f2745de64a717222363f60feadfaa5da6b589457b6d04e80e09bf2ec8dda020257f833e073b6f8f225052304a3b54afd5484ec353d728a79b40ae24e2622c75f80e09bf2ec8dda020238983a9f7c9504e358b7d00ab16267f4baf6956104a8a4a459b443d3fec7dec380e09bf2ec8dda020274be5c171b0b0742783923aa8f52cf0153841ad354d4ecd90f4fab3d6c54bbe080e09bf2ec8dda0202ea3e1bc8cc71d358cf6fe703eecbb4dda5e33c1cfdd52fcef4ce16152cb6650a80e09bf2ec8dda02022849a35f6151cb8c04a462da08e283d3b9f50b1e33a55050a9f8ace418b2584680e09bf2ec8dda0202cba2d4ac6284697c92ba62a18dfd055e60203b71e702f914aa72baed48521fb480e09bf2ec8dda0202691b3deac2927f3c933156ea2be7bd21c523abaccbe07232c0bb2a791aba99aa80e09bf2ec8dda02020ea7d2f3c39680912839b3e6f31cef5e2a2d39735578926248ebd22d96c1464080e09bf2ec8dda0202e06743f29de87212a9b7dbc0a9e8ccefe3adda538fc40d3e732a0e8a3f987df880e09bf2ec8dda0202dbdb5033f0c6a7eb28660f670df82a40f953650da809669be74cf1d502f2a0d580e09bf2ec8dda020254ce2d2c32fb6c2a8491eca824e9b71d6e27ad7faa207bd90a39045d5c6cd4868080f696a6b688010231881e4807f679f65a15531d81d9cc5bb6835ab74139714c83e2eac5ec6914758080f696a6b6880102f84ff9a0d22b9673daca115e7df47158daf06192f54a05f155ee41c4265224ad8080f696a6b68801029af7107c562586118f181a31d1571caa5a0c8b77f7fd5b5b33090a373ec34cc68080f696a6b68801028c12af2c97cb863fa238acf4bceeff26c9e42dfff0d2cb6df84621205cc94d6d8080f696a6b6880102e1275c3c08c09a79afd8c20262a5f7c7741f9fa9a92c38d95e984ef405a53e528080f696a6b688010282dc661af2dbca70b1ebaa8929aa486d73d7f87dc02259990560ebd3173c54278080f696a6b68801029d315f24b1e593907a9a150bdb74738ecac3c09cd62b3210e70f3d388161debf8080f696a6b6880102b2f68a2792cac934aa1d5cbbd6d6be525a74591b212fc8ca7ee81ef00c036a328080f696a6b6880102f4ab9167ff51ece9749a16acc1c356232c3a5d3da1fca6bb7ec91484e8d9c3bb8080f696a6b68801023de0257264c84757da6ac63d47795705a9bed5d77e78264cfc3c6359354596aa8080f696a6b6880102bbeb390d054b6020c4f423dcad093f19cee2eb5fed9a69ae147ebe435ade7f518080f696a6b6880102880ddf58e931864db2f6ddb661ce267fe7fc736cd7834ec4af539809b87fec168080f696a6b688010245f270d64fd731c21a9bf088dcd5337add7d3e0bb792fa4a0ec428ed2ee3dc108080f696a6b68801029e3f77aaf236bb8882b9bae06609f9619a116953ddc427a3b56435851aebd1df8080f696a6b688010292e323f19d925a7a172f46b513e93a6ccb41f7f733e4e3553c9d8c5819d8319c8080f696a6b6880102898e4bc4d1de345c0e18bd0d10213aa169f5f2a231dea1f1baa06995075607138080f696a6b68801022e3cf2359f293777ebff011a898a993e2684af43541fb7e3a48be4e5f26e5d238080f696a6b688010286af32e2a8ff830c881b60677b4d68b3237a9daf7e029a1cafdb43d8594a1a108080f696a6b6880102101ccb132a7c59681e1e687d620b0205c46e2b0c8d4440d174d4b5ea0b5c1fd68080f696a6b6880102cbc6f2dca7649831cb4bee71e0a5e312d41864a9eb51567385999abd9ee433ad8080f696a6b68801021583a92e907d65afa1840aa71940e13276f5c1609e162e638f400dd5159f9ae58080f696a6b68801023ef3de60189ff2d056af378005a15bd7bcf1df29826dfcf2f327a10dfcf000d58080f696a6b688010280c4e45845a6aaddf95788d08c094f4ba8dcf6fc036cf72463e9f90ae31c1b168080f696a6b6880102c3601bad1bdad44ad84e5ab310646e5449434ea7a324daa5f5561cc21b5d5fac8080f696a6b68801020a20fc29f67c6fec9cc7409d69aec786111cb421148686ddbfe4c7ac4e1807618080f696a6b688010242ec637c8aaf2e36bbf48dbdca96d499ac608b8b97fee1de83fe078a9d43c5228080f696a6b688010296692ed4dde7cef5e7d27a49b2a48e76ba50f9738d664d2f3010ff08bea19bc48080f696a6b6880102ede0233e5f00dd9a3fcacf22024c6bbca3ea3933a7bb5518f37a4516452b5b0f8080f696a6b6880102fe4eeca17a6de138818d95a548906ea4c5a2a25d773176151d82218175d20b0e8080f696a6b68801027837f7593b800d51f960a87c6daf600df91f6c7ae8d261c91700f5af69befe338080f696a6b68801028fc2af3afb2bcb9a734401d49df9fb09a8ae49c77cfa4ae88ec81edc13e7af5a8080f696a6b6880102572e0bf6acb089ce9afad10625e96ee0efef457fab183009871c1c547ce4f0438080f696a6b68801021eb358b1c5ea00b33485a3d4655a54ece3158f00410b52dc278431c835d36dc48080f696a6b6880102ccea70c2067e4ca0aa5a06f90a6c2005c32aeaafb049d051472cd1d76491a7558080f696a6b688010299b7332d806553f3ddb45d2447ebea006de1014e4d2646b5b8f4eb400c96c3ea8080f696a6b6880102ab9eab7e57ae591e0cf72e4bbfc4b16942f725991bd00ebdcebdb3f73c8240df8080f696a6b6880102848977adee172dae13e29c1bd70c6d2e601296411cb6ce717999ee1faa5802a28080f696a6b6880102b58a9d47e1435f46b87e6f0b8b43c2c4e6a77ddbfcc1a757c9e31a583a66dc1b8080f696a6b68801027fe5757b60b14254e734f512185ee5f6494a58c7458508d9f31cefdc3101568a8080f696a6b6880102eb1cdcc324c47797d401e61f3e5d6719b3ee1991b12361d2f0e9376b4914359c8080f696a6b6880102058df2cca4289ccecbb2ed3c240d1696692b86e640279cfe3a613ca47b3f84158080f696a6b6880102524eda186eb708c8124e7faa89c283845a304a2da3600959b5dd3182ad5aec578080f696a6b68801022d3bdcd24ebfee1ca04ad05cb44732c29c0b51a04211a829065101ef89712b8b8080f696a6b6880102b7d11202c4472d2fc28fa97572938a15cb88ac7eba403f6a05da1e55f4b52bdd8080f696a6b68801027b979a8febab1722fc8032c6dc1ce9fb0b4189be300ebc4e2c47fd00dd43e2668080f696a6b688010262929c71a054f4a878ef75dcfc08e4f38f438dc588e5ad0959d0b28131a9ac778080f696a6b68801021efcd281fd98938bc694badd4155571ca67206077409531fedcca0d28e63cb088080f696a6b6880102cf380037918262396e51289d5442bc034c825a12bd4cb434f8130f923062f9bb8080f696a6b688010273822e94474c2da6ece0d6f631d4aa22271616a8ebc9a7a62264d09fb6a5a17e8080f696a6b68801029b3871ba934014685533c5cc45763f674deb9749b3a3b4850a2a0db61bac0d59210136f4df1446faf47389f209e9fa36e250c2e823deb9ba8d959e3a819d9e357c6500"sv;
    inline constexpr uint32_t GENESIS_NONCE = 12345;

    inline constexpr uint64_t GOVERNANCE_REWARD_INTERVAL_IN_BLOCKS = 1000;
    inline constexpr std::array GOVERNANCE_WALLET_ADDRESS =
    {
      "T6SdCrA7XkP9tvDmQFKjChE7r4XS5JD4x9cawYqEWYmUFoQzPoqMcQ8hqw6aEzWVLEbCCcvjV8DjxF8Gxm2Vi9My2hxRDs47q"sv,
      "T6SdCrA7XkP9tvDmQFKjChE7r4XS5JD4x9cawYqEWYmUFoQzPoqMcQ8hqw6aEzWVLEbCCcvjV8DjxF8Gxm2Vi9My2hxRDs47q"sv,
    };

    // Testnet uptime proofs are 6x faster than mainnet (devnet config also uses these)
    inline constexpr auto UPTIME_PROOF_FREQUENCY = 10min;
    inline constexpr auto UPTIME_PROOF_VALIDITY = 21min;
    inline constexpr uint64_t BATCHING_INTERVAL = 20;
    inline constexpr uint64_t SERVICE_NODE_PAYABLE_AFTER_BLOCKS = 4;
  }

  namespace devnet
  {
    inline constexpr uint64_t HEIGHT_ESTIMATE_HEIGHT = 0;
    inline constexpr time_t HEIGHT_ESTIMATE_TIMESTAMP = 1597170000;
    inline constexpr uint64_t PUBLIC_ADDRESS_BASE58_PREFIX = 3930; // ~ dV1 .. dV3
    inline constexpr uint64_t PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX = 4442; // ~ dVA .. dVC
    inline constexpr uint64_t PUBLIC_SUBADDRESS_BASE58_PREFIX = 5850; // ~dVa .. dVc
    inline constexpr uint16_t P2P_DEFAULT_PORT = 13011;
    inline constexpr uint16_t RPC_DEFAULT_PORT = 13012;
    inline constexpr uint16_t ZMQ_RPC_DEFAULT_PORT = 13013;
    inline constexpr uint16_t QNET_DEFAULT_PORT = 13014;
    inline constexpr boost::uuids::uuid const NETWORK_ID = { {
        0xac,0xce,0x69,0x5a,0x62,0x9c,0x44,0x90,0x81,0x0c,0xe5,0x01,0xa6,0x6c,0x31,0xc6
      } };
    inline constexpr std::string_view GENESIS_TX = "03651e00e0a801c0d102a0fa0380a305e0cb06c0f407a09d0980c60ae0ee0bc0970da0c00e80e90fe09111c0ba12a0e313808c15e0b416c0dd17a0861980af1ae0d71bc0801da0a91e80d21fe0fa20c0a322a0cc2380f524e09d26c0c627a0ef2880982ae0c02bc0e92ca0922e80bb2fe0e330c08c32a0b53380de34e08636c0af37a0d83880813ae0a93bc0d23ca0fb3d80a43fe0cc4000e0a801c0d102a0fa0380a305e0cb06c0f407a09d0980c60ae0ee0bc0970da0c00e80e90fe09111c0ba12a0e313808c15e0b416c0dd17a0861980af1ae0d71bc0801da0a91e80d21fe0fa20c0a322a0cc2380f524e09d26c0c627a0ef2880982ae0c02bc0e92ca0922e80bb2fe0e330c08c32a0b53380de34e08636c0af37a0d83880813ae0a93bc0d23ca0fb3d80a43fe0cc40001e01ff006580c0dc8df9ecc5b80102dc26faa674b6abb5f4b82c46eb054e4967c338e8e746a3626ddde163c92af34180e09bf2ec8dda02028cb013ce7b645d186ca08f8e7463db4c7d63b407354d42d38f52c5233d8bdbad80e09bf2ec8dda0202d189b22a90a0776a37abaec353a78ff7331332a49939c2425e9c61ea0b1e57b380e09bf2ec8dda02026c540c44e6e965709cf826d1295fe0e12fac8beae053ab74649daa419ccaabc480e09bf2ec8dda02027ce06f1ecac3741610d6e9b54d1eb8933591fec3cf0825a86f4fa5b16a52ec8880e09bf2ec8dda02023a1b44d883142c0407d527141d859be1798a05ccec6f1ec0d9fa47fd4c009e5280e09bf2ec8dda0202292ec4814bbe3fb838a64ec825e7344f5606b282b23545489dd3f2df1f9882b280e09bf2ec8dda02020b2e8bb688ef3225987c7627c6989cda161da626756418edbc67507d4776819a80e09bf2ec8dda0202467e966e9d64f75ee44fe6f77be888c146ff11fe04f4516a522d64c57603eede80e09bf2ec8dda0202b4a19a5c9ba29979fe5514993d118d2530e643b8128a5530f86dbc9e348f3c0f80e09bf2ec8dda0202dbfda7302c0ad657f4b7036208bf7f7ee3a17fc5a94843c34e7f1eae78b244f080e09bf2ec8dda0202dcb59a19cccc5f7fec7c0921aba80e6760f46d784ab3af22ab29d9e432d4cdc480e09bf2ec8dda020265a362ee016fdbb89b260945785c541e68cad7d5305081ee1074a8a54e29b5b480e09bf2ec8dda020219b23ed5c7d688212090b81076f085269096231f7b055ff41ca030bd068ebfcd80e09bf2ec8dda0202f87acd68710ed21634069cf24e8ce9114903b0b56cab76d534d503d6f75fd1b680e09bf2ec8dda0202f2a40f9bd71b50deea8f54313ab33e8aad7a7efafec923849515ab486dc4ae6d80e09bf2ec8dda0202659cab0b84811e633ef2e256ecb2ff38ef14fe67b063e2e15afb068a502d653180e09bf2ec8dda020208a697fa9561ff24b8a1f111b667892f76a4effa062d7932ffa8d0adf687c9b580e09bf2ec8dda0202af84c03c7a4bff7352fd59845d521795fec5cd1d643bedd8d52858bbc830c86080e09bf2ec8dda0202f9a797ac519f46435ffc7d8e4fe1f6e11ead610e7d0ebfc3ad24f56f875a7aa480e09bf2ec8dda02028c3b7720aba1f316b8a78c7289d8721053f70ef6f5a9969504666c87c7263ec680e09bf2ec8dda0202fa25d7d9f2e546174952dc01412f9d9a86c8d3bd1a4b9df6d5a8fbe07ed2d6c880e09bf2ec8dda02027e40e215ba268ff5b2ecc004739d0f24d6c8b5a2de62b503131d510df52cdef280e09bf2ec8dda0202f00d3ca4d71a0d31fa8a88913c5331db8e759d77966f477d63d1ee129eab1eca80e09bf2ec8dda020273f4c7b4e8e114b33c5efa04a45b15e2ba8e75e465cc226ada5966021abfd21780e09bf2ec8dda0202c11e4fe4f23b4be7810bd27f58c5e94ed6ecf8e5f21c23e86ddf47f46867125e80e09bf2ec8dda02026e3bdb736fd6327e5d2373b390480bb80e01429d81c03ee566c86d32fb44cc3580e09bf2ec8dda0202dd63b3e80bcf73ba22eafc6195a27b0911b1170dd3fd6742ec27ebb730e985bf80e09bf2ec8dda02027f8a221380e1933c1af2bd672f98efc5112bf9a9c66ac8ee18c75a5708a5164180e09bf2ec8dda0202253bbf554b8cff3ac594f16206cdf80058ba1a184eee4f18ff119bccb3c6266180e09bf2ec8dda02020854fa99719a0f0e6262bde7dbeca4398f005c44edaf1c9264548a0a55a1381580e09bf2ec8dda02024e7a8233a5074c60185dc238724d9a54c4e435b2750e3e1144b8d5289f5f943480e09bf2ec8dda0202f5eed25828744985b83d999083e384152e5d9eca837984d1f9b499c99997819580e09bf2ec8dda02023baf48e9285eea09df761fe466e200044378a6bd716dcc3ae279acf8ae8bb4cd80e09bf2ec8dda0202bb9d71d521cc5d692a530f5d0ec15bbed9221f283c17f30097de7ef9070fc65680e09bf2ec8dda020277810d7552cd536760aa3ee9a20b4013d42a13e2f1ad63cda20461eab1ae200f80e09bf2ec8dda0202e5bdb54ae4b5fb2dafae077f41beaaee4631e6e189f45b14b32f31070f5f701080e09bf2ec8dda0202d6b165f4d5c14c442a6117b464f415949ca4464cd30d1d2147646058fa9e1b5d80e09bf2ec8dda0202b7c110e9d9096668b8d4333277ac6c8a52588b5a4b6d70ea06351a0670f5f4a480e09bf2ec8dda0202783377b09ddeb5f2533302a6b87e982416807b38f3ca775730bf5fc2141e935580e09bf2ec8dda0202516edd27f99ab476b160a343b5da55cd4ff2033a23bcbc1124d4bfb65417dfd980e09bf2ec8dda02021824d89c954695249cd2bb15017474b330b3a2fd4c68d2f5fa0050790297275b80e09bf2ec8dda02025a38eb5873b3390c73f45330e2b15d206eb0ffafd6c95e3ec9836b4d6ee997cf80e09bf2ec8dda0202982f4df2efd3e01070a24a0ecec2b513dc8e9219caffb581def0f73e13c1cc1c80e09bf2ec8dda0202b1d43eab2fb2a6b5d6db14786828f4dae005deca8498e714e3a78829361fd1f280e09bf2ec8dda0202071100b091ca9e83f74a23f207de45d8f42dac8c9b5ef2aa26d627b409de3f9d80e09bf2ec8dda020244968c827cd56b07287636c6f8a1af3335f6c092250e7b0005ac9b214832efd380e09bf2ec8dda02024a5ecf1fe22879a7ccffe59f56066d42acb4d5fd4fbc8a52b7f920b3550189ea80e09bf2ec8dda0202d853c204ef473f510a4a168704e24a5bab7a690000222f4c46c71b1428c2f4ff80e09bf2ec8dda0202dfc5c86c739c7f7b6a1a79a74b47cf37b99f3a981c162d8bfd4d21c065feb19180e09bf2ec8dda0202b0f91b9ab60d946a2e3f4eb1ff8e95b78f57be425c729382899c4fe58b5fd8048080f696a6b68801021ff031b7f9fdfb73eef7a8b19a263259ae2b82e0cdb6101b62c89ed90f3151668080f696a6b6880102020d4fce5532d252063349685178ac9abd45aaf1308798e85078f9c90ff2a0758080f696a6b6880102c893af2bc92279eace5af9ca62029ff616135ce6c2772566df4e13d18fb3369c8080f696a6b6880102b72955219dc04ffc6f418c917390ec39a41a1e20f373ff75ab331b3b6ddabd638080f696a6b6880102014b01f5e2efe5ba3a370e95792d596cfb5a1ae361f4a5d7b19a4489d2382e198080f696a6b68801022c9423ae45d6448ba10cf8650ef6f7337f9829a06193c16ae007c1df008bb7018080f696a6b6880102d3b522457744edc98a532800a74ebfb0a4b8a61d9d2df622162d58a2425b83fa8080f696a6b688010248a3101632fa36c5a3e633f84e3a646ac46e4e50af8e3b18340cb143072fdc188080f696a6b6880102dfc6250393be3327defa9405957fb3e6577823fae5464b445971995587e21b6b8080f696a6b6880102bc04575e4f82cd095dac5612d129a5ff89e932dab9e942a08731a01bd35182e68080f696a6b68801026528831b4df5e152ceaa0a261fc524dbde028c0e3b923e15136568c835a30ec88080f696a6b68801024a749cea474782a6bf47335993e35bb10ec70e427eaf814a57e9c17075a2ba4f8080f696a6b6880102ffee087b029809c101b7bbbcf3b27b67c582070d740570a96955f749251ea6a28080f696a6b68801023be1c19e96649d5882181711d411ee36b076c9f115c9e26eb3f322545b21bfc48080f696a6b6880102a56b66159bf27d1dd0714b0c7b473c1fa3bf246431ed8fda2c5c27f7d8a4f2408080f696a6b68801020fecebfc35ee4c37fe8b04c645f7b993a159a2c9ff2121566974e6b36fa35e898080f696a6b6880102192fd12bca16c59e5668448a71ffd4a15aacbb764c6096dbe322653d99005eb88080f696a6b688010218c18a390efc7ea06ba70b92e05810ecf325c299d6b0ef0d4ce8fe2da8b299258080f696a6b68801024e03317c799575f98cdf762f066964758e4f2787af0e826c491f330e0a50a3378080f696a6b688010216865165c9a78e048b2a3fcc0e323984d20845d9c369d5a087cdc3e36acdea5d8080f696a6b68801021e95e46c1ad016e1286feaa9584f46418ddff72297f0cfea4cd789dd0b6f85238080f696a6b6880102f477e450b57f79f3ba2980f43fb4458e5dd2eca1d1dd4d1edc1bc859aac1199c8080f696a6b6880102e4699929b9ca7617b56bfa2cdbd5a6b35c74f9381fbab8fdf2f83e2b774ac1b68080f696a6b6880102c57ce042e716caffc9fa5ffff860c8254a0963d68d1f183199845ddc38a17aac8080f696a6b68801025cc9f7d4dd7ff32525765154da8a053705c94aba2b2998eeda1f00ff939512a18080f696a6b68801027f0854c2647597f23e2e117b83f183b596a5dcbf2e34e934d17ad0be589949658080f696a6b6880102d5d9924bfff480939f3c85b4c2b6a85d3a3172b35ff7964d116d1c2d86f191958080f696a6b68801023f214c3b44947d6e28e2e058d756d30407777e9e1f8773ea6672906f5b5e51a28080f696a6b6880102e833d21ad9532a15550e4772012cfd3b8e60bbc007fc65d4f37ebd46922f2fd48080f696a6b68801026eabfdd51583b4e9f466dcdb5c0450bddf66f03f37e96b5cec1142d58f66f62f8080f696a6b68801025eaa477555d868c74f0d28c6994be7ee3d6e7e2e6bc599087d3900073c167eef8080f696a6b68801024e309784de30fcab3edbb3e06bfb74afbcd2c73bae5b7b7ad60bbf6b88fe76ab8080f696a6b68801025ebe27fb6982264509cc5bf88d99f92301bec1bac7fa39e5ab41aa1f7be7cad08080f696a6b68801022164a08530b7652ba2d36eca756ea941aa75a9231398c6627f210c0657086f0b8080f696a6b6880102a2e2b5400aa8607e4224bc5a1f00f1994f0844e27433e737bc03ee42dd48df9d8080f696a6b68801028dde3200def51ab371240b5f37fdd558016a0ca01dfc75248bcc0f09c85f6b0b8080f696a6b6880102a9a90495f81ad871ba1e69286ef227da4f579451b893132f9fdb0ae3a83f0de58080f696a6b68801025387cfb93746e54417c2e0cde5e5a95d37f3e194fc78ceed369fcf272dd38eed8080f696a6b6880102acbd97a369bf952582857b4a6ffc009c0581ce0acc33998c9cb2213c067b6c5f8080f696a6b6880102af25f1b23c08ffc405f857129675b7f532ba596134785634a3af173314fd86788080f696a6b6880102b01bc00d11193caf952c4b3bd0d0479c121a3bcd61d81b56e94bffbf05e848618080f696a6b6880102014d155d6cd94c980efba8fe3cc69ea53799696c1196e9351700449bb30d0b138080f696a6b6880102a64b518c33d46d6385ae5ebfbda00ff7ee7e8ca46d8a66dbd99bada1106289358080f696a6b688010204ab953b5933f15cc093db86d51ee42791efa591de41c9bb4b6a7da098eb83e28080f696a6b688010241c9121a7cdcfaa2236c24de6c2a07473b384a3621b1bc9127905bb04bdce7cb8080f696a6b688010288655c13d330dbf85b8f7abfb3ae8ef0a2115c122ed5b056387b8a0b1ee3287e8080f696a6b6880102fc0110758024a60a2369733539d637a6e2dd06053cc7e2c30c2206541267a77f8080f696a6b68801021a05f84d5542cc563c57e50e54bbec1b9ea32b5988557b663b6b3103e190089d8080f696a6b68801029044bbb361eefb44ba39948d9b614484efc1df0dc9ec05060c5055135d533bda8080f696a6b688010203b9b06f509a5871b72f63df3030a3fccde0727eadb096a4a4bc28609a01cd762101619e7abb579c272826c1767a167760db5f53ac23f4d890648fefa80513da823800"sv;
    inline constexpr uint32_t GENESIS_NONCE = 12345;

    inline constexpr uint64_t GOVERNANCE_REWARD_INTERVAL_IN_BLOCKS = 7 * BLOCKS_PER_DAY;
    inline constexpr std::array GOVERNANCE_WALLET_ADDRESS =
    {
      "dV2518qeonT9tvDmQFKjChE7r4XS5JD4x9cawYqEWYmUFoQzPoqMcQ8hqw6aEzWVLEbCCcvjV8DjxF8Gxm2Vi9My2hxQHKBPp"sv, // hardfork v7-9
      "dV2518qeonT9tvDmQFKjChE7r4XS5JD4x9cawYqEWYmUFoQzPoqMcQ8hqw6aEzWVLEbCCcvjV8DjxF8Gxm2Vi9My2hxQHKBPp"sv,// hardfork v10
    };

    inline constexpr auto UPTIME_PROOF_STARTUP_DELAY = 5s;
  }

  namespace fakechain {
    // Fakechain uptime proofs are 60x faster than mainnet, because this really only runs on a
    // hand-crafted, typically local temporary network.
    inline constexpr auto UPTIME_PROOF_STARTUP_DELAY = 5s;
    inline constexpr auto UPTIME_PROOF_CHECK_INTERVAL = 5s;
    inline constexpr auto UPTIME_PROOF_FREQUENCY = 1min;
    inline constexpr auto UPTIME_PROOF_VALIDITY = 2min + 5s;
  }
}  // namespace config

struct network_config
{
  network_type NETWORK_TYPE;
  uint64_t HEIGHT_ESTIMATE_HEIGHT;
  time_t HEIGHT_ESTIMATE_TIMESTAMP;
  uint64_t PUBLIC_ADDRESS_BASE58_PREFIX;
  uint64_t PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX;
  uint64_t PUBLIC_SUBADDRESS_BASE58_PREFIX;
  uint16_t P2P_DEFAULT_PORT;
  uint16_t RPC_DEFAULT_PORT;
  uint16_t ZMQ_RPC_DEFAULT_PORT;
  uint16_t QNET_DEFAULT_PORT;
  boost::uuids::uuid NETWORK_ID;
  std::string_view GENESIS_TX;
  uint32_t GENESIS_NONCE;
  uint64_t GOVERNANCE_REWARD_INTERVAL_IN_BLOCKS;
  std::array<std::string_view, 2> GOVERNANCE_WALLET_ADDRESS;

  std::chrono::seconds UPTIME_PROOF_TOLERANCE;
  std::chrono::seconds UPTIME_PROOF_STARTUP_DELAY;
  std::chrono::seconds UPTIME_PROOF_CHECK_INTERVAL;
  std::chrono::seconds UPTIME_PROOF_FREQUENCY;
  std::chrono::seconds UPTIME_PROOF_VALIDITY;

  uint64_t BATCHING_INTERVAL;
  uint64_t MIN_BATCH_PAYMENT_AMOUNT;
  uint64_t LIMIT_BATCH_OUTPUTS;
  uint64_t SERVICE_NODE_PAYABLE_AFTER_BLOCKS;

  uint64_t HARDFORK_DEREGISTRATION_GRACE_PERIOD;

  uint64_t STORE_LONG_TERM_STATE_INTERVAL;


  inline constexpr std::string_view governance_wallet_address(hf hard_fork_version) const {
    const auto wallet_switch =
      (NETWORK_TYPE == network_type::MAINNET || NETWORK_TYPE == network_type::FAKECHAIN)
      ? hf::hf11_infinite_staking
      : hf::hf10_bulletproofs;
    return GOVERNANCE_WALLET_ADDRESS[hard_fork_version >= wallet_switch ? 1 : 0];
  }
};
inline constexpr network_config mainnet_config{
  network_type::MAINNET,
  config::HEIGHT_ESTIMATE_HEIGHT,
  config::HEIGHT_ESTIMATE_TIMESTAMP,
  config::PUBLIC_ADDRESS_BASE58_PREFIX,
  config::PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX,
  config::PUBLIC_SUBADDRESS_BASE58_PREFIX,
  config::P2P_DEFAULT_PORT,
  config::RPC_DEFAULT_PORT,
  config::ZMQ_RPC_DEFAULT_PORT,
  config::QNET_DEFAULT_PORT,
  config::NETWORK_ID,
  config::GENESIS_TX,
  config::GENESIS_NONCE,
  config::GOVERNANCE_REWARD_INTERVAL_IN_BLOCKS,
  config::GOVERNANCE_WALLET_ADDRESS,
  config::UPTIME_PROOF_TOLERANCE,
  config::UPTIME_PROOF_STARTUP_DELAY,
  config::UPTIME_PROOF_CHECK_INTERVAL,
  config::UPTIME_PROOF_FREQUENCY,
  config::UPTIME_PROOF_VALIDITY,
  config::BATCHING_INTERVAL,
  config::MIN_BATCH_PAYMENT_AMOUNT,
  config::LIMIT_BATCH_OUTPUTS,
  config::SERVICE_NODE_PAYABLE_AFTER_BLOCKS,
  config::HARDFORK_DEREGISTRATION_GRACE_PERIOD,
  config::STORE_LONG_TERM_STATE_INTERVAL,
};
inline constexpr network_config testnet_config{
  network_type::TESTNET,
  config::testnet::HEIGHT_ESTIMATE_HEIGHT,
  config::testnet::HEIGHT_ESTIMATE_TIMESTAMP,
  config::testnet::PUBLIC_ADDRESS_BASE58_PREFIX,
  config::testnet::PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX,
  config::testnet::PUBLIC_SUBADDRESS_BASE58_PREFIX,
  config::testnet::P2P_DEFAULT_PORT,
  config::testnet::RPC_DEFAULT_PORT,
  config::testnet::ZMQ_RPC_DEFAULT_PORT,
  config::testnet::QNET_DEFAULT_PORT,
  config::testnet::NETWORK_ID,
  config::testnet::GENESIS_TX,
  config::testnet::GENESIS_NONCE,
  config::testnet::GOVERNANCE_REWARD_INTERVAL_IN_BLOCKS,
  config::testnet::GOVERNANCE_WALLET_ADDRESS,
  config::UPTIME_PROOF_TOLERANCE,
  config::UPTIME_PROOF_STARTUP_DELAY,
  config::UPTIME_PROOF_CHECK_INTERVAL,
  config::testnet::UPTIME_PROOF_FREQUENCY,
  config::testnet::UPTIME_PROOF_VALIDITY,
  config::testnet::BATCHING_INTERVAL,
  config::MIN_BATCH_PAYMENT_AMOUNT,
  config::LIMIT_BATCH_OUTPUTS,
  config::testnet::SERVICE_NODE_PAYABLE_AFTER_BLOCKS,
  config::HARDFORK_DEREGISTRATION_GRACE_PERIOD,
  config::STORE_LONG_TERM_STATE_INTERVAL,
};
inline constexpr network_config devnet_config{
  network_type::DEVNET,
  config::devnet::HEIGHT_ESTIMATE_HEIGHT,
  config::devnet::HEIGHT_ESTIMATE_TIMESTAMP,
  config::devnet::PUBLIC_ADDRESS_BASE58_PREFIX,
  config::devnet::PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX,
  config::devnet::PUBLIC_SUBADDRESS_BASE58_PREFIX,
  config::devnet::P2P_DEFAULT_PORT,
  config::devnet::RPC_DEFAULT_PORT,
  config::devnet::ZMQ_RPC_DEFAULT_PORT,
  config::devnet::QNET_DEFAULT_PORT,
  config::devnet::NETWORK_ID,
  config::devnet::GENESIS_TX,
  config::devnet::GENESIS_NONCE,
  config::devnet::GOVERNANCE_REWARD_INTERVAL_IN_BLOCKS,
  config::devnet::GOVERNANCE_WALLET_ADDRESS,
  config::UPTIME_PROOF_TOLERANCE,
  config::UPTIME_PROOF_STARTUP_DELAY,
  config::UPTIME_PROOF_CHECK_INTERVAL,
  config::testnet::UPTIME_PROOF_FREQUENCY,
  config::testnet::UPTIME_PROOF_VALIDITY,
  config::testnet::BATCHING_INTERVAL,
  config::MIN_BATCH_PAYMENT_AMOUNT,
  config::LIMIT_BATCH_OUTPUTS,
  config::testnet::SERVICE_NODE_PAYABLE_AFTER_BLOCKS,
  config::HARDFORK_DEREGISTRATION_GRACE_PERIOD,
};
inline constexpr network_config fakenet_config{
  network_type::FAKECHAIN,
  config::HEIGHT_ESTIMATE_HEIGHT,
  config::HEIGHT_ESTIMATE_TIMESTAMP,
  config::PUBLIC_ADDRESS_BASE58_PREFIX,
  config::PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX,
  config::PUBLIC_SUBADDRESS_BASE58_PREFIX,
  config::P2P_DEFAULT_PORT,
  config::RPC_DEFAULT_PORT,
  config::ZMQ_RPC_DEFAULT_PORT,
  config::QNET_DEFAULT_PORT,
  config::NETWORK_ID,
  config::GENESIS_TX,
  config::GENESIS_NONCE,
  100, //::config::GOVERNANCE_REWARD_INTERVAL_IN_BLOCKS,
  config::GOVERNANCE_WALLET_ADDRESS,
  config::UPTIME_PROOF_TOLERANCE,
  config::fakechain::UPTIME_PROOF_STARTUP_DELAY,
  config::fakechain::UPTIME_PROOF_CHECK_INTERVAL,
  config::fakechain::UPTIME_PROOF_FREQUENCY,
  config::fakechain::UPTIME_PROOF_VALIDITY,
  config::testnet::BATCHING_INTERVAL,
  config::MIN_BATCH_PAYMENT_AMOUNT,
  config::LIMIT_BATCH_OUTPUTS,
  config::testnet::SERVICE_NODE_PAYABLE_AFTER_BLOCKS,
  config::HARDFORK_DEREGISTRATION_GRACE_PERIOD,
  config::STORE_LONG_TERM_STATE_INTERVAL,
};

inline constexpr const network_config& get_config(network_type nettype)
{
  switch (nettype)
  {
    case network_type::MAINNET: return mainnet_config;
    case network_type::TESTNET: return testnet_config;
    case network_type::DEVNET: return devnet_config;
    case network_type::FAKECHAIN: return fakenet_config;
    default: throw std::runtime_error{"Invalid network type"};
  }
}

}
