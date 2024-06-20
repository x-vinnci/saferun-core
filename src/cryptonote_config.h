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
  inline constexpr std::string_view GENESIS_TX = "03651e00e0a801c0d102a0fa0380a305e0cb06c0f407a09d0980c60ae0ee0bc0970da0c00e80e90fe09111c0ba12a0e313808c15e0b416c0dd17a0861980af1ae0d71bc0801da0a91e80d21fe0fa20c0a322a0cc2380f524e09d26c0c627a0ef2880982ae0c02bc0e92ca0922e80bb2fe0e330c08c32a0b53380de34e08636c0af37a0d83880813ae0a93bc0d23ca0fb3d80a43fe0cc4000e0a801c0d102a0fa0380a305e0cb06c0f407a09d0980c60ae0ee0bc0970da0c00e80e90fe09111c0ba12a0e313808c15e0b416c0dd17a0861980af1ae0d71bc0801da0a91e80d21fe0fa20c0a322a0cc2380f524e09d26c0c627a0ef2880982ae0c02bc0e92ca0922e80bb2fe0e330c08c32a0b53380de34e08636c0af37a0d83880813ae0a93bc0d23ca0fb3d80a43fe0cc40001e01ff006580c0dc8df9ecc5b8010250923927f3a573bf6c9094a9b45eb724854bf33110583970e0bc85f9e48f0fec80e09bf2ec8dda0202a152a51cc82d9d0085ac6fccfa64e264c3528ddd29b02acc72fa1671576cb9da80e09bf2ec8dda020230201a28c95781d9802214ad06345a083c67eb0e265bf14c134041141230b07080e09bf2ec8dda0202ee5103774e1d3c437be41b655cb0d32f33ed6a3f98e994d5c92921cb6b3c773380e09bf2ec8dda0202dfe52e4a9cc62144df55006f5735721197c38aef401b93f34bbeac9004f8357680e09bf2ec8dda020290685f9cb5a67755454657d57dc0c0ff40197039367c4e2d05409c012e72536f80e09bf2ec8dda0202159fc6c1d09a56d0d8f12e00ac5c5926cadc18ef25606b2ce1056e4dc26d5a4480e09bf2ec8dda02020d4915d795b6e9476b17d787b3db1c9f95f35ffb0c4451728db09817346fa91180e09bf2ec8dda0202b4007d1ba6b8b311f3e1733d56302ec47f61bfbe057944f3ff631eaf7497b08580e09bf2ec8dda0202f14138c2b1888c54ecbdbe1896f5b979ac330a922c180c3c752a7e14c50de2a780e09bf2ec8dda0202b0fa567cb4d8d48d202201042e9cdf13cfb91ff69d8fafdefe6aca42e7d2870e80e09bf2ec8dda02022f5d97f003475a5f4e967d04c614e6d2abdd10d9ccec653276229bee261791f380e09bf2ec8dda02027fe3e3ca739d1fb8c464810b4785db9e50f7f6237b04552b659b542839df962f80e09bf2ec8dda020274c4790e3babf0a086386ceb6f4bf03b865d67ac318d8552a2bff2a1601bb7b480e09bf2ec8dda0202fd694c13c98db6cc4e9ddcaae7bc1c09ea7c6c7cb8f0eaa9eec4c42937cb828b80e09bf2ec8dda02028d95335ffad530862f8eaf5cfd5598f58e719c000b777db66c684ffe85c036ba80e09bf2ec8dda0202c85b3ed6112b25218d44078294a4da4029927cccc6475aed47fedf6a1d5dda1a80e09bf2ec8dda020258b0947f4f5e33f7672a0687a2f987558bd97312ba199e0365ea97aa2ee635e580e09bf2ec8dda0202b06a3deb49446be62d82e36d4e6a47adb3ac03d1292ac44eeee1d3dc09020c2b80e09bf2ec8dda0202a32c220d1cdbc09169506d4e3be6b43402cf9dca9fa0af82c0328b78d98c012480e09bf2ec8dda02026045d63046e244f960ffd4b955f464a45810b5c8df2f6bf68edfcf9f6351426280e09bf2ec8dda02024dda1d0c4aa8392905c5e42b983dc2162e037a5512c41a4241769420cba4791a80e09bf2ec8dda0202a078dba517d326881dd7c9984b62cca97ce54e8fa6afe0705f6b5f6e0f6337c380e09bf2ec8dda020250366ed6e63a21c816284196e76d07fba1cfe67e4c4be6e670b5bd110abf97ed80e09bf2ec8dda020223ab33f3480f007f887b09ba4f56716e5f27cd1549830ad4e97ade47a34b325680e09bf2ec8dda0202d53623dfea112aa3be0fbcac8da74ebcebdc35e7cdf0b6e66d138d7600b7e6cd80e09bf2ec8dda0202e2da166c073d4454391eb54ae628abc0dc0587620e6697c0b79dc1055e66c0b580e09bf2ec8dda02024e3151e2b2733717828c29efbb462aa6184b8859a6775c91fc77c6b0af6048ec80e09bf2ec8dda0202c7da8cb42d16bc6ac1b26c365d74b49b68c93bbd2c0dd26ebea37475fbfa0cb380e09bf2ec8dda0202609f5ed6022dd24de7afced8736dcc05176549c87f98bd413ba049a23fe84e0380e09bf2ec8dda0202512fd24d7f03eeeb8169640009f2dd9f9ade44ef16a950bc53fe823a39116e0980e09bf2ec8dda0202a1c8a3675ebd2a70b7ded841e5ca3853794b37f8afff08871c1f49e285b6d30780e09bf2ec8dda02021c4598c841ffa53ef4c43900e992cd1a351a9b5abaf3c2c35f7b3b72825d25d380e09bf2ec8dda020297e99c789a479ca821656c04bf499c059f7468d470cc229486c95c9087dfe1c280e09bf2ec8dda0202552253a12c3987a5ed4e9ad3d4b8fbcdc0448e90970cdc1d3d974560d3fe9d2b80e09bf2ec8dda02020b506336c12d9084655fb4fcee03d8eb68e16b035e737878c50d7e2519cca15d80e09bf2ec8dda02025d88711b511dc092a40193cbbcfddf773254aa93b51384cc3895fbde8e3490c080e09bf2ec8dda020279324a4870cc10bf19c58a5b1d52b93bd100933bf1e700f24154a4c64d68147d80e09bf2ec8dda02024c4b87e7b04deb2cfa91d631a9e1b620061ada5883dbf4dff8a990bc26db583b80e09bf2ec8dda0202222e5091cb2629f7502e83efc7df9a3fa29eca2faaaf805bd8e944047aabb58980e09bf2ec8dda02021af4bfcde7118814a41574846d2fad3b029db7a80246588a4bafe072645373a380e09bf2ec8dda020264a12d37cd4a27c8d587908be28371f040769125f1bfe30c2ee9744fd827c3b580e09bf2ec8dda020218b044f2f73d433e7ede473de8a878fa502722a64cb4b3c90f7e4b54bbb90f4680e09bf2ec8dda02024fde8a51ed2baaaa521f5d102e49121957b1d9045ddee8a267d0ee1e9738782580e09bf2ec8dda0202db8f3e1963f438f60a3c3b3aa1a5342576575138cc26ecf87c3d2a2beb75e16e80e09bf2ec8dda0202c6c1fdc69e8368feb8e561ec681a17e1a2dfc99e2470ced8ef20d85f6a478c2b80e09bf2ec8dda020244e943ada06f1c99490454ab86d9f35a055caee302a6cae63fbd1d5cbdd2df5380e09bf2ec8dda0202a93de14c9c0659b6105d01e8c454648a22714a23c5f6c94bf05ebf0e20d75d0980e09bf2ec8dda0202929a3e20eb7c62f1f88e0170b4d0ea7c6e8d93ad0d549d01ad140760934b532c80e09bf2ec8dda0202a78f3cda69a3336d584111da6b7c2924ac310d54ee60e92d820b5f18f3da566b80e09bf2ec8dda0202b0ce7b0e2b73d482bf513734222fc6f1abb2aa7242d6dd25ff0a27c7c51699108080f696a6b68801027f9c90b34513f3512aa10a4162f91518af8e74255b0a0c3d1f3c8166014536998080f696a6b688010236f9a8f2c1c073614eae32959a6e78423ae7525bd809105bccee1356adfac2778080f696a6b68801021451d2b9773ed6e0c954101dc75215cd3b0f72a8dd86c3cfa644f0d90564bfe98080f696a6b6880102383874cda27e8ca30c1e5b1750808f37942df1d1ce80a0ecfdeb878593ec3ce48080f696a6b68801021d48ed28f83e3b1cf6535d223218f1781e5f5526311b59afe9f471d7decdd6dd8080f696a6b68801026e8045383e85fd527cf293d64877bd30f7247226d77b29bac170ad17b51b8e4e8080f696a6b68801022f14c6f5babfabd652d07cfaabae04644766152606cff1a949e253185321eb928080f696a6b688010231a3ca1c902e3efcc394e45930e56013286907612677c71921e7757385d657f78080f696a6b688010252292ac933272139d2ae64714b09eac1d4d5ed417a6c4fa5c5e0d0377a2c84878080f696a6b6880102aac552c8064ab4ac77f592305674acbdf07a43c927293f03fc35c341d8b8a3188080f696a6b68801029b99891c36a856ef73cfec2362bc9d2f67ef091195fa632aeaa9d856381218198080f696a6b688010226f967bc622a5d0995cc3431cf53d2467c2bdf11fada33244a0e05a93888fea08080f696a6b688010244da88558665b52630c7951a9844ed481baabf2a244150375db96418142578cb8080f696a6b6880102280cd719f68ed6b4cfc8502d0a75f0453f4322223c271d6e3e278c54723c1e478080f696a6b68801027e97a6ac987c3ca5fc546dbc431625eedb91f16f919e1b59766f2a810852d0628080f696a6b688010206c9a20a05da95f9a6a4399065214fd2aa06b594076a96d191c4192e1b012a4e8080f696a6b68801023751287f4755ee9c98a81df7e82eade513b57d252b84e1ad28af6bc83d01c0528080f696a6b6880102de7f895290a13dd83f39348c7243227570648537044178441a1a3fe477d555a08080f696a6b68801026eec30df894c0841c609429bbc455fb82bcbea1f4f2a145216e0fc4ec48cbc778080f696a6b6880102804caae00227ce53ea3326a79aca4da690bf1bfc0b8b2523ec27039cf09f6cca8080f696a6b6880102e7bcddc6e729ba8142bc79b7bc08290243f6fec60b3fd666941ec98e82af78888080f696a6b68801021bd5da30a0644e9a1cb4e6a86fdb123abbcac328cbc4b256527275cd255cbb568080f696a6b68801021021454a5c395b0a19e7f206119d73dd04887e019d2c9c42d93e81225ef6a81c8080f696a6b688010238ba3024d7dd94a4d7ebad5d92927bb2265765caef9f000113c36f1cb310a7208080f696a6b68801029d6df5ab21f48c52c61da999b8f8c15c05e8d9270cb8e1ac8ad9da765d839a138080f696a6b68801022dd276cd5088b322d4bbd2d8ebd52a8d87f01ffdc43de4d964891e53b4fbb8168080f696a6b68801029a459a24407bda811108c833ecc6ccd11e1563a0096bb43276b14415b27da6648080f696a6b688010274b1503374bf026bd378a3d4a693c1c59e259b0ca19dd9e1ad5bdc5486bcdb378080f696a6b688010243c0632e7ccfc7287b8cfebb741c3148037a9f0556e49be24ed23c6ae42299e58080f696a6b6880102e9adf06719ed71e435170a798e552a11af6a969435313f24d139ec3f0c4302848080f696a6b68801024e22daf65cc693f7e1599b2ca44a4fc725b3565c06f643ce8b0058b9dca05abe8080f696a6b688010250c3d7a5cedaea465606f071b8a2d962d7c32657958d867b87d9365f7e96b7ca8080f696a6b688010238ddd4081a4352e6ce356894af9638665aa5ae4b91917c9b15c27af72c88312b8080f696a6b68801027a9b9babe153c8baf307cf8ae805421bec0b6338679d38ed4642fa288fa7a89f8080f696a6b6880102cce985d065126b113d36e5126054eaa1867e2ed0c79663a76f1471acaeac97488080f696a6b68801025878f0de8af1ef9fe7175970a1202ea75817d8964369d474d5a332d88818f0b18080f696a6b68801024fe7efc222b7d26caa73d84c754bef51c7addd8746241172416cbed9247743048080f696a6b6880102a7189e92c525164822f316d938c103abd8fdecdf5cdc2b0836b32145d7d851968080f696a6b6880102ad8880e3c01d34752882ae7310898edb7df801fc9929a1dec98265b67cc984068080f696a6b6880102e2f0eb6ca5bc892f58c3d8357504d453a7b4f10925e22ea8f0e5a0b7bd5a25318080f696a6b6880102f1098f1f3de668492a2bf8bb1c296cea17d36860ee04584dce43661ccffdc4a08080f696a6b6880102e7a88c8061d0b8fa05e4dd2c9f9ee04e47bf441367f67fdcec90ab6c197fb71d8080f696a6b688010204821be8bb1783d3ae93e5b04e35a9af647348d7bff2d26608e0ad7c1146a3a38080f696a6b6880102f36e551a56e057bb18cf3f2efa5aa2ac2ddcff22701565c0e3af917f9d0f38178080f696a6b6880102cfba51e09c1856c325a6f7639323b82bb462449958b67a474fa6445fd48291878080f696a6b68801021d0058f0ad811d0f19f770e41df320bbd5ce045c64ddc7d2fe7c477f6b3b64ea8080f696a6b68801021a8a12cc9f993d51d96a56895f1afe3859ac02faec003c92842b68af4b77dc0a8080f696a6b6880102399cd3f3ec5c04d9eb70a2776b4805ee0730fa2bba194dd00599ab3c2b424a848080f696a6b6880102dd9e2a0ef5f23f6ab834c3ff5ddf1222a6dc851fdd8b49ca3f41456352fc17178080f696a6b68801021b72d7b9256f84a1bae1aee375df2a201bbe1454fb176c0b2c51ac608d063c4d2101185713c97ba6f99043d8308a2b4cd1884637f092151cf87e3871dff31067391300"sv;
  inline constexpr uint32_t GENESIS_NONCE = 3141592;

  inline constexpr uint64_t GOVERNANCE_REWARD_INTERVAL_IN_BLOCKS = 7 * cryptonote::BLOCKS_PER_DAY;
  inline constexpr std::array GOVERNANCE_WALLET_ADDRESS =
  {
    "L9WnGkFycpkg1mJzYBhnKiHofSNRSDZ1CiykUZ5DAgB4M5DeP6PngxMT5CaJVkND25PfEKJechmYkG56EsKFUTgEJY4FdKz"sv, // hardfork v7-10
    "L9WnGkFycpkg1mJzYBhnKiHofSNRSDZ1CiykUZ5DAgB4M5DeP6PngxMT5CaJVkND25PfEKJechmYkG56EsKFUTgEJY4FdKz"sv, // hardfork v11
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
    inline constexpr std::string_view GENESIS_TX = "03651e00e0a801c0d102a0fa0380a305e0cb06c0f407a09d0980c60ae0ee0bc0970da0c00e80e90fe09111c0ba12a0e313808c15e0b416c0dd17a0861980af1ae0d71bc0801da0a91e80d21fe0fa20c0a322a0cc2380f524e09d26c0c627a0ef2880982ae0c02bc0e92ca0922e80bb2fe0e330c08c32a0b53380de34e08636c0af37a0d83880813ae0a93bc0d23ca0fb3d80a43fe0cc4000e0a801c0d102a0fa0380a305e0cb06c0f407a09d0980c60ae0ee0bc0970da0c00e80e90fe09111c0ba12a0e313808c15e0b416c0dd17a0861980af1ae0d71bc0801da0a91e80d21fe0fa20c0a322a0cc2380f524e09d26c0c627a0ef2880982ae0c02bc0e92ca0922e80bb2fe0e330c08c32a0b53380de34e08636c0af37a0d83880813ae0a93bc0d23ca0fb3d80a43fe0cc40001e01ff006580c0dc8df9ecc5b80102a008fdf2b979dc1c2bffc625ce76e1949407efc3d255a787201a84299e31db9a80e09bf2ec8dda0202be46a8f04164913fb87d5669e58d76ae69edf2b11e67e65e2dc59a3f637d46aa80e09bf2ec8dda02020900cec08dea0f9afdd22c9869b1c545644a582a2cafaed595938007c14629a180e09bf2ec8dda0202a633ca8461d061f49d7c32e1675a8aeae5cff3af10a4cdb9ecb70502daf14a9380e09bf2ec8dda0202474a7d6cd2890eba824c1ea7cf813fa7b81d50b389fae5a019a8fe17b869255380e09bf2ec8dda02023b7928bba5dc30392ab11bea118a05e2285a3acb39512094af2cfb859e567a0980e09bf2ec8dda0202aa9a6bbb61f626027a7ea0e3fef45f0fa89512fef2ae604a78e08560e71784b880e09bf2ec8dda02028b2a78b5072d38d72ade3fc5d248c572f9ac0df6b412b241ead61a7edf85a36a80e09bf2ec8dda0202e717e17a8466e10f90c4d06bed44bddaa525dc0948ac76094ddbb5686c729a9680e09bf2ec8dda0202131d1d268c96768764cd91213532c684a533619a2ef1c7f2d6a01e14275dd31280e09bf2ec8dda02020b6b0ef66d9d4c5df8c00e6f0bc3368e5dbe03905707032bf153f11bebf10f0080e09bf2ec8dda0202d7250ae5b0a9ae69863a9c84fcc029b124ae0e748d81c9bda377b3b08c7694b180e09bf2ec8dda0202b3cf63b59867dc5d35c33f351aaec8c623e1bc9e556c090eabf5ab33b1c14c7f80e09bf2ec8dda020291b1b3b767db70c3d396005c2d3c778cdc4445900f169d30da236e8d6523bac980e09bf2ec8dda0202989f5aa5c7f9480974f25757e8179726b7b1484e7c50ebab6b475ccb919a0f8f80e09bf2ec8dda0202983080667831bf811bcbbde9d75f01308e09644ae6709eaf38e8f728cf19118880e09bf2ec8dda020271ca6260d9b850e16fde778b87aed3e9561494f228cc272e670a51943fd6e9e480e09bf2ec8dda0202858f0d5c56b10afa38e47abb59870f1ce3dd4068f1f44d99b4e8f7d16a5b611f80e09bf2ec8dda02026aa576c07747c93a004534b781f2f48df385d92fb83eb2f2c582b84235e8444180e09bf2ec8dda0202157eeb3868c270e01048c64fec0d58f2bbe04c3c7f75be02ce1eb2604af41e6480e09bf2ec8dda0202d286732da53d2acbd8431631a26e45f71031f4d5bab3d5035d65723c29b7fe5080e09bf2ec8dda0202c3ca5a1ff2d733811a526e10c43c590f9b324ae4bcc70ae42eedd92886354bb780e09bf2ec8dda02027caf5c5de811e2830317f609b6923fafceda97f46a2a13e48d83fedb0493841580e09bf2ec8dda0202249f8b955a5e59f7e506664718bbda8f286253e89c4a650826af011917b4d83a80e09bf2ec8dda020217f9353bbaaedd84004ac850652ee99dc0820784c59aded0da6e6479409307d980e09bf2ec8dda0202757f34ec6cc33ebacae6bca8cb8de89128d547c2de5d24a91bb7d2e412fe4fdf80e09bf2ec8dda02021970ee9100cfc51cd025428f5853618e2f625bc33536ebd62075d59f2d3b3ee480e09bf2ec8dda02026c8790ac1b076edc4a4b98d4e9e804b3596555a4677f99af3d0d9a415e8aba1680e09bf2ec8dda02029af69d2e72d102d390eb622cee0d4fe60d5fcd96a438f0df97de8b0aff8fd63280e09bf2ec8dda0202bcd99118a12f5daa3d34089bd9ce1ca0b32dd431d9ef3c6527fac1e9a99f83d480e09bf2ec8dda020296faff4352a3cbee8cfa51f864aa19afeac30fc2b3d10a1b2ed90373a3cb83a880e09bf2ec8dda020277132d4ce96b3e3e7e4905b99cabb49017f5f815a5bb3b2a79585501789d61b380e09bf2ec8dda0202934ba2a1bdff60e2f5f14841925d755783c71ea680d3036fb7220934a8d29c5580e09bf2ec8dda02026b0361d48a109dd3b71602b0ee438f1cbb82e91df266e63a111ea30be607a4fe80e09bf2ec8dda0202d9e24d252ffdfff345ceaded6e93acf293d3b8be893947c1d7c117c05d16ae4a80e09bf2ec8dda0202e33509fa594a90c3d3e1987a9e4305aa5a00457da2ba29d0eb616babf418a32b80e09bf2ec8dda0202f5ba3fc017549885c76c715e0098f5bb576930ae97904fc45873eb29a55d95e980e09bf2ec8dda020287e53db8cec82c8211235f6068ed7af61dff22c8b1d8e8892b3c3efc17893db780e09bf2ec8dda020249ac4b54050b2e3c7492b9324dcf5ca8515f7fc6a9d8bee2160a7ec08b052cd780e09bf2ec8dda0202bb895d2c96d99c6289e123a6a5fe0598849e2ef3ddc8b173ece6df1fde2708b180e09bf2ec8dda02023214ecfd8239219b07281920e21d3123c646dd9be6e34e154f2a217abf38078e80e09bf2ec8dda0202a2abc18d16e3a5b948e8cf4c265e15cd12c9ed0757797d620329f9b50c9f6ede80e09bf2ec8dda0202909f2577a4fb43c66033e69661944923dc21587ed1a51d5980b5c1b0a5a60c2f80e09bf2ec8dda0202da3b7c46301de4d007ee3981def2bd591fa18f902f5ccafeba2146f7d426c89f80e09bf2ec8dda020233e77897eac96b617589ff1c5eb866ccedcafe69ef245df903cddf3eac27281880e09bf2ec8dda0202a1f1c5934ef4a361a15984190d57107b2140b7ad749047bcab6197d1d94694c680e09bf2ec8dda0202b8a2c7434413edba6d89a04136484cd091d5c34d746cc37fa64ee6d48062ff3280e09bf2ec8dda0202d674b92c8385f36d2c76a482e9865e549127aae83fc991001b4e39bc2239b19c80e09bf2ec8dda02021e437b2890169f62b5ca56bd45032d1a1380f9f86bb456a272130a561eefec8280e09bf2ec8dda02022c8acacfeaff90981a2a664a4fed6f65b302550ed28b83061e8a3e37a9ae2e7c80e09bf2ec8dda02021c40621771db97a1ad1dd7bd39779be1ffb7eeac62ddab6979359d4065b3972d8080f696a6b68801028b6a48ba62010e5c434e53a4200e5a22fbf46b439ef93d1557d43d185f8245de8080f696a6b68801020861ccac87eb87892aa4472f23f66e783fb0a1bd9cd555bf22f8c5967e3994a18080f696a6b68801028742d685f4852da0237f91df7b205e04b34e68f1fb4360e4645eb235c751b9b68080f696a6b68801025bd75877cd30d782f1ded64167c1a068b77f0c3f19994d338a7792f1b1f81a098080f696a6b68801027b5339928dfaedf773882b19e0210d0a5148b10fd95140a72195910fc4fb0ec08080f696a6b688010275937a16a562d4eeb50bab2a01512c16ae700830571f380e0d8d923f990af49c8080f696a6b688010211b5ddf5dee493c4535da39ede1a1c93d511e4fa72b142e6f6d1115c95ff56278080f696a6b68801022e3f4e12d4e867a622e48915531c90124cbad62114657c627c7baea2478c02108080f696a6b6880102a797b32f745c6b5f242cb90f459f5d495032307ffdc6e87623924735a4fcf87a8080f696a6b688010230289fcbfebe727e238f74f8a3bbdac624e0977f6aad51c4952b82440dbf55dc8080f696a6b68801026f7dda7f171d46101120a9a22c4bff2b20c848002c48b16b8b569041ad4fee538080f696a6b6880102b42525258d413f02bc79100c62fd4c375b48b99b0677f66057369e8a5b7513258080f696a6b68801029353bc4fd2d2aa72dc3dd2666a252b691106bd7dcf5e187ab67c5846845a91a28080f696a6b688010283aef0993c354f419c936899e95c913f9c5a744f07aa8b93f5759a1052dff6da8080f696a6b6880102dc341a044c7ee1f5f646e20968b1e7199218496bd162b7fbfe59e74732671eeb8080f696a6b6880102981694a60707e4ddae0ee0fffd4f9145e5cc0fae5a0df743a5088963de3d82988080f696a6b6880102ae32ee96b8cb8462b1098603bb71e376104f0cc1631a082fda6c4bee7c8ba4608080f696a6b6880102346b2531ae10beff8342c22d490475525d8727c4776af91f5f260f7ee24dbf858080f696a6b6880102d22b5bd864a6a00e3b9a7f284089692494e3c23aebc477fce1d8a639fbb883658080f696a6b68801024243ec2edf779fbf84291fcb4b9f5e70cfdcd9ea03e83e57518816de817815028080f696a6b688010287f8ef7feb7db2b981dc53ff018c6212af8a33a1079cbc92c43259124426e7298080f696a6b688010224199847a4441df02b78714cb46c269ca386684634fcc798844fde3ad3c4681f8080f696a6b688010284b7f49772dc51e0a92a2cce8185f86076a4c8803d67b2c67d5e9821f8e4fb4a8080f696a6b6880102072e03a46918b4b6d41d69d31864b9c881c3d3a37f4b877b4df8e1a424b680458080f696a6b68801021aefb02c383977deedf60953010f706dcf2b7e229175358a5995d82d91566dce8080f696a6b6880102f22b6142d28c0a60892aa3f60c466def670430515084b9057ecbcdb1de0e8dd48080f696a6b688010252d76b30d3940d16ce6c6f2f4ef31658a41f4d37798209a2248b16ca3ca0d7a38080f696a6b6880102a747215f00782df69cb892eff6e9c8a26776e475587b47285826d6d97e1a000f8080f696a6b6880102e503e513300d2d262f5f3e47b370eafe0a3f147b1f57a3f68e73b15c58574b508080f696a6b68801026a6f2096d36752b5ba24d2b432de73cf3762f717848968ee20ab9f53b46535038080f696a6b68801023b811f754f976cc70e30d2ed217cb8568e71feafb93369325a2b3faab29f43838080f696a6b6880102e991a81c19b1c264b488ae8d54aa5c66d0a4c1aa1bc4893a470183354e2aa3ba8080f696a6b68801028c5e26fc4f629cbee15727421d298c731632d461e4715fe7f514a3292bc5cc8e8080f696a6b6880102dff54660bd064f5633fa9bf1c149faacfe69991bf13be8c42748ee3978634dea8080f696a6b6880102efe93d5e0662a93e381da1cbad8a0f8f20454f4e6d59ec15228a29d5c21690b28080f696a6b688010229dccf9dbfbf835347136a452cca9e54b84873ee446f10fe310d1709e92997378080f696a6b6880102e2a1894a82d38a012efec5fd095a45e84257a98af1c9e3b058130560f7e599e98080f696a6b6880102936b44fc0f3117e1e236d55bab73a58940a73b7911ef061e99ec087869f495f88080f696a6b6880102af4a02ae2ce92b145f5b8fa3180dbfaca03cf0223cf87d554b9dfc3ac9cad6b08080f696a6b688010244e5c4a4b1923440c0cc2986ebc15bca9ed86b0db07d4882bfeb4eca78a2256b8080f696a6b688010260bca41554d44381f21b668ee461cb78b68544d34a8f211e530b62b6981578528080f696a6b68801024f2021e3045ec316fa0075876f5a66bb01360ae693aa3ee043c1838c5cf367998080f696a6b68801028382d6d6a055377f400b1321df77736f52d06e90b2f13f3d035b95eaa4571f038080f696a6b68801023d232744cc0f536c01dedfaa185d22043d430b63974185dc5da65dcc895e1b8f8080f696a6b6880102566aca8ddabb3f712b378703181bb7bca53b9627467816efc72d6705419ba0bb8080f696a6b6880102cabf0f652f125d5601edf002eb158cb93a92c977ce1594b5b734eb71c7c29a498080f696a6b68801023c1695978c1020ce7b178538647fe947e14a82476d069462d11f5e077debd8ba8080f696a6b6880102b2b425d44be7237e85997f57140805ab86b464849aba2801068f33c110f5a5768080f696a6b6880102d61bef4bb577a76b43e421684ba0ff87a3fa7f1703d5ab700518bcd32a2bd76e8080f696a6b6880102f7e5f0942b92700f77a4aa1fd3867fc311dfb20591127c0229ce14e545730c4221019c96897224f7213cab1520a866b66b2fcefb429092c5375ab48797af68c9db3800"sv;
    inline constexpr uint32_t GENESIS_NONCE = 12345;

    inline constexpr uint64_t GOVERNANCE_REWARD_INTERVAL_IN_BLOCKS = 1000;
    inline constexpr std::array GOVERNANCE_WALLET_ADDRESS =
    {
      "T6TAiML6XENN4Vjsc2tm7vRKVMhKv3MLiYSeQjZ2r6AEgPLqpjGG1bgQrV8Dy6nhey7SnKKxoXofn9FmzmxkvrcV2xLpT4nrr"sv,
      "T6TAiML6XENN4Vjsc2tm7vRKVMhKv3MLiYSeQjZ2r6AEgPLqpjGG1bgQrV8Dy6nhey7SnKKxoXofn9FmzmxkvrcV2xLpT4nrr"sv,
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
    inline constexpr std::string_view GENESIS_TX = "03651e00e0a801c0d102a0fa0380a305e0cb06c0f407a09d0980c60ae0ee0bc0970da0c00e80e90fe09111c0ba12a0e313808c15e0b416c0dd17a0861980af1ae0d71bc0801da0a91e80d21fe0fa20c0a322a0cc2380f524e09d26c0c627a0ef2880982ae0c02bc0e92ca0922e80bb2fe0e330c08c32a0b53380de34e08636c0af37a0d83880813ae0a93bc0d23ca0fb3d80a43fe0cc4000e0a801c0d102a0fa0380a305e0cb06c0f407a09d0980c60ae0ee0bc0970da0c00e80e90fe09111c0ba12a0e313808c15e0b416c0dd17a0861980af1ae0d71bc0801da0a91e80d21fe0fa20c0a322a0cc2380f524e09d26c0c627a0ef2880982ae0c02bc0e92ca0922e80bb2fe0e330c08c32a0b53380de34e08636c0af37a0d83880813ae0a93bc0d23ca0fb3d80a43fe0cc40001e01ff006580c0dc8df9ecc5b801026f377a3326effd2ed060efbeca18bcd1ec10663ec56fde42f42f669ca1754a5e80e09bf2ec8dda0202663ab49e64447297547cff7aa24869e7066d0312acd8db20fd32d1aa02f76b9880e09bf2ec8dda020290654e3eed817f629e8d052217b211783b167215b5b5ce6e4b7762feb54e8b1e80e09bf2ec8dda020233d25b7f69fdc12d3d2bb610f090cebcdde97bb1ec0c2284790841a514b2cc0a80e09bf2ec8dda0202ffc71dc1b112fdf8ad75fbde02c385d6d4e0a68141b5cc97452d63903303942680e09bf2ec8dda020298f0d1ffe6ff14d567059563bc7622693757509ee4b14e34ceb91f68dd4157ce80e09bf2ec8dda0202ba08de26143eac44124f6e08c44644bc76c2d0dc36d1b8e89a404a2f2024197b80e09bf2ec8dda02029ee8f50dabf598d2f0754a4e266d8095d4669eac3281193caaf8f745585cea5480e09bf2ec8dda02025ade762c3d131c297bc4f49991f91b345e34dc44a49b2002c4f9da2f6eb4cd3b80e09bf2ec8dda02022ac91eed18e409fdd628fdec5622bcdeed7dc3b2cb9c1879fe9e365f4cc2e2a180e09bf2ec8dda02025404624c073b120f152ca3cc0a36f577fc2bffc3fc14f25cac0e1feeb144b3ab80e09bf2ec8dda0202841285de9821054cbfe8617eee23ab74bd15cf53a7e1038382be90738cdfc7d380e09bf2ec8dda0202def0bf1f20845ec22f4dc670b7ef00d8d0460d527ae882f35bb0efcacb3e938380e09bf2ec8dda02025484f52e517dfa9a18d66ebb93a411474aa2c5ee85d60c8faa13abd357e449fa80e09bf2ec8dda020272f0c2a79e8cae1c7fc4c43c620f12974533bb3d8ff8d54c35e9df255c57ea9980e09bf2ec8dda02021be45b8aa45b896dbf8560a0ed0231b38a2cbbe52f7f628c24d390c891fc0d6680e09bf2ec8dda02021dc4083a5f090d0f929adc59ac14dee533254546ef8e5344118a21181d6685f380e09bf2ec8dda0202948f6d3235a1d6f75bb1794d9fe90b7ac69f3616860bd8f7f5ed07e12dce02f580e09bf2ec8dda0202c08ce81bf5b758c2d5def6d586aa845ed350a236ec6bfa97fcff5bfe974dafd380e09bf2ec8dda0202d842ba8123cbecaa6dcc95d8cbeb71123e61a02ae5f839ab9a520887c2fb3f5a80e09bf2ec8dda020204a17b2c66c353de937acd23de9a27a3160767c1bdb455dd80b530300cdd2f5d80e09bf2ec8dda02021043483606709fa06211a125e8fe027ffd0d9a2a6846db3ddab5d8fd3224fff580e09bf2ec8dda02025da12a77918975c8287fe9da4a37ce3417987bf824ebef5b64849ee5783ca17380e09bf2ec8dda0202706a59e7c73120d957e269a5fc197344231a13d4e1d63b5376c37f863eabe24c80e09bf2ec8dda02027037ee7d54e6ce46bd38dc6bc73e0f59c4ec766b5b1a697fe440a8e3871d42c180e09bf2ec8dda02023fef34a0b061a2013ff972980db93e93852d9cbe0d0cc3607b6fecc5468d6ab080e09bf2ec8dda02028670266d517ae12defd97b1c3584400fad531e5672816c65b1706d4462189bbe80e09bf2ec8dda0202936cf8e23059b6b371f72a896f47073df4b3bc3d6a5ec0a5548f3e02c12577b780e09bf2ec8dda0202acbaa9e77f4e728ebc6529236b29291c886b8d532791a638fe8e97ba34b9368780e09bf2ec8dda0202835dcc3cf908e4090947f49b06ab9fa42d38b632730d09c9567724f95e421b3280e09bf2ec8dda0202b3d5213350be2022496dc489e25e95af5e03f973a676986ca404fe30af97458a80e09bf2ec8dda0202925058c451b911a3262c0009d94c1ee5c36ef7b8cc76cf6f814736a17de5051180e09bf2ec8dda0202383e45ad6df69aa5a39b3b5bd2acb22c5487e331d352fde402d197ee1234119580e09bf2ec8dda02027e7a6272aca23a87da732403871dc87f3e9521ece2cbcd3a888e272560b3660b80e09bf2ec8dda02020b547e5546c01a395c5428c84bd07d306d19ae9f84114bc62dcff827bced3e2c80e09bf2ec8dda0202e350113ed091ee579842d36c7eaf93692eba0e9dafa6c12b0616d9ba15accdef80e09bf2ec8dda0202775dd98ff6424819e808f1c51f9045391c437bf80d35bc40b692a7c0531159f680e09bf2ec8dda020236d6e36e896213715a6b1808a66a59dfce6666c4e3422bb9a73de1e8bd416bac80e09bf2ec8dda0202393d81727bebac3ba6cf346cf3f2436c5922d29c6e4eafdfabe8d9a55375cf9180e09bf2ec8dda0202e3239870bbb0b8fe1d4304fb03041a2829329625cbae7597a0826fce8e8e1a3b80e09bf2ec8dda0202d7277f24f806f39c632583dd9d4f5d14603b13701f7c905a902d46b0530e02a680e09bf2ec8dda020239158853158d1b717c7e2dcee423a42e5e0f3f24023de6ef64626a2d33fbaf6a80e09bf2ec8dda020224f292d1cce018740e6dbcb2265c0dc469a753c70a061e85c33f56e96d8d2f4e80e09bf2ec8dda0202ee098fca01f24ebf8e749208724def27711d88a855235883c17f99d621d4097f80e09bf2ec8dda020228eba669765200b883edd93c067a7e420341c427170f433e85e4deef294402ce80e09bf2ec8dda0202bb4f2c03ae958b2c2421617115c911ac0dd9fece2838152a290b1793d0cd8d9480e09bf2ec8dda0202220f47f47895284db8ee595db49bb2b1c9b6c4c67f7d8f39b6066e76a0e1a56c80e09bf2ec8dda0202e3998a3a090e2c2992cc4b8d2dafe59088b44c757da9e46e08531490eebbcb5f80e09bf2ec8dda0202ecf36c718e1752da79d1c1c95a04a4c882b3b57f28069ecb0df039000e2c82c280e09bf2ec8dda02028cac9b29a0a89cadc65e4eb70b8ec747c8c914fe8d0c1a214eb504d00f6ae0e080e09bf2ec8dda02020d228cf8739919b20b10d4e737068667f683feba5ccad8d14b5e37872b4188c88080f696a6b6880102fa60e2f82db705f1106dabca7a13ff0e015ddeebca0ee47adb885928cd8a23e78080f696a6b6880102e236bd682c1f51cb26a5ac2042bc99117af0e74e7f1fd495535185e6204c6d2a8080f696a6b688010211909d49b7d119c312eade97145dbccc8b7468c8e8145053c7b581671fd468408080f696a6b6880102a21f2dba0e9ef552576237dcf103e25a5731f0a2b21fab969de3ed66d6fded5d8080f696a6b6880102f0d90d03cf24a0259502aa75f0e9fb0db225867681743f100f0a26d9ecdfbc4d8080f696a6b68801024ec9614fd498601849b3d9049471c6607ba6b8b294a6bb0e1e93048cdd375c788080f696a6b6880102ce4d6d7bc499d540166ae45a859942caaabdb5d18e03730ac159d2a4748f17d88080f696a6b68801023fe82965ada6e65d55c62d664daaa6e2f1376425bb51194ebb55290bb72ab91b8080f696a6b6880102ccd27de5dd0418d62ecab344e0a249eeeedd5447f56a973f7ae115c26c908ab88080f696a6b68801028a22f46d72465abe56d24366184865f15c52c43be1e3588451047546b779c7598080f696a6b68801027c2f6dbcfb7c743ec3f49a4cb2572424f8de64786624460abfd0007205fadf598080f696a6b6880102f17cc7e8f57c4440e970bd71dd44dd044f6ee2fbc8e2725f9c2745cac94014e08080f696a6b6880102d0c3c74bc07b5350dbf18c0aaa3464a1e396570785879e43af044c7b64a10fea8080f696a6b6880102841e8bada6300774acd0425f92cca0c4f9d59d46b05f49d56311a7ea506ac14f8080f696a6b68801020589db606182ddf38e8ff0f38e1a83b757accb2377f3a07ccf53c3ac9cb2e6d48080f696a6b68801027f1d627425fde1869b25cb4894dff65bfa66534a794508cacc117bad7ebbf0978080f696a6b688010235be06c24c4b701c86b6855cef86b2d5c14f6d857aaf52e1eb18c8c38484afe78080f696a6b68801029a96e61eb4b135c626eca5de32b9cf5e68433260e58c49f2b83a7e709fc2aa5a8080f696a6b6880102516f113b93ec22fbc3a523ed51e45b0aff228d51ddbb0f0274ba32e8c28aed108080f696a6b6880102a53d7da6a846cf5aa27e931d67fd76ea03bbbd5b4e7a713a7363691bafa8cd708080f696a6b6880102555fa4e5e690609b411dfac89ce81a3e6a6de979cb87a8ade667305baaa996dc8080f696a6b68801026b9276223c7c30a6d7df5d992d20d347d8763bbb2ad1ac12eb75b0d9248bf0fa8080f696a6b6880102b87da7c1af4a986f71eff7f15eaf4ed2e1302fb63460b4767f361df3579bb7c38080f696a6b6880102ec93684f98657e294c02ba7fe713bca838cb2b907f6610f11fa74ce91b07176d8080f696a6b68801023e3d2066e25ff3050947de50194789fcb53615d273935c43ccbf477dff0d34bb8080f696a6b68801026c8491947bc68110237637d62d7622c2e76657d71323625675e9a251162a5e4b8080f696a6b6880102f70f2ad4a8870e23d8b85a03a86db59b152325342779d88554c071b9f99bc38b8080f696a6b68801029839fcdafa684e36bee05a10215de01475b4181054a84b7369de455238eb74208080f696a6b68801022793d35f6add87e3097dacd5394384b7c6e2e0b8fba456b8e42d77b9118bfa2b8080f696a6b6880102597c98592e1106b103cc757d356a278ff8188efe1d31b9f0c64f16d5a415c6428080f696a6b6880102e1f2e582141209fdc257d35bdd59f2306ecb08027606ce648bc95967da870c518080f696a6b6880102890c8c36f6548dcc6ce9b4d7b401e31058847f66ad4f1e18ca8a3c6a9a37cd388080f696a6b6880102c85fa310083ab9070e0bd9faeda6cb8bc1579ece475867b0b17c7ba090379e1b8080f696a6b6880102b3a5ba7a14ad05a17807ac861f641d1e1030761478ef086593dcfb033c4969098080f696a6b68801027008516ec8abd95a7fe9ea14da39f132a5f7297ae76ea4e4b653db1aa42148918080f696a6b6880102b0470c91fa138ac5512bed396665165d36f46dc82c9ab5f4039ee463975c49598080f696a6b6880102da24ef841d31676429556d9f842f50af2bb6ba5fa3f016a88228bc57155fec878080f696a6b6880102643c45fb5d39f8542f9bc3ca1781ab5a047fd614abe1d50d5901a2213f65d6568080f696a6b68801029720ded463daa8168523344c7e1cf4db07ab45365a0e5e1be4780719766c2bee8080f696a6b6880102ffa1beff30b5bf021d7887842291f0d69f79089862ba36ec7c8bc24d86a7b7cc8080f696a6b6880102d553881daabe8e43e415d6dc3684159d7852450b762867fbe5428f83b1a8242c8080f696a6b6880102b491e7ad70f451c77a5301ad1cd55f84142803861b69e3bf27bb137564a1084b8080f696a6b68801027537a8cf5853dffaeb42c145e618399d38e09ba412958ffc5f5398877a6a39418080f696a6b68801029e433c7fa3e6d98598cf7ab769219447fb9692c72173349b1c9d281942c00a378080f696a6b6880102b4812c180d7e85c7a72db4b1d2000f84e844a4163dec9d02995a9120025ecf5d8080f696a6b68801024e673257701b571dc0685895cd941528a867f624ffe5fdc1f46fe4a89ddbd33c8080f696a6b6880102f238f85f25734b8a56ae440eedf88250d517030e7b26018f41918080a797ce378080f696a6b68801025695c0445902ad6f92944dbcab32fcfc20285be301ab485e0a98ec0b83a732c38080f696a6b6880102959352b151ec7f5a204ef26cf20f2a80587d84e0b3664cccf95ad2a30ab3e9fe8080f696a6b6880102cf8e51392b4080e5606b2fa7ebf3a878611a41437629bb3723c0f3a1a30c5ddf2101f70e7538945546a4039da9fd8a0c76ec3c0b40ad99aad415e757b4c6509fd7d400"sv;
    inline constexpr uint32_t GENESIS_NONCE = 12345;

    inline constexpr uint64_t GOVERNANCE_REWARD_INTERVAL_IN_BLOCKS = 7 * BLOCKS_PER_DAY;
    inline constexpr std::array GOVERNANCE_WALLET_ADDRESS =
    {
      "dV2cWe1doGSN4Vjsc2tm7vRKVMhKv3MLiYSeQjZ2r6AEgPLqpjGG1bgQrV8Dy6nhey7SnKKxoXofn9FmzmxkvrcV2xLqbMnPf"sv, // hardfork v7-9
      "dV2cWe1doGSN4Vjsc2tm7vRKVMhKv3MLiYSeQjZ2r6AEgPLqpjGG1bgQrV8Dy6nhey7SnKKxoXofn9FmzmxkvrcV2xLqbMnPf"sv,// hardfork v10
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
