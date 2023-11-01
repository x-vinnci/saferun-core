#pragma once

#include <cstdint>
#include <string>

#include "cryptonote_config.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/tx_extra.h"

namespace ethereum {

bool validate_ethereum_tx(
        cryptonote::hf hf_version,
        uint64_t blockchain_height,
        cryptonote::transaction const& tx,
        cryptonote::tx_extra_ethereum& eth_extra,
        std::string* reason);
} // ethereum
