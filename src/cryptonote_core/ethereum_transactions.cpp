#include "ethereum_transactions.h"

#include "cryptonote_basic/cryptonote_format_utils.h"

using cryptonote::hf;

namespace ethereum {

template <typename... T>
static bool check_condition(
        bool condition, std::string* reason, std::string_view format, T&&... args) {
    if (condition && reason)
        *reason = fmt::format(format, std::forward<T>(args)...);
    return condition;
}

bool validate_ethereum_tx(
        hf hf_version,
        uint64_t blockchain_height,
        cryptonote::transaction const& tx,
        cryptonote::tx_extra_ethereum& eth_extra,
        std::string* reason) {

    // Extract Ethereum Extra from TX
    {
        if (check_condition(
                    tx.type != cryptonote::txtype::ethereum,
                    reason,
                    "{} uses wrong tx type, expected={}",
                    tx,
                    cryptonote::txtype::ethereum))
            return false;

        if (check_condition(
                    !cryptonote::get_field_from_tx_extra(tx.extra, eth_extra),
                    reason,
                    "{} didn't have ethereum data in the tx_extra",
                    tx))
            return false;
    }

    // Validate Ethereum Address
    {
        const size_t ETH_ADDRESS_SIZE = 20;  // 20 bytes, 40 hex characters
        if (check_condition(
                    eth_extra.eth_address.size() != ETH_ADDRESS_SIZE * 2,  // Multiplied by 2 because it's hex representation
                    reason,
                    "{} invalid ethereum address size",
                    tx))
            return false;

        // TODO sean potentially add more rigorous eth address checking here
    }

    // Validate Ethereum Signature
    {
        //TODO sean this verify signature stuff
        //bool signature_valid = verify_ethereum_signature(eth_extra.eth_address, eth_extra.signature, eth_extra.pub_key);
        bool signature_valid = true;
        if (check_condition(
                    !signature_valid,
                    reason,
                    "{} invalid signature over new ethereum address",
                    tx))
            return false;
    }


    return true;
}

}
