#pragma once

#include <string>

namespace bls {
class PublicKey;
class Signature;
};  // namespace bls

namespace bls_utils {
std::string PublicKeyToHex(const bls::PublicKey& publicKey);
std::string SignatureToHex(const bls::Signature& sig);
}  // namespace bls_utils
