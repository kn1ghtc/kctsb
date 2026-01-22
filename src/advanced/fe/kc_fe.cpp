/**
 * @file kc_fe.cpp
 * @brief HElib-based functional encryption wrapper (legacy, benchmark only)
 *
 * This file provides a thin wrapper around HElib for benchmark comparison purposes.
 * For production use, prefer the native BGV implementation in bgv/ directory.
 *
 * @warning This implementation depends on HElib library and is NOT for production use.
 *          Use native BGV (bgv_context.cpp) for production homomorphic encryption.
 *
 * @version 4.6.0
 * @date 2025-07-20
 *
 * Design Notes:
 * - HElib wrapper exists solely for performance benchmarking against native BGV
 * - All HElib-specific optimizations (NTT, RNS) serve as reference implementations
 * - Native BGV should eventually match or exceed HElib performance
 */

#include <cstdint>
#include <cstddef>
#include <vector>
#include <stdexcept>

#ifdef KCTSB_HAS_HELIB
#include <helib/helib.h>
#endif

namespace kctsb {
namespace fe {

/**
 * @brief HElib BGV Context wrapper for benchmark comparison
 *
 * This class wraps HElib's Context for direct performance comparison
 * with the native BGV implementation.
 */
class HElibBGVContext {
public:
    /**
     * @brief Construct HElib BGV context with specified parameters
     * @param m Cyclotomic polynomial index (ring dimension = phi(m)/2)
     * @param p Plaintext modulus
     * @param r Hensel lifting exponent (plaintext modulus = p^r)
     * @param bits Security bits (determines coefficient modulus chain)
     */
    HElibBGVContext(
        [[maybe_unused]] long m,
        [[maybe_unused]] long p,
        [[maybe_unused]] long r,
        [[maybe_unused]] long bits
    ) {
#ifdef KCTSB_HAS_HELIB
        // Initialize HElib context for BGV scheme
        // This mirrors native BGV parameter setup for fair comparison
        helib::Context::Builder contextBuilder = helib::Context::Builder(m, p, r);
        contextBuilder.bits(bits);
        context_ = std::make_unique<helib::Context>(contextBuilder.build());

        // Generate keys
        secret_key_ = std::make_unique<helib::SecKey>(*context_);
        secret_key_->GenSecKey();
        helib::addSome1DMatrices(*secret_key_);

        public_key_ = std::make_unique<helib::PubKey>(*secret_key_);
#else
        throw std::runtime_error(
            "HElib support not compiled. "
            "Rebuild with -DKCTSB_ENABLE_HELIB=ON"
        );
#endif
    }

    /**
     * @brief Encrypt a vector of integers
     * @param plaintext Vector of plaintext integers
     * @return Encrypted ciphertext handle (opaque)
     */
    [[nodiscard]]
    std::vector<uint8_t> encrypt(
        [[maybe_unused]] const std::vector<int64_t>& plaintext
    ) const {
#ifdef KCTSB_HAS_HELIB
        helib::Ptxt<helib::BGV> ptxt(*context_);
        for (size_t i = 0; i < plaintext.size() && i < ptxt.size(); ++i) {
            ptxt[i] = plaintext[i];
        }

        helib::Ctxt ctxt(*public_key_);
        public_key_->Encrypt(ctxt, ptxt);

        // Serialize to bytes
        std::ostringstream oss;
        ctxt.writeTo(oss);
        std::string s = oss.str();
        return std::vector<uint8_t>(s.begin(), s.end());
#else
        throw std::runtime_error("HElib not available");
#endif
    }

    /**
     * @brief Decrypt a ciphertext
     * @param ciphertext Encrypted ciphertext bytes
     * @return Decrypted plaintext vector
     */
    [[nodiscard]]
    std::vector<int64_t> decrypt(
        [[maybe_unused]] const std::vector<uint8_t>& ciphertext
    ) const {
#ifdef KCTSB_HAS_HELIB
        std::string s(ciphertext.begin(), ciphertext.end());
        std::istringstream iss(s);
        helib::Ctxt ctxt = helib::Ctxt::readFrom(iss, *public_key_);

        helib::Ptxt<helib::BGV> ptxt(*context_);
        secret_key_->Decrypt(ptxt, ctxt);

        std::vector<int64_t> result(ptxt.size());
        for (size_t i = 0; i < ptxt.size(); ++i) {
            result[i] = static_cast<int64_t>(NTL::IsZero(ptxt[i]) ? 0 : NTL::IsOne(ptxt[i]) ? 1 : 0);
        }
        return result;
#else
        throw std::runtime_error("HElib not available");
#endif
    }

    /**
     * @brief Get slot count (number of parallel SIMD lanes)
     * @return Number of plaintext slots
     */
    [[nodiscard]]
    size_t slot_count() const {
#ifdef KCTSB_HAS_HELIB
        return static_cast<size_t>(context_->getEA().size());
#else
        return 0;
#endif
    }

private:
#ifdef KCTSB_HAS_HELIB
    std::unique_ptr<helib::Context> context_;
    std::unique_ptr<helib::SecKey> secret_key_;
    std::unique_ptr<helib::PubKey> public_key_;
#endif
};

} // namespace fe
} // namespace kctsb
