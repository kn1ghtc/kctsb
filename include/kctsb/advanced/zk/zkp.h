/**
 * @file zkp.h
 * @brief Zero-Knowledge Proof System Interface
 * 
 * Provides complete zk-SNARK functionality based on Groth16 protocol:
 * - Circuit definition and constraint system
 * - Trusted setup (CRS generation)
 * - Proof generation
 * - Proof verification
 * 
 * Security Level: 128-bit (BN254 curve)
 * 
 * Mathematical Foundation:
 * - Bilinear pairings on BN254 elliptic curve
 * - Quadratic Arithmetic Programs (QAP)
 * - Knowledge of Exponent (KEA) assumption
 * 
 * Usage Example:
 * @code
 *   // Define circuit: x^3 + x + 5 == y
 *   Circuit circuit;
 *   circuit.add_multiplication_gate(...);
 *   circuit.add_addition_gate(...);
 *   
 *   // Setup
 *   auto crs = Groth16::setup(circuit);
 *   
 *   // Prove
 *   Witness witness = {...};
 *   auto proof = Groth16::prove(crs.proving_key, circuit, witness);
 *   
 *   // Verify
 *   bool valid = Groth16::verify(crs.verification_key, proof, public_inputs);
 * @endcode
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 */

#ifndef KCTSB_CRYPTO_ZKP_H
#define KCTSB_CRYPTO_ZKP_H

#include <vector>
#include <cstdint>
#include <string>
#include <memory>
#include <map>
#include <NTL/ZZ.h>
#include <NTL/ZZ_p.h>
#include <NTL/vec_ZZ_p.h>

using NTL::ZZ;
using NTL::ZZ_p;
using NTL::vec_ZZ_p;

namespace kctsb {
namespace zkp {

// ============================================================================
// Forward Declarations
// ============================================================================

class Circuit;
class ConstraintSystem;
class QAP;
struct Groth16Proof;
struct ProvingKey;
struct VerificationKey;
struct CommonReferenceString;

// ============================================================================
// Field and Curve Parameters (BN254)
// ============================================================================

/**
 * @brief BN254 curve parameters
 * 
 * BN254 (alt_bn128) parameters:
 * - Prime field: p = 21888242871839275222246405745257275088696311157297823662689037894645226208583
 * - Scalar field: r = 21888242871839275222246405745257275088548364400416034343698204186575808495617
 * - Embedding degree: k = 12
 */
struct BN254Params {
    static ZZ get_field_prime();
    static ZZ get_scalar_order();
    static size_t get_security_bits() { return 128; }
};

// ============================================================================
// Elliptic Curve Points
// ============================================================================

/**
 * @brief Point on G1 (base field curve)
 */
struct G1Point {
    ZZ_p x;
    ZZ_p y;
    bool infinity = false;
    
    static G1Point generator();
    static G1Point identity();
    
    G1Point operator+(const G1Point& other) const;
    G1Point operator*(const ZZ& scalar) const;
    bool operator==(const G1Point& other) const;
    
    std::vector<uint8_t> serialize() const;
    static G1Point deserialize(const uint8_t* data, size_t len);
};

/**
 * @brief Point on G2 (extension field curve)
 */
struct G2Point {
    // G2 uses Fp2 extension field (represented as pairs)
    ZZ_p x_real, x_imag;
    ZZ_p y_real, y_imag;
    bool infinity = false;
    
    static G2Point generator();
    static G2Point identity();
    
    G2Point operator+(const G2Point& other) const;
    G2Point operator*(const ZZ& scalar) const;
    bool operator==(const G2Point& other) const;
    
    std::vector<uint8_t> serialize() const;
    static G2Point deserialize(const uint8_t* data, size_t len);
};

/**
 * @brief Target group element (GT = Fp12)
 */
struct GTElement {
    // Simplified representation of Fp12 element
    std::vector<ZZ_p> coeffs;  // 12 coefficients
    
    static GTElement identity();
    GTElement operator*(const GTElement& other) const;
    bool operator==(const GTElement& other) const;
};

/**
 * @brief Bilinear pairing computation
 * @param a Point on G1
 * @param b Point on G2
 * @return Pairing result in GT
 */
GTElement pairing(const G1Point& a, const G2Point& b);

/**
 * @brief Multi-pairing computation (more efficient for multiple pairings)
 */
GTElement multi_pairing(const std::vector<G1Point>& g1_points,
                        const std::vector<G2Point>& g2_points);

// ============================================================================
// Constraint System
// ============================================================================

/**
 * @brief Wire (variable) in the circuit
 */
struct Wire {
    size_t index;           ///< Wire index
    std::string name;       ///< Optional name for debugging
    bool is_public;         ///< Is this a public input?
    
    Wire() : index(0), is_public(false) {}
    Wire(size_t idx, bool pub = false) : index(idx), is_public(pub) {}
};

/**
 * @brief Linear combination of wires
 */
struct LinearCombination {
    std::map<size_t, ZZ> terms;  // wire_index -> coefficient
    
    void add_term(size_t wire_idx, const ZZ& coeff);
    void add_term(const Wire& wire, const ZZ& coeff);
    
    LinearCombination operator+(const LinearCombination& other) const;
    LinearCombination operator*(const ZZ& scalar) const;
};

/**
 * @brief R1CS constraint: A * B = C
 */
struct R1CSConstraint {
    LinearCombination a;
    LinearCombination b;
    LinearCombination c;
};

/**
 * @brief Rank-1 Constraint System
 */
class ConstraintSystem {
public:
    ConstraintSystem() = default;
    
    /**
     * @brief Allocate a new wire
     * @param is_public Is this wire a public input?
     * @return Allocated wire
     */
    Wire allocate_wire(bool is_public = false);
    
    /**
     * @brief Add a constraint A * B = C
     */
    void add_constraint(const LinearCombination& a,
                        const LinearCombination& b,
                        const LinearCombination& c);
    
    /**
     * @brief Get number of constraints
     */
    size_t num_constraints() const { return constraints_.size(); }
    
    /**
     * @brief Get number of wires
     */
    size_t num_wires() const { return num_wires_; }
    
    /**
     * @brief Get number of public inputs
     */
    size_t num_public_inputs() const { return num_public_; }
    
    /**
     * @brief Get all constraints
     */
    const std::vector<R1CSConstraint>& get_constraints() const { return constraints_; }
    
    /**
     * @brief Check if witness satisfies all constraints
     */
    bool is_satisfied(const std::vector<ZZ>& witness) const;

private:
    std::vector<R1CSConstraint> constraints_;
    size_t num_wires_ = 1;  // Wire 0 is always 1
    size_t num_public_ = 0;
};

// ============================================================================
// Circuit Builder
// ============================================================================

/**
 * @brief High-level circuit construction interface
 */
class Circuit {
public:
    Circuit();
    ~Circuit();
    
    // Move operations (disable copy)
    Circuit(Circuit&& other) noexcept;
    Circuit& operator=(Circuit&& other) noexcept;
    Circuit(const Circuit&) = delete;
    Circuit& operator=(const Circuit&) = delete;
    
    // ========================================================================
    // Wire Management
    // ========================================================================
    
    /**
     * @brief Allocate a public input wire
     */
    Wire public_input(const std::string& name = "");
    
    /**
     * @brief Allocate a private (witness) wire
     */
    Wire private_input(const std::string& name = "");
    
    /**
     * @brief Get the constant wire (always = 1)
     */
    Wire one() const;
    
    // ========================================================================
    // Basic Operations
    // ========================================================================
    
    /**
     * @brief Addition: result = a + b
     */
    Wire add(const Wire& a, const Wire& b);
    
    /**
     * @brief Subtraction: result = a - b
     */
    Wire sub(const Wire& a, const Wire& b);
    
    /**
     * @brief Multiplication: result = a * b
     */
    Wire mul(const Wire& a, const Wire& b);
    
    /**
     * @brief Division: result = a / b (requires b != 0)
     */
    Wire div(const Wire& a, const Wire& b);
    
    /**
     * @brief Constant multiplication: result = a * const
     */
    Wire mul_const(const Wire& a, const ZZ& constant);
    
    /**
     * @brief Add constant: result = a + const
     */
    Wire add_const(const Wire& a, const ZZ& constant);
    
    // ========================================================================
    // Comparison and Boolean
    // ========================================================================
    
    /**
     * @brief Assert equality: a == b
     */
    void assert_equal(const Wire& a, const Wire& b);
    
    /**
     * @brief Assert wire is boolean (0 or 1)
     */
    void assert_boolean(const Wire& a);
    
    /**
     * @brief Boolean AND: result = a AND b (requires boolean inputs)
     */
    Wire boolean_and(const Wire& a, const Wire& b);
    
    /**
     * @brief Boolean OR: result = a OR b (requires boolean inputs)
     */
    Wire boolean_or(const Wire& a, const Wire& b);
    
    /**
     * @brief Boolean NOT: result = NOT a (requires boolean input)
     */
    Wire boolean_not(const Wire& a);
    
    // ========================================================================
    // Advanced Operations
    // ========================================================================
    
    /**
     * @brief Power: result = base^exp (exp is small constant)
     */
    Wire pow(const Wire& base, size_t exp);
    
    /**
     * @brief Range check: assert 0 <= a < 2^bits
     */
    void range_check(const Wire& a, size_t bits);
    
    /**
     * @brief Pack bits into field element
     */
    Wire pack_bits(const std::vector<Wire>& bits);
    
    /**
     * @brief Unpack field element into bits
     */
    std::vector<Wire> unpack_bits(const Wire& a, size_t num_bits);
    
    // ========================================================================
    // Finalization
    // ========================================================================
    
    /**
     * @brief Get the underlying constraint system
     */
    const ConstraintSystem& get_constraint_system() const;
    
    /**
     * @brief Finalize circuit (no more gates can be added)
     */
    void finalize();
    
    /**
     * @brief Check if circuit is finalized
     */
    bool is_finalized() const { return finalized_; }

private:
    std::unique_ptr<ConstraintSystem> cs_;
    std::map<std::string, Wire> named_wires_;
    bool finalized_ = false;
};

// ============================================================================
// Quadratic Arithmetic Program (QAP)
// ============================================================================

/**
 * @brief QAP representation of constraint system
 */
class QAP {
public:
    /**
     * @brief Convert R1CS to QAP
     * @param cs Constraint system
     * @return QAP instance
     */
    static QAP from_r1cs(const ConstraintSystem& cs);
    
    /**
     * @brief Get target polynomial t(x)
     */
    const std::vector<ZZ>& get_target_polynomial() const { return t_; }
    
    /**
     * @brief Get number of constraints
     */
    size_t num_constraints() const { return num_constraints_; }
    
    /**
     * @brief Get polynomial degree
     */
    size_t degree() const { return degree_; }
    
    /**
     * @brief Evaluate polynomials at a point
     */
    void evaluate_at(const ZZ& point, 
                     std::vector<ZZ>& u_vals,
                     std::vector<ZZ>& v_vals,
                     std::vector<ZZ>& w_vals) const;

private:
    std::vector<std::vector<ZZ>> u_polys_;  // U polynomials
    std::vector<std::vector<ZZ>> v_polys_;  // V polynomials
    std::vector<std::vector<ZZ>> w_polys_;  // W polynomials
    std::vector<ZZ> t_;                      // Target polynomial
    size_t num_constraints_ = 0;
    size_t degree_ = 0;
};

// ============================================================================
// Groth16 Protocol
// ============================================================================

/**
 * @brief Groth16 proving key
 */
struct ProvingKey {
    // G1 elements
    G1Point alpha_g1;
    G1Point beta_g1;
    G1Point delta_g1;
    std::vector<G1Point> a_query;   // [A_i(τ)]₁
    std::vector<G1Point> b_g1_query; // [B_i(τ)]₁
    std::vector<G1Point> h_query;    // [τⁱ * t(τ) / δ]₁
    std::vector<G1Point> l_query;    // [(β*U_i(τ) + α*V_i(τ) + W_i(τ)) / δ]₁
    
    // G2 elements
    G2Point beta_g2;
    G2Point delta_g2;
    std::vector<G2Point> b_g2_query; // [B_i(τ)]₂
    
    std::vector<uint8_t> serialize() const;
    static ProvingKey deserialize(const uint8_t* data, size_t len);
};

/**
 * @brief Groth16 verification key
 */
struct VerificationKey {
    G1Point alpha_g1;
    G2Point beta_g2;
    G2Point gamma_g2;
    G2Point delta_g2;
    std::vector<G1Point> ic;  // [(β*U_i(τ) + α*V_i(τ) + W_i(τ)) / γ]₁ for public inputs
    
    std::vector<uint8_t> serialize() const;
    static VerificationKey deserialize(const uint8_t* data, size_t len);
};

/**
 * @brief Common Reference String (CRS)
 */
struct CommonReferenceString {
    ProvingKey proving_key;
    VerificationKey verification_key;
};

/**
 * @brief Groth16 proof structure
 */
struct Groth16Proof {
    G1Point a;  // [A]₁
    G2Point b;  // [B]₂
    G1Point c;  // [C]₁
    
    std::vector<uint8_t> serialize() const;
    static Groth16Proof deserialize(const uint8_t* data, size_t len);
    
    /**
     * @brief Get proof size in bytes
     */
    size_t size() const;
};

/**
 * @brief Groth16 zk-SNARK protocol
 */
class Groth16 {
public:
    /**
     * @brief Generate Common Reference String (trusted setup)
     * @param circuit Circuit to generate CRS for
     * @return CRS containing proving and verification keys
     * 
     * WARNING: The toxic waste (τ, α, β, γ, δ) must be securely discarded.
     * In production, use a multi-party computation ceremony.
     */
    static CommonReferenceString setup(const Circuit& circuit);
    
    /**
     * @brief Generate a proof
     * @param pk Proving key
     * @param circuit Circuit
     * @param witness Full witness (public + private inputs)
     * @return Groth16 proof
     */
    static Groth16Proof prove(const ProvingKey& pk,
                              const Circuit& circuit,
                              const std::vector<ZZ>& witness);
    
    /**
     * @brief Verify a proof
     * @param vk Verification key
     * @param proof Proof to verify
     * @param public_inputs Public inputs
     * @return true if proof is valid
     */
    static bool verify(const VerificationKey& vk,
                       const Groth16Proof& proof,
                       const std::vector<ZZ>& public_inputs);
    
    /**
     * @brief Batch verify multiple proofs
     * @param vk Verification key
     * @param proofs Vector of proofs
     * @param public_inputs_vec Vector of public inputs for each proof
     * @return true if all proofs are valid
     */
    static bool batch_verify(const VerificationKey& vk,
                             const std::vector<Groth16Proof>& proofs,
                             const std::vector<std::vector<ZZ>>& public_inputs_vec);
};

// ============================================================================
// Example Circuits
// ============================================================================

/**
 * @brief Build circuit for: x^3 + x + 5 == y
 * @param x_val Private input value
 * @param y_val Public output value
 */
Circuit build_cubic_circuit();

/**
 * @brief Build Merkle proof verification circuit
 * @param depth Tree depth
 */
Circuit build_merkle_circuit(size_t depth);

/**
 * @brief Build hash preimage circuit
 * @param hash_type "sha256" or "poseidon"
 */
Circuit build_hash_preimage_circuit(const std::string& hash_type);

} // namespace zkp
} // namespace kctsb

#endif // KCTSB_CRYPTO_ZKP_H
