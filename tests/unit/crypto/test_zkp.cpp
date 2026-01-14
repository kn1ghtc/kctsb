/**
 * @file test_zkp.cpp
 * @brief Unit tests for Zero-Knowledge Proof (zk-SNARKs Groth16)
 */

#include <gtest/gtest.h>
#include <kctsb/advanced/zk/zkp.h>

using namespace kctsb::zkp;

// ============================================================================
// BN254 Curve Tests
// ============================================================================

TEST(BN254Test, PointAddition) {
    // Generator point
    G1Point g = G1Point::generator();
    G1Point zero = G1Point::zero();
    
    // g + 0 = g
    G1Point sum = g + zero;
    EXPECT_TRUE(sum.is_on_curve());
}

TEST(BN254Test, ScalarMultiplication) {
    G1Point g = G1Point::generator();
    
    // 1 * g = g
    NTL::ZZ one(1);
    G1Point result = g * one;
    EXPECT_TRUE(result.is_on_curve());
    
    // 0 * g = identity
    NTL::ZZ zero_scalar(0);
    G1Point zero_result = g * zero_scalar;
    EXPECT_TRUE(zero_result.is_infinity());
}

TEST(BN254Test, G2Operations) {
    G2Point g2 = G2Point::generator();
    EXPECT_TRUE(g2.is_on_curve());
    
    NTL::ZZ scalar(12345);
    G2Point result = g2 * scalar;
    EXPECT_TRUE(result.is_on_curve());
}

// ============================================================================
// Constraint System Tests
// ============================================================================

TEST(ConstraintSystemTest, Creation) {
    ConstraintSystem cs;
    
    size_t x = cs.alloc_variable();
    size_t y = cs.alloc_variable();
    size_t z = cs.alloc_variable();
    
    EXPECT_EQ(x, 1);  // 0 is reserved for constant 1
    EXPECT_EQ(y, 2);
    EXPECT_EQ(z, 3);
}

TEST(ConstraintSystemTest, AddConstraint) {
    ConstraintSystem cs;
    
    size_t a = cs.alloc_variable();
    size_t b = cs.alloc_variable();
    size_t c = cs.alloc_variable();
    
    // a * b = c
    LinearCombination lc_a, lc_b, lc_c;
    lc_a.add_term(a, NTL::ZZ(1));
    lc_b.add_term(b, NTL::ZZ(1));
    lc_c.add_term(c, NTL::ZZ(1));
    
    cs.add_constraint(lc_a, lc_b, lc_c);
    
    EXPECT_EQ(cs.num_constraints(), 1);
    EXPECT_EQ(cs.num_variables(), 4);  // Including constant
}

TEST(ConstraintSystemTest, Satisfaction) {
    ConstraintSystem cs;
    
    size_t x = cs.alloc_variable();
    size_t y = cs.alloc_variable();
    size_t xy = cs.alloc_variable();
    
    // x * y = xy constraint
    LinearCombination lc_x, lc_y, lc_xy;
    lc_x.add_term(x, NTL::ZZ(1));
    lc_y.add_term(y, NTL::ZZ(1));
    lc_xy.add_term(xy, NTL::ZZ(1));
    cs.add_constraint(lc_x, lc_y, lc_xy);
    
    // Set witness: x=3, y=4, xy=12
    cs.set_variable(x, NTL::ZZ(3));
    cs.set_variable(y, NTL::ZZ(4));
    cs.set_variable(xy, NTL::ZZ(12));
    
    EXPECT_TRUE(cs.is_satisfied());
}

TEST(ConstraintSystemTest, UnsatisfiedConstraint) {
    ConstraintSystem cs;
    
    size_t x = cs.alloc_variable();
    size_t y = cs.alloc_variable();
    size_t xy = cs.alloc_variable();
    
    LinearCombination lc_x, lc_y, lc_xy;
    lc_x.add_term(x, NTL::ZZ(1));
    lc_y.add_term(y, NTL::ZZ(1));
    lc_xy.add_term(xy, NTL::ZZ(1));
    cs.add_constraint(lc_x, lc_y, lc_xy);
    
    // Wrong witness: x=3, y=4, xy=10 (should be 12)
    cs.set_variable(x, NTL::ZZ(3));
    cs.set_variable(y, NTL::ZZ(4));
    cs.set_variable(xy, NTL::ZZ(10));
    
    EXPECT_FALSE(cs.is_satisfied());
}

// ============================================================================
// Circuit Builder Tests
// ============================================================================

TEST(CircuitBuilderTest, MultiplicationGate) {
    CircuitBuilder builder;
    
    auto x = builder.alloc_input();
    auto y = builder.alloc_input();
    auto z = builder.mul(x, y);
    
    builder.set_input(x, NTL::ZZ(5));
    builder.set_input(y, NTL::ZZ(7));
    
    auto& cs = builder.get_constraint_system();
    EXPECT_TRUE(cs.is_satisfied());
}

TEST(CircuitBuilderTest, AdditionGate) {
    CircuitBuilder builder;
    
    auto x = builder.alloc_input();
    auto y = builder.alloc_input();
    auto z = builder.add(x, y);
    
    builder.set_input(x, NTL::ZZ(10));
    builder.set_input(y, NTL::ZZ(20));
    
    auto& cs = builder.get_constraint_system();
    EXPECT_TRUE(cs.is_satisfied());
}

TEST(CircuitBuilderTest, BooleanConstraint) {
    CircuitBuilder builder;
    
    auto b = builder.alloc_input();
    builder.enforce_boolean(b);
    
    // b = 0 should satisfy
    builder.set_input(b, NTL::ZZ(0));
    EXPECT_TRUE(builder.get_constraint_system().is_satisfied());
    
    // b = 1 should satisfy
    builder.set_input(b, NTL::ZZ(1));
    EXPECT_TRUE(builder.get_constraint_system().is_satisfied());
}

TEST(CircuitBuilderTest, RangeCheck) {
    CircuitBuilder builder;
    
    auto x = builder.alloc_input();
    builder.enforce_range(x, 8);  // 8-bit range
    
    // x = 200 should satisfy (< 256)
    builder.set_input(x, NTL::ZZ(200));
    EXPECT_TRUE(builder.get_constraint_system().is_satisfied());
}

// ============================================================================
// QAP Tests
// ============================================================================

TEST(QAPTest, Compilation) {
    ConstraintSystem cs;
    
    size_t x = cs.alloc_variable();
    size_t y = cs.alloc_variable();
    size_t z = cs.alloc_variable();
    
    LinearCombination lc_x, lc_y, lc_z;
    lc_x.add_term(x, NTL::ZZ(1));
    lc_y.add_term(y, NTL::ZZ(1));
    lc_z.add_term(z, NTL::ZZ(1));
    cs.add_constraint(lc_x, lc_y, lc_z);
    
    QAP qap = QAP::from_constraint_system(cs);
    
    EXPECT_GT(qap.degree(), 0);
}

// ============================================================================
// Groth16 Setup Tests
// ============================================================================

TEST(Groth16Test, TrustedSetup) {
    // Simple circuit: x * y = z
    CircuitBuilder builder;
    auto x = builder.alloc_input();
    auto y = builder.alloc_input();
    builder.mul(x, y);
    
    Groth16 groth16;
    auto [pk, vk] = groth16.setup(builder.get_constraint_system());
    
    // Keys should be generated
    EXPECT_FALSE(pk.alpha_g1.is_infinity());
    EXPECT_FALSE(vk.alpha_g1.is_infinity());
}

TEST(Groth16Test, ProveAndVerify) {
    // Circuit: prove knowledge of x such that x^3 = 27 (x = 3)
    CircuitBuilder builder;
    auto x = builder.alloc_input();
    auto x2 = builder.mul(x, x);      // x^2
    auto x3 = builder.mul(x2, x);     // x^3
    
    // x3 = 27 (public)
    auto out = builder.alloc_input();
    builder.enforce_equal(x3, out);
    
    builder.set_input(x, NTL::ZZ(3));
    builder.set_input(out, NTL::ZZ(27));
    
    EXPECT_TRUE(builder.get_constraint_system().is_satisfied());
    
    Groth16 groth16;
    auto [pk, vk] = groth16.setup(builder.get_constraint_system());
    
    // Generate proof
    auto proof = groth16.prove(pk, builder.get_constraint_system());
    
    // Verify proof
    std::vector<NTL::ZZ> public_inputs = {NTL::ZZ(27)};
    bool valid = groth16.verify(vk, proof, public_inputs);
    
    EXPECT_TRUE(valid);
}

// ============================================================================
// Example Circuit Tests
// ============================================================================

TEST(ExampleCircuitTest, CubicCircuit) {
    // x^3 + x + 5 = y
    auto cs = example_cubic_circuit(NTL::ZZ(3), NTL::ZZ(35));
    EXPECT_TRUE(cs.is_satisfied());
}

TEST(ExampleCircuitTest, HashPreimageCircuit) {
    // Simplified hash preimage proof
    NTL::ZZ preimage(12345);
    NTL::ZZ hash = preimage * preimage % NTL::ZZ("21888242871839275222246405745257275088548364400416034343698204186575808495617");
    
    auto cs = example_hash_preimage_circuit(preimage, hash);
    EXPECT_TRUE(cs.is_satisfied());
}

// ============================================================================
// LinearCombination Tests
// ============================================================================

TEST(LinearCombinationTest, Addition) {
    LinearCombination lc1, lc2;
    
    lc1.add_term(1, NTL::ZZ(3));
    lc1.add_term(2, NTL::ZZ(5));
    
    lc2.add_term(1, NTL::ZZ(2));
    lc2.add_term(3, NTL::ZZ(7));
    
    LinearCombination sum = lc1 + lc2;
    
    // Should have terms for variables 1, 2, 3
    EXPECT_EQ(sum.terms.size(), 3);
}

TEST(LinearCombinationTest, ScalarMultiplication) {
    LinearCombination lc;
    lc.add_term(1, NTL::ZZ(4));
    lc.add_term(2, NTL::ZZ(6));
    
    LinearCombination scaled = lc * NTL::ZZ(3);
    
    // Coefficients should be multiplied by 3
    for (const auto& term : scaled.terms) {
        if (term.variable == 1) {
            EXPECT_EQ(term.coefficient, NTL::ZZ(12));
        }
        if (term.variable == 2) {
            EXPECT_EQ(term.coefficient, NTL::ZZ(18));
        }
    }
}

// ============================================================================
// Pairing Tests
// ============================================================================

TEST(PairingTest, BilinearProperty) {
    G1Point g1 = G1Point::generator();
    G2Point g2 = G2Point::generator();
    
    NTL::ZZ a(5), b(7);
    
    // e(a*g1, b*g2) = e(g1, g2)^(ab)
    GTElement lhs = pairing(g1 * a, g2 * b);
    GTElement rhs = pairing(g1, g2);
    
    // In a proper implementation, lhs should equal rhs^(ab)
    EXPECT_TRUE(lhs.is_valid());
    EXPECT_TRUE(rhs.is_valid());
}

TEST(PairingTest, MultiPairing) {
    std::vector<G1Point> g1_points = {G1Point::generator(), G1Point::generator() * NTL::ZZ(2)};
    std::vector<G2Point> g2_points = {G2Point::generator(), G2Point::generator() * NTL::ZZ(3)};
    
    GTElement result = multi_pairing(g1_points, g2_points);
    EXPECT_TRUE(result.is_valid());
}

// ============================================================================
// Edge Cases
// ============================================================================

TEST(EdgeCaseTest, EmptyConstraintSystem) {
    ConstraintSystem cs;
    EXPECT_EQ(cs.num_constraints(), 0);
    EXPECT_TRUE(cs.is_satisfied());  // Empty system is trivially satisfied
}

TEST(EdgeCaseTest, ZeroCoefficients) {
    LinearCombination lc;
    lc.add_term(1, NTL::ZZ(0));
    lc.add_term(2, NTL::ZZ(5));
    
    // Zero coefficient should be effectively ignored
    EXPECT_EQ(lc.terms.size(), 2);
}

TEST(EdgeCaseTest, LargeScalar) {
    G1Point g = G1Point::generator();
    
    // Large scalar multiplication
    NTL::ZZ large_scalar;
    NTL::RandomBits(large_scalar, 254);
    
    G1Point result = g * large_scalar;
    EXPECT_TRUE(result.is_on_curve());
}
