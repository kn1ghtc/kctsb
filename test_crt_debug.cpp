#include <iostream>
#include <vector>
#include <random>
#include <cstdint>

// Simple test to verify CRT reconstruction
int main() {
    uint64_t q0 = 65537;
    uint64_t q1 = 114689;
    __int128 Q = (__int128)q0 * q1;
    
    std::cout << "q0 = " << q0 << std::endl;
    std::cout << "q1 = " << q1 << std::endl;
    std::cout << "Q = q0*q1 = " << (uint64_t)Q << std::endl;
    std::cout << "Q/2 = " << (uint64_t)(Q/2) << std::endl;
    
    // Test CRT for value 1
    uint64_t x = 1;
    uint64_t x0 = x % q0;  // = 1
    uint64_t x1 = x % q1;  // = 1
    
    std::cout << \"x = 1, x0 = \" << x0 << \", x1 = \" << x1 << std::endl;
    
    // CRT reconstruction: x = x0 + q0 * k where k = (x1-x0)*q0^{-1} mod q1
    // For x=1: x0=1, x1=1, so diff=0, k=0, result=1 (correct!)
    
    // Test for noise-affected value: say value is 1 + noise where noise is modular
    // If c0+c1*s = 1 mod q0 and = 1 mod q1, then reconstruction gives 1
    
    std::cout << \"CRT for (1,1) should give 1\" << std::endl;
    
    return 0;
}
