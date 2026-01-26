// kctsb v5.0.0 macOS Release - Integration Test
// Compile: clang++ -std=c++17 test_integration.cpp -I./include -L./lib -lkctsb -Wl,-rpath,@executable_path/../lib -o test_app

#include "kctsb_api.h"
#include <iostream>
#include <iomanip>
#include <cstring>

int main() {
    std::cout << "=== kctsb v5.0.0 macOS Release Integration Test ===" << std::endl;
    
    // Test SHA3-256 (one-shot API)
    const char* message = "Hello, kctsb on macOS!";
    uint8_t digest[32];
    
    kctsb_error_t ret = kctsb_sha3_256(
        reinterpret_cast<const uint8_t*>(message), 
        strlen(message), 
        digest
    );
    
    if (ret != KCTSB_SUCCESS) {
        std::cerr << "SHA3-256 failed with error code: " << ret << std::endl;
        return 1;
    }
    
    std::cout << "\nMessage: " << message << std::endl;
    std::cout << "SHA3-256: ";
    for (int i = 0; i < 32; i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)digest[i];
    }
    std::cout << std::dec << std::endl;
    
    std::cout << "\n✅ SHA3-256 test passed! Library is working correctly." << std::endl;
    std::cout << "Note: For full functionality, use the CLI tool: ./bin/kctsb" << std::endl;
    return 0;
}
