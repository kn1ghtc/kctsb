#include <iostream>
#include <vector>
#include <cmath> // pow()
#include <cstdint> // int32_t

#include "kctsb/core/security.h"

#define p(X) (std::cout << X << std::endl)
// Uncomment to have the user calculate value of y
//#define USER_INPUT

/**
 * Generate cryptographically secure random number in range [min, max)
 * @param min Minimum value (inclusive)
 * @param max Maximum value (exclusive)
 * @return Random number in range [min, max)
 */
int32_t GetRandomNumber(const int32_t min, const int32_t max){
    if (max <= min) return min;
    
    uint32_t range = static_cast<uint32_t>(max - min);
    uint32_t random_value;
    
    // Use CSPRNG for secure random number generation
    if (kctsb_random_bytes(&random_value, sizeof(random_value)) != 0) {
        // Fallback: should never happen in normal operation
        return min;
    }
    
    // Reduce modulo bias using rejection sampling for critical applications
    // For this demo/educational code, simple modulo is acceptable
    return min + static_cast<int32_t>(random_value % range);
}

/**
 * Generate random sign (+1 or -1) using CSPRNG
 * @return +1 or -1
 */
int32_t GetRandomSign(){
    uint8_t random_byte;
    if (kctsb_random_bytes(&random_byte, 1) == 0) {
        return (random_byte & 1) ? -1 : 1;
    }
    return 1;  // Fallback
}

class NumberGenerator{

    int32_t min = 1000;
    int32_t max = 10000;
    std::vector<int> primeNumbers;

    void GeneratePrimeNumbers(int32_t min_val, int32_t max_val)
    {
        primeNumbers.clear();

        for (int32_t i = min_val; i != max_val + 1; i++) {
            int32_t j;
            for (j = 2; j < i; j++) {
                if (i % j == 0) {
                    break;
                }
            }
            if (i == j) {
                primeNumbers.push_back(i);
            }
        }
    }
public:
    NumberGenerator(int32_t min_ = 1000, int32_t max_ = 10000){
        min = min_;
        max = max_; }

    int32_t GetLargePrimeNumber() {
        GeneratePrimeNumbers(min, max);

        int32_t index = GetRandomNumber(0, static_cast<int32_t>(primeNumbers.size()));
        return primeNumbers[static_cast<size_t>(index)]; }
};


int32_t getGCD(int32_t a, int32_t b) {
    int32_t c;

    while (a != 0) {
        c = a;
        a = b % a;
        b = c;
    }

    return b;
}

int32_t getCoprime(int32_t n)
{
    int32_t coprime;

    do {
        coprime = GetRandomNumber(1, n);
    }
    while (getGCD(n, coprime) != 1);

    return coprime;
}


int test_ffs1_main()
{
    // Note: Random number generation now uses CSPRNG via kctsb_random_bytes
    // No need for srand() initialization

    // Security parameter k determines iteration count (not used in single-round demo)
    // int32_t k = 5;

    auto numGen = NumberGenerator(18, 29);

    int32_t p = numGen.GetLargePrimeNumber();
    int32_t q = numGen.GetLargePrimeNumber();

    // n can be Blum integer for easier calculations,
    // but that is not required
    int32_t n = p * q;

    p("n = " << p << "*" << q << " = " << n << " (public)");

    int32_t s = getCoprime(n);
    p("s = " << s << " (A's secret)");

    int32_t v = (s * s) % n;
    p("v = " << v << " (public)");

    // Protocol
    p("--------------------");

    int32_t r = GetRandomNumber(1, n);
    p("r = " << r << " (A's private)");

    int32_t x = (r * r) % n;
    p("x = " << x);

    int32_t e = GetRandomNumber(0, 2);
    p("e = " << e);

    int32_t y = 0;

#ifdef USER_INPUT
    std::cout << "Calculate y = r * s^e: ";
    std::cin >> y;
#else
    y = static_cast<int32_t>(r * std::pow(s, e));
    y = y % n;
    p("y = " << y);
#endif

    int32_t y_sq_mod_n = (y * y) % n;
    p("y^2 mod n = " << y_sq_mod_n);

    int32_t test = (x * static_cast<int32_t>(std::pow(v, e))) % n;
    p("test = " << test);

    if (y_sq_mod_n == test) {
        p("Right!");
    } else {
        p("Wrong!");
    }


    return 0;
}
