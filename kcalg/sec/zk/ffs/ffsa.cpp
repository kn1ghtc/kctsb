#include "ffsa.h"
#include "opentsb/kc_sec.h"
#include <iostream>


/*check GMP number for primality*/
bool ffsa_check_prime(mpz_class p)
{
    int8_t reps = 25;

    int prob = mpz_probab_prime_p(p.get_mpz_t(), reps);

    if(prob == 2)
        return true;
    else if(prob == 0)
        return false;
    else if(prob == 1)
    {
        /*REMARK: Instead of increasing the reps(maybe even n number of times)
          one may run some deterministic prime verification algorithm like AKS
          to provide a level of certainty. But, since Miller-Rabin is likely or
          almost definitely destined to return "probably prime", one may also
          consider going with a deterministic version all along as the speedup
          may not be achieved through double checking.*/
        reps = 50;
        prob = mpz_probab_prime_p(p.get_mpz_t(), reps);
        if(prob == 2)
            return true;
        else if(prob == 0)
            return false;
        else if(prob == 1)
            return true;
    }
    return false;
}

/*generate random prime couple p,q and derive the modulus n=pq*/
mpz_class ffsa_get_modulus(void)
{
    mpz_class p, q;

    gmp_randclass r (gmp_randinit_mt);

    srand(time(NULL));
    unsigned long int seed = (unsigned long int) rand();
    r.seed(seed);

    p = r.get_z_bits(1024);
    q = r.get_z_bits(1024);

    while(p % 2 == 0 || p % 4 != 3)
        p = r.get_z_bits(1024);

    while(q % 2 == 0 || q % 4 != 3)
        q = r.get_z_bits(1024);

    while(ffsa_check_prime(p) == false || p % 4 != 3)
        p = p + 2;

    while(ffsa_check_prime(q) == false || p == q || q % 4 != 3)
        q = q + 2;

    return p * q;
}

/*get random bool vector of length k*/
bool_vec_t ffsa_get_bool_vector(int8_t k) {
    bool_vec_t a;
    a.reserve(k);

    srand(time(NULL));

    for(int8_t i = 0; i < k; i++)
        a.push_back((bool)rand() % 2);

    return a;
}

/*get random coprime vector of length k derived from n*/
mpz_vec_t ffsa_get_secrets(int8_t k, mpz_class n)
{
    mpz_vec_t s;
    s.reserve(k);

    gmp_randclass r (gmp_randinit_mt);

    srand(time(NULL));
    unsigned long int seed = (unsigned long int) rand();
    r.seed(seed);

    mpz_class intermediate;

    for(int8_t i = 0; i < k; i++)
    {
        begin:
        do
        {
            intermediate = r.get_z_range(n-1) + 1;
        } while(gcd(intermediate, n) != 1);

        for(int8_t j = 0; j < i; j++)
            if(s[i] == intermediate)
                goto begin;

        s.push_back(intermediate);
    }

    return s;
}

/*derive verifier vector from secret vector and modulus*/
mpz_vec_t ffsa_get_verifiers(mpz_vec_t s, mpz_class n)
{
    srand(time(NULL));

    mpz_vec_t v;
    v.reserve(s.size());

    mpz_class inter;

    int8_t sig;

    for(int8_t i = 0; i < s.size(); i++)
    {
        sig = (rand() % 2) ? -1 : 1;

        inter = s[i] * s[i];
        inter = inter % n;
        inter = sig * inter;
        v.push_back(inter);
    }

    return v;
}

/*compute verifier constant*/
mpz_class ffsa_compute_x(mpz_class r, int8_t sig, mpz_class n)
{
    mpz_class x = r * r;
    x = x % n;
    x = sig * x;
    return x;
}

/*compute share number*/
mpz_class ffsa_compute_y(mpz_vec_t s, const bool_vec_t a, mpz_class r, mpz_class n)
{
    if(s.size() != a.size())
        return 0;

    mpz_class y = r;

    for(int8_t i = 0; i < s.size(); i++)
        if(a[i])
            y = y * s[i];

    return y % n;
}

/*verify share number and verify-vector*/
bool ffsa_verify_values(mpz_class y, mpz_vec_t v, const bool_vec_t a, mpz_class n, mpz_class x)
{
    if(v.size() != a.size() || x == 0)
        return false;

    mpz_class verifier = y * y, check = x;
    verifier = verifier % n;

    for(int8_t i = 0; i < v.size(); i++)
        if(a[i])
            check = check * v[i];

    check = check % n;

    if(verifier == check || verifier == -1 * check)
        return true;
    else
        return false;
}

int test_ffsa_main()
{
    /*Example run*/
    
    /*--------
     * Setup -
     *--------
     */
    
    /*set number of streams and rounds*/
    int8_t k = 6, t = 5;
    
    /*derive private primes and modulus*/
    mpz_class n = ffsa_get_modulus();
    
    /*derive secrets vector*/
    mpz_vec_t s = ffsa_get_secrets(k, n);
    
    /*derive derive verifier vector*/
    mpz_vec_t v = ffsa_get_verifiers(s, n);
    
    /*initialize random generator*/
    srand(time(NULL));
    gmp_randclass rand_c (gmp_randinit_mt);
    
    /*-----------------------------
     * Prover and verifier dialog -
     *-----------------------------
     */
    
    mpz_class r, x, y;
    int8_t sig;
    
    /*round based iteration*/
    for(int8_t i = 1; i <= t; i++)
    {
        /*--------
         * Round -
         *--------
         */
        
        /*REMARK: Round iteration may be too fast for providing sufficient
         distinct rand seeds generated over the time parameter. Fast
         computers may require a wait command.*/
        
        /*seed GMP random generator*/
        unsigned long int seed = (unsigned long int) rand();
        rand_c.seed(seed);
        
        /*derive random round constant and sign*/
        r = rand_c.get_z_range(n-1) + 1;
        
        sig = (rand() % 2) ? -1 : 1;
        
        /*derive verifier constant*/
        x = ffsa_compute_x(r, sig, n);
        
        /*get random bool vector of length k*/
        const bool_vec_t a = ffsa_get_bool_vector(k);
        
        /*derive share number*/
        y = ffsa_compute_y(s, a, r, n);
        
        /*single round verification of derived values*/
        if(ffsa_verify_values(y, v, a, n, x))
            std::cout << "Round " << (int)i << ": Correct\n";
        else
        {
            std::cout << "####Uncorrect -- Aborted####\n";
            return 0;
        }
    }
    
    /*Complete verification after t successful rounds*/
    std::cout << "####Verified####\n";
    return 0;
}
