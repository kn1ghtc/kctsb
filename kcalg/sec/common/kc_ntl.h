//
//  kc_ntl.h
//  kcalg
//
//  Created by knightc on 2019/7/18.
//  Copyright © 2019 knightc. All rights reserved.
//

#ifndef kc_ntl_h
#define kc_ntl_h

/*
The basic ring classes are:

ZZ: big integers
ZZ_p: big integers modulo p
zz_p: integers mod "single precision" p
GF2: integers mod 2
ZZX: univariate polynomials over ZZ
ZZ_pX: univariate polynomials over ZZ_p
zz_pX: univariate polynomials over zz_p
GF2X: polynomials over GF2
ZZ_pE: ring/field extension over ZZ_p
zz_pE: ring/field extension over zz_p
GF2E: ring/field extension over GF2
ZZ_pEX: univariate polynomials over ZZ_pE
zz_pEX: univariate polynomials over zz_pE
GF2EX: univariate polynomials over GF2E
*/

/*
destination  source

xdouble      double
quad_float   double
RR           double
ZZ           long
ZZ_p         long
ZZ_pX        long, ZZ_p
zz_p         long
zz_pX        long, zz_p
ZZX          long, ZZ
GF2          long
GF2X         long, GF2
GF2E         long, GF2
GF2EX        long, GF2, GF2E
ZZ_pE        long, ZZ_p
ZZ_pEX       long, ZZ_p, ZZ_pE
zz_pE        long, zz_p
zz_pEX       long, zz_p, zz_pE
*/

/*
 The following is a summary of the main NTL modules. The corresponding documentation file can be obtained by clicking on the module name. Note that the links below will take you to a "pretty printed" version of the correspinding .txt file.
 
 BasicThreadPool    class BasicThreadPool: a simple thread pool; plus additional thread boosting features
 GF2    class GF2: integers mod 2
 GF2X    class GF2X: polynomials over GF(2) (much more efficient than using zz_pX with p=2); includes routines for GCDs and minimal polynomials
 GF2XFactoring    routines for factoring polynomials over GF(2); also includes routines for testing for and constructing irreducible polynomials
 GF2XVec    class GF2XVec: fixed-length vectors of fixed-length GF2Xs; less flexible, but more efficient than vec_GF2X
 GF2E    class GF2E: polynomial extension field/ring over GF(2), implemented as GF(2)[X]/(P).
 GF2EX    class GF2EX class GF2EX: polynomials over GF2E; includes routines for modular polynomials arithmetic, modular composition, minimal and characteristic polynomials, and interpolation.
 GF2EXFactoring    routines for factoring polynomials over GF2E; also includes routines for testing for and constructing irreducible polynomials
 HNF    routines for computing the Hermite Normal Form of a lattice
 Lazy    Support for thread-safe lazy initialization of objects
 LazyTable    Support for thread-safe lazy initialization of tables
 LLL    routines for performing lattice basis reduction, including very fast and robust implementations of the Schnorr-Euchner LLL and Block Korkin Zolotarev reduction algorithm, as well as an integer-only reduction algorithm. Also, there are routines here for computing the kernel and image of an integer matrix, as well as finding integer solutions to linear systems of equations over the integers.
 RR    class RR: arbitrary-precision floating point numbers.
 SmartPtr    template classes SmartPtr, UniquePtr, and a few other useful classes for managing pointers.
 ZZ    class ZZ: arbitrary length integers; includes routines for GCDs, Jacobi symbols, modular arithmetic, and primality testing; also includes small prime generation routines and in-line routines for single-precision modular arithmetic
 ZZ_limbs    Low-level routines for accessing the "limbs" of a ZZ.
 ZZVec    class ZZVec: fixed-length vectors of fixed-length ZZs; less flexible, but more efficient than vec_ZZ
 ZZX    class ZZX: polynomials over ZZ; includes routines for GCDs, minimal and characteristic polynomials, norms and traces
 ZZXFactoring    routines for factoring univariate polynomials over ZZ
 ZZ_p    class ZZ_p: integers mod p
 ZZ_pE    class ZZ_pE: ring/field extension of ZZ_p
 ZZ_pEX    class ZZ_pEX: polynomials over ZZ_pE; includes routines for modular polynomials arithmetic, modular composition, minimal and characteristic polynomials, and interpolation.
 ZZ_pEXFactoring    routines for factoring polynomials over ZZ_pE; also includes routines for testing for and constructing irreducible polynomials
 ZZ_pX    class ZZ_pX: polynomials over ZZ_p; includes routines for modular polynomials arithmetic, modular composition, minimal and characteristic polynomials, and interpolation.
 ZZ_pXFactoring    routines for factoring polynomials over ZZ_p; also includes routines for testing for and constructing irreducible polynomials
 lzz_p    class zz_p: integers mod p, where p is single-precision
 lzz_pE    class zz_pE: ring/field extension of zz_p
 lzz_pEX    class zz_pEX: polynomials over zz_pE; provides the same functionality as class ZZ_pEX, but for single-precision p
 lzz_pEXFactoring    routines for factoring polynomials over zz_pE; provides the same functionality as class ZZ_pEX, but for single-precision p
 lzz_pX    class zz_pX: polynomials over zz_p; provides the same functionality as class ZZ_pX, but for single-precision p
 lzz_pXFactoring    routines for factoring polynomials over zz_p; provides the same functionality as class ZZ_pX, but for single-precision p
 matrix    template class for dynamic-size 2-dimensional arrays
 mat_GF2    class mat_GF2: matrices over GF(2); includes basic matrix arithmetic operations, including determinant calculation, matrix inversion, solving nonsingular systems of linear equations, and Gaussian elimination
 mat_GF2E    class mat_GF2E: matrices over GF2E; includes basic matrix arithmetic operations, including determinant calculation, matrix inversion, solving nonsingular systems of linear equations, and Gaussian elimination
 mat_RR    class mat_RR: matrices over RR; includes basic matrix arithmetic operations, including determinant calculation, matrix inversion, and solving nonsingular systems of linear equations.
 mat_ZZ    class mat_ZZ: matrices over ZZ; includes basic matrix arithmetic operations, including determinant calculation, matrix inversion, and solving nonsingular systems of linear equations. See also the LLL module for additional routines.
 mat_ZZ_p    class mat_ZZ_p: matrices over ZZ_p; includes basic matrix arithmetic operations, including determinant calculation, matrix inversion, solving nonsingular systems of linear equations, and Gaussian elimination
 mat_ZZ_pE    class mat_ZZ_pE: matrices over ZZ_pE; includes basic matrix arithmetic operations, including determinant calculation, matrix inversion, solving nonsingular systems of linear equations, and Gaussian elimination
 mat_lzz_p    class mat_zz_p: matrices over zz_p; includes basic matrix arithmetic operations, including determinant calculation, matrix inversion, solving nonsingular systems of linear equations, and Gaussian elimination
 mat_lzz_pE    class mat_zz_pE: matrices over zz_pE; includes basic matrix arithmetic operations, including determinant calculation, matrix inversion, solving nonsingular systems of linear equations, and Gaussian elimination
 mat_poly_ZZ    routine for computing the characteristic polynomial of a mat_ZZ
 mat_poly_ZZ_p    routine for computing the characteristic polynomial of a mat_ZZ_p
 mat_poly_lzz_p    routine for computing the characteristic polynomial of a mat_zz_p
 pair    template class for pairs
 quad_float    class quad_float: quadruple-precision floating point numbers.
 tools    some basic types and utility routines, including the timing function GetTime(), and several overloaded versions of min() and max()
 vector    template class for dynamic-size vectors
 vec_GF2    class vec_GF2: vectors over GF(2), with arithmetic
 vec_GF2E    class vec_GF2E: vectors over GF2E, with arithmetic
 vec_RR    class vec_RR: vectors over RR, with arithmetic
 vec_ZZ    class vec_ZZ: vectors over ZZ, with arithmetic
 vec_ZZ_p    class vec_ZZ_p: vectors over ZZ_p, with arithmetic
 vec_ZZ_pE    class vec_ZZ_pE: vectors over ZZ_pE, with arithmetic
 vec_lzz_p    class vec_zz_p: vectors over zz_p, with arithmetic
 vec_lzz_pE    class vec_zz_pE: vectors over zz_pE, with arithmetic
 version    macros defining the NTL version number
 xdouble    class xdouble: double-precision floating point numbers with extended exponent range.
 Some other types
 In addition to the above, other generic vectors are declared, not explicitly documented elsewhere:
 
 vec_GF2XVec
 vec_ZZVec
 vec_double
 vec_long
 vec_quad_float
 vec_ulong
 vec_vec_GF2
 vec_vec_GF2E
 vec_vec_RR
 vec_vec_ZZ
 vec_vec_ZZ_p
 vec_vec_ZZ_pE
 vec_vec_long
 vec_vec_lzz_p
 vec_vec_lzz_pE
 vec_vec_ulong
 vec_xdouble
 These decalarations are found in ".h" files with corresponding names. These header files simply provide typedefs for the corresponding template types, mainly for backward compatibility, e.g., vec_double is a typedef for Vec<double>, and vec_vec_RR is a typedef for Vec< Vec<RR> >. No additional functionality is provided.
 
 All of the header files for polynomial classes ZZ_pX, ZZX, etc., declare typedefs for the corresponding vectors of polynomials vec_ZZ_pX, vec_ZZX, etc.
 
 There are also a number of generic pair classes defined, not explicitly documented elsewhere:
 
 pair_GF2EX_long
 pair_GF2X_long
 pair_ZZX_long
 pair_ZZ_pEX_long
 pair_ZZ_pX_long
 pair_lzz_pEX_long
 pair_lzz_pX_long
 
    These decalarations are found in ".h" files with corresponding names. Again, these files mainly exist for backward compatibilty, and provide typedefs for the corresponding template types, e.g., pair_GF2EX_long is a typedef for Pair<GF2EX,long>. These files also give typedefs for the corresponding vector types, e.g., vec_pair_GF2EX_long is a typedef for Vec< Pair<GF2EX,long> >. No additional functionality is provided.
 */



#endif /* kc_ntl_h */
