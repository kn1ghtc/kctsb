/**
 * @file zz_p.cpp
 * @brief Static member definitions for ZZ_pContext and GF2EContext
 * @author kctsb Team
 * @version 5.0
 * 
 * This file provides static member definitions that are needed for the
 * self-contained bignum implementation. Only static pointer members that are
 * declared but not defined in headers are defined here.
 */

#include "kctsb/math/bignum/ZZ_p.h"
#include "kctsb/math/bignum/GF2E.h"

namespace kctsb {

// ============================================================================
// ZZ_pContext static member definitions
// ============================================================================

ZZ_pContext* ZZ_pContext::current_ = nullptr;

// ============================================================================
// GF2EContext static member definitions
// ============================================================================

GF2EContext* GF2EContext::current_ = nullptr;

} // namespace kctsb
