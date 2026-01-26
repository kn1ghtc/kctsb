/**
 * @file zz_p.cpp
 * @brief Static member definitions for ZZ_pContext
 * @author kctsb Team
 * @version 5.1
 * 
 * This file provides static member definitions that are needed for the
 * self-contained bignum implementation. Only static pointer members that are
 * declared but not defined in headers are defined here.
 */

#include "kctsb/math/ZZ_p.h"

namespace kctsb {

// ============================================================================
// ZZ_pContext static member definitions
// ============================================================================

ZZ_pContext* ZZ_pContext::current_ = nullptr;

} // namespace kctsb
