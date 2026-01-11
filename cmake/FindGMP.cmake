# ============================================================================
# FindGMP.cmake - Find GMP (GNU Multiple Precision Arithmetic Library)
# ============================================================================
#
# This module defines:
#   GMP_FOUND        - True if GMP was found
#   GMP_INCLUDE_DIRS - Include directories for GMP
#   GMP_LIBRARIES    - Libraries to link against
#   GMP::GMP         - Imported target for GMP
#

find_path(GMP_INCLUDE_DIR
    NAMES gmp.h
    PATHS
        /usr/local/include
        /usr/include
        /opt/local/include
        /opt/homebrew/include
        $ENV{GMP_ROOT}/include
        ${GMP_ROOT}/include
        # Windows Strawberry Perl
        C:/Strawberry/c/include
    PATH_SUFFIXES gmp
)

find_library(GMP_LIBRARY
    NAMES gmp libgmp
    PATHS
        /usr/local/lib
        /usr/lib
        /usr/lib64
        /opt/local/lib
        /opt/homebrew/lib
        $ENV{GMP_ROOT}/lib
        ${GMP_ROOT}/lib
        # Windows Strawberry Perl
        C:/Strawberry/c/lib
)

# Also find GMPXX for C++ support
find_library(GMPXX_LIBRARY
    NAMES gmpxx libgmpxx
    PATHS
        /usr/local/lib
        /usr/lib
        /usr/lib64
        /opt/local/lib
        /opt/homebrew/lib
        $ENV{GMP_ROOT}/lib
        ${GMP_ROOT}/lib
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(GMP
    REQUIRED_VARS GMP_LIBRARY GMP_INCLUDE_DIR
)

if(GMP_FOUND)
    set(GMP_INCLUDE_DIRS ${GMP_INCLUDE_DIR})
    set(GMP_LIBRARIES ${GMP_LIBRARY})
    if(GMPXX_LIBRARY)
        list(APPEND GMP_LIBRARIES ${GMPXX_LIBRARY})
    endif()
    
    if(NOT TARGET GMP::GMP)
        add_library(GMP::GMP UNKNOWN IMPORTED)
        set_target_properties(GMP::GMP PROPERTIES
            IMPORTED_LOCATION "${GMP_LIBRARY}"
            INTERFACE_INCLUDE_DIRECTORIES "${GMP_INCLUDE_DIR}"
        )
        if(GMPXX_LIBRARY)
            set_property(TARGET GMP::GMP APPEND PROPERTY
                INTERFACE_LINK_LIBRARIES "${GMPXX_LIBRARY}"
            )
        endif()
    endif()
endif()

mark_as_advanced(GMP_INCLUDE_DIR GMP_LIBRARY GMPXX_LIBRARY)
