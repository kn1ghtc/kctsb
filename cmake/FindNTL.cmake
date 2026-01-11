# ============================================================================
# FindNTL.cmake - Find NTL (Number Theory Library)
# ============================================================================
#
# This module defines:
#   NTL_FOUND        - True if NTL was found
#   NTL_INCLUDE_DIRS - Include directories for NTL
#   NTL_LIBRARIES    - Libraries to link against
#   NTL::NTL         - Imported target for NTL
#

find_path(NTL_INCLUDE_DIR
    NAMES NTL/ZZ.h
    PATHS
        /usr/local/include
        /usr/include
        /opt/local/include
        /opt/homebrew/include
        $ENV{NTL_ROOT}/include
        ${NTL_ROOT}/include
    PATH_SUFFIXES NTL
)

find_library(NTL_LIBRARY
    NAMES ntl libntl
    PATHS
        /usr/local/lib
        /usr/lib
        /usr/lib64
        /opt/local/lib
        /opt/homebrew/lib
        $ENV{NTL_ROOT}/lib
        ${NTL_ROOT}/lib
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(NTL
    REQUIRED_VARS NTL_LIBRARY NTL_INCLUDE_DIR
)

if(NTL_FOUND)
    set(NTL_INCLUDE_DIRS ${NTL_INCLUDE_DIR})
    set(NTL_LIBRARIES ${NTL_LIBRARY})
    
    if(NOT TARGET NTL::NTL)
        add_library(NTL::NTL UNKNOWN IMPORTED)
        set_target_properties(NTL::NTL PROPERTIES
            IMPORTED_LOCATION "${NTL_LIBRARY}"
            INTERFACE_INCLUDE_DIRECTORIES "${NTL_INCLUDE_DIR}"
        )
    endif()
endif()

mark_as_advanced(NTL_INCLUDE_DIR NTL_LIBRARY)
