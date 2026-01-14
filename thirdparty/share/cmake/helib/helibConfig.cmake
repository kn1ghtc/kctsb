# Copyright (C) 2019-2020 IBM Corp.
#
# This program is Licensed under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance
# with the License. You may obtain a copy of the License at
#   http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License. See accompanying LICENSE file.


####### Expanded from @PACKAGE_INIT@ by configure_package_config_file() #######
####### Any changes to this file will be overwritten by the next CMake run ####
####### The input file was helibConfig.cmake.in                            ########

get_filename_component(PACKAGE_PREFIX_DIR "${CMAKE_CURRENT_LIST_DIR}/../../../" ABSOLUTE)

macro(set_and_check _var _file)
  set(${_var} "${_file}")
  if(NOT EXISTS "${_file}")
    message(FATAL_ERROR "File or directory ${_file} referenced by variable ${_var} does not exist !")
  endif()
endmacro()

macro(check_required_components _NAME)
  foreach(comp ${${_NAME}_FIND_COMPONENTS})
    if(NOT ${_NAME}_${comp}_FOUND)
      if(${_NAME}_FIND_REQUIRED_${comp})
        set(${_NAME}_FOUND FALSE)
      endif()
    endif()
  endforeach()
endmacro()

####################################################################################

# Searching pthread pre-emptively to have them defined in case they are required
find_package(Threads QUIET)

include("${CMAKE_CURRENT_LIST_DIR}/helibTargets.cmake")

check_required_components("helib")

get_target_property(helib_public_compile_definitions
                    "helib"
                    INTERFACE_COMPILE_DEFINITIONS)
LIST(FIND helib_public_compile_definitions
          "$<$<BOOL:ON>:HELIB_DEBUG>"
          helib_debug_defined)

if(NOT ${helib_debug_defined} EQUAL -1)
  message(WARNING
          "HElib has been built with HELIB_DEBUG.\nThis can cause issues (sigsegv) if the debugging module is not initialized properly.\nUse with care.\n")
endif(NOT ${helib_debug_defined} EQUAL -1)

unset(helib_public_compile_definitions)
unset(helib_debug_defined)
