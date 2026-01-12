# ============================================================================
# kctsb Examples CMakeLists.txt
# ============================================================================

# Basic AES encryption example
add_executable(example_aes
    basic/aes_example.cpp
)
target_link_libraries(example_aes PRIVATE kctsb)
target_include_directories(example_aes PRIVATE ${CMAKE_SOURCE_DIR}/include)

# Hash functions example
add_executable(example_hash
    basic/hash_example.cpp
)
target_link_libraries(example_hash PRIVATE kctsb)
target_include_directories(example_hash PRIVATE ${CMAKE_SOURCE_DIR}/include)

# SM algorithms example (Chinese National Standards)
add_executable(example_sm
    basic/sm_example.cpp
)
target_link_libraries(example_sm PRIVATE kctsb)
target_include_directories(example_sm PRIVATE ${CMAKE_SOURCE_DIR}/include)

# RSA example
add_executable(example_rsa
    basic/rsa_example.cpp
)
target_link_libraries(example_rsa PRIVATE kctsb)
target_include_directories(example_rsa PRIVATE ${CMAKE_SOURCE_DIR}/include)

# ECC example
add_executable(example_ecc
    basic/ecc_example.cpp
)
target_link_libraries(example_ecc PRIVATE kctsb)
target_include_directories(example_ecc PRIVATE ${CMAKE_SOURCE_DIR}/include)

# Whitebox AES example
add_executable(example_whitebox
    advanced/whitebox_example.cpp
)
target_link_libraries(example_whitebox PRIVATE kctsb)
target_include_directories(example_whitebox PRIVATE ${CMAKE_SOURCE_DIR}/include)

# Secret Sharing example
add_executable(example_sss
    advanced/sss_example.cpp
)
target_link_libraries(example_sss PRIVATE kctsb_static)
if(WIN32)
    target_link_libraries(example_sss PRIVATE bcrypt)
endif()
target_include_directories(example_sss PRIVATE ${CMAKE_SOURCE_DIR}/include)

# Combined demo
add_executable(kctsb_demo
    demo/main.cpp
)
target_link_libraries(kctsb_demo PRIVATE kctsb_static)
if(WIN32)
    target_link_libraries(kctsb_demo PRIVATE bcrypt)
endif()
target_include_directories(kctsb_demo PRIVATE ${CMAKE_SOURCE_DIR}/include)
