add_test([=[BenchmarkTest.AES128_Performance]=]  D:/pyproject/kctsb/build-release/bin/test_benchmark.exe [==[--gtest_filter=BenchmarkTest.AES128_Performance]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[BenchmarkTest.AES128_Performance]=]  PROPERTIES DEF_SOURCE_LINE [==[D:\pyproject\kctsb\tests\benchmark\test_benchmark.cpp:11]==] WORKING_DIRECTORY D:/pyproject/kctsb/build-release/tests SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==] LABELS performance)
set(  test_benchmark_TESTS BenchmarkTest.AES128_Performance)
