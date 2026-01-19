# kctsb Bignum 重构计划

**版本**: v4.1.0 (计划)  
**日期**: 2026-01-19 (Beijing Time, UTC+8)  
**作者**: kctsb Development Team

---

## 📋 执行摘要

本文档描述了将 NTL 源码集成到 kctsb 后的重构计划，目标是：

1. **彻底去除 NTL 品牌标识**：所有 `NTL_*` 宏改为 `KCTSB_*`
2. **精简头文件数量**：从 117 个减少到约 40 个（与核心 cpp 文件对应）
3. **优化编译速度**：使用 Ninja + 并行 8 路构建 + 增量编译
4. **动态库编译模式**：生成 kctsb.dll，链接预编译的 GMP/gf2x 动态库
5. **清理不需要的功能**：删除浮点精度模块（RR、xdouble、quad_float）

---

## 📊 当前状态分析

### 头文件统计

| 类别 | 数量 | 状态 |
|------|------|------|
| 核心算法头文件 | 35 | ✅ 保留 |
| HAVE_*.h 特性检测 | 17 | ❌ 删除（使用编译器检测） |
| 浮点精度相关 | 12 | ❌ 删除（不需要） |
| 矩阵向量辅助 | 25 | ⚠️ 精简合并 |
| 配置和工具 | 15 | ⚠️ 精简合并 |
| 其他 | 13 | ⚠️ 评估后处理 |
| **总计** | **117** | **目标: ~40** |

### CPP 文件统计

| 目录 | 数量 | 保留 | 删除 |
|------|------|------|------|
| core/ | 11 | 8 | 3 |
| precision/ | 4 | 0 | 4 |
| poly/ | 22 | 22 | 0 |
| ring/ | 6 | 6 | 0 |
| matrix/ | 12 | 10 | 2 |
| vector/ | 8 | 5 | 3 |
| fft/ | 2 | 2 | 0 |
| lattice/ | 11 | 3 | 8 |
| **总计** | **76** | **~56** | **~20** |

---

## 🗑️ Phase 1: 删除不需要的文件

### 1.1 删除 precision/ 目录（浮点精度）

这些文件实现任意精度浮点运算，kctsb 只使用整数运算：

```
src/math/bignum/precision/
├── RR.cpp          ❌ 删除
├── quad_float.cpp  ❌ 删除
├── quad_float1.cpp ❌ 删除
└── xdouble.cpp     ❌ 删除
```

对应头文件：
```
include/kctsb/math/bignum/
├── RR.h            ❌ 删除
├── quad_float.h    ❌ 删除
├── xdouble.h       ❌ 删除
├── vec_RR.h        ❌ 删除
├── vec_quad_float.h ❌ 删除
├── vec_xdouble.h   ❌ 删除
├── vec_vec_RR.h    ❌ 删除
└── mat_RR.h        ❌ 删除
```

### 1.2 删除 HAVE_*.h 特性检测头文件

这些文件用于 NTL 的 configure 系统，我们使用 CMake 编译器检测替代：

```
include/kctsb/math/bignum/
├── HAVE_AES_NI.h         ❌ 删除
├── HAVE_ALIGNED_ARRAY.h  ❌ 删除
├── HAVE_AVX.h            ❌ 删除
├── HAVE_AVX2.h           ❌ 删除
├── HAVE_AVX512F.h        ❌ 删除
├── HAVE_BUILTIN_CLZL.h   ❌ 删除
├── HAVE_CHRONO_TIME.h    ❌ 删除
├── HAVE_COPY_TRAITS1.h   ❌ 删除
├── HAVE_COPY_TRAITS2.h   ❌ 删除
├── HAVE_FMA.h            ❌ 删除
├── HAVE_KMA.h            ❌ 删除
├── HAVE_LL_TYPE.h        ❌ 删除
├── HAVE_MACOS_TIME.h     ❌ 删除
├── HAVE_PCLMUL.h         ❌ 删除
├── HAVE_POSIX_TIME.h     ❌ 删除
├── HAVE_SSSE3.h          ❌ 删除
└── linux_s390x.h         ❌ 删除
```

### 1.3 删除 lattice/ 目录的扩展精度 LLL

保留基本 LLL 算法，删除扩展精度变体：

```
src/math/bignum/lattice/
├── LLL.cpp      ✅ 保留
├── HNF.cpp      ✅ 保留
├── FacVec.cpp   ✅ 保留
├── LLL_FP.cpp   ❌ 删除（依赖 RR）
├── LLL_QP.cpp   ❌ 删除
├── LLL_RR.cpp   ❌ 删除
├── LLL_XD.cpp   ❌ 删除
├── G_LLL_FP.cpp ❌ 删除
├── G_LLL_QP.cpp ❌ 删除
├── G_LLL_RR.cpp ❌ 删除
└── G_LLL_XD.cpp ❌ 删除
```

### 1.4 删除不需要的 core/ 文件

```
src/math/bignum/core/
├── subset.cpp   ❌ 删除（NTL 工具）
├── newnames.cpp ❌ 删除（NTL 兼容层）
├── ctools.cpp   ⚠️ 评估
```

### 1.5 删除其他不需要的头文件

```
include/kctsb/math/bignum/
├── ALL_FEATURES.h        ❌ 删除
├── REPORT_ALL_FEATURES.h ❌ 删除
├── PackageInfo.h         ❌ 删除
├── version.h             ❌ 删除（使用 kctsb/version.h）
├── new.h                 ❌ 删除
├── mach_desc.h           ❌ 删除
├── PD.h                  ❌ 删除（专用于精度）
├── simde_*.h             ⚠️ 评估（SIMD 模拟）
```

---

## 🔧 Phase 2: 重命名 NTL 宏为 KCTSB 宏

### 2.1 全局宏替换

| 旧宏 | 新宏 | 说明 |
|------|------|------|
| `NTL_GMP_LIP` | `KCTSB_GMP_LIP` | GMP 后端 |
| `NTL_GF2X_LIB` | `KCTSB_GF2X_LIB` | gf2x 库 |
| `NTL_THREADS` | `KCTSB_THREADS` | 线程支持 |
| `NTL_STD_CXX17` | `KCTSB_STD_CXX17` | C++17 |
| `NTL_EXCEPTIONS` | `KCTSB_EXCEPTIONS` | 异常支持 |
| `NTL_HAVE_*` | 编译器检测 | 删除 |
| `NTL_NAMESPACE` | 删除 | 使用 kctsb::bignum |

### 2.2 命名空间变更

```cpp
// 旧代码
NTL_START_IMPL
namespace NTL {
    ...
}
NTL_END_IMPL

// 新代码
namespace kctsb {
namespace bignum {
    ...
}
}
```

---

## 📁 Phase 3: 头文件结构重构

### 3.1 目标结构

```
include/kctsb/math/bignum/
├── bignum.h              # 主头文件（对外）
├── config.h              # 配置（合并所有配置）
├── ZZ.h                  # 大整数
├── ZZ_p.h                # 模整数
├── ZZ_pE.h               # 有限域扩展
├── GF2.h                 # GF(2)
├── GF2X.h                # GF(2)[X] 多项式
├── GF2E.h                # GF(2^k) 扩展域
├── matrix.h              # 矩阵运算（合并）
├── vector.h              # 向量运算（合并）
├── polynomial.h          # 多项式运算（合并）
├── fft.h                 # FFT 算法（合并）
├── lll.h                 # 格基规约（合并）
├── tools.h               # 工具函数
├── thread.h              # 线程池
└── internal/             # 内部头文件
    ├── lip.h             # 低级整数操作
    ├── sp_arith.h        # 单精度运算
    ├── gmp_aux.h         # GMP 辅助
    ├── lazy.h            # 延迟求值
    └── smart_ptr.h       # 智能指针
```

### 3.2 头文件合并策略

| 合并后 | 合并前 |
|--------|--------|
| `matrix.h` | mat_ZZ.h, mat_ZZ_p.h, mat_ZZ_pE.h, mat_GF2.h, mat_GF2E.h, mat_lzz_p.h, mat_lzz_pE.h, mat_poly_*.h, MatPrime.h |
| `vector.h` | vec_ZZ.h, vec_ZZ_p.h, vec_ZZ_pE.h, vec_GF2.h, vec_GF2E.h, vec_lzz_p.h, vec_lzz_pE.h, vec_long.h, vec_ulong.h, vec_double.h |
| `polynomial.h` | ZZX.h, ZZ_pX.h, ZZ_pEX.h, GF2X.h, GF2EX.h, lzz_pX.h, lzz_pEX.h, *Factoring.h |
| `fft.h` | FFT.h, FFT_impl.h, pd_FFT.h |
| `lll.h` | LLL.h, HNF.h, FacVec.h |
| `config.h` | config.h, kctsb_bignum_config.h, platform.h |

---

## ⚡ Phase 4: 编译优化

### 4.1 CMake 配置变更

```cmake
# 默认使用 Ninja
set(CMAKE_GENERATOR "Ninja" CACHE STRING "Build generator")

# 并行 8 路构建
set(CMAKE_BUILD_PARALLEL_LEVEL 8 CACHE STRING "Parallel build level")

# 增量编译优化
set(CMAKE_DEPENDS_IN_PROJECT_ONLY ON)

# 默认不构建测试（使用 -DKCTSB_BUILD_TESTS=ON 显式启用）
option(KCTSB_BUILD_TESTS "Build tests" OFF)

# 动态库编译
option(KCTSB_BUILD_SHARED "Build shared library" ON)
option(KCTSB_BUILD_STATIC "Build static library" OFF)
```

### 4.2 预编译头文件（PCH）

```cmake
# 使用预编译头文件加速编译
target_precompile_headers(kctsb_shared PRIVATE
    <cstdint>
    <cstring>
    <vector>
    <array>
    <memory>
    "kctsb/math/bignum/ZZ.h"
)
```

### 4.3 动态库链接

```cmake
# thirdparty 动态库搜索顺序
# 1. ${CMAKE_BINARY_DIR}/lib (构建输出)
# 2. ${KCTSB_THIRDPARTY_PLATFORM_DIR}/lib
# 3. 系统路径

# 构建后复制依赖动态库到输出目录
add_custom_command(TARGET kctsb_shared POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${KCTSB_THIRDPARTY_PLATFORM_DIR}/lib/libgmp.dll"
        "${KCTSB_THIRDPARTY_PLATFORM_DIR}/lib/libgf2x.dll"
        $<TARGET_FILE_DIR:kctsb_shared>
)
```

---

## 🧪 Phase 5: 测试迁移

### 5.1 GoogleTest 迁移

将 NTL 原有测试迁移到 GoogleTest 框架：

| 原测试 | 新测试 | 优先级 |
|--------|--------|--------|
| ZZTest | test_zz.cpp | 高 |
| GF2XTest | test_gf2x.cpp | 高 |
| ZZ_pTest | test_zz_p.cpp | 高 |
| MatTest | test_matrix.cpp | 中 |
| PolyTest | test_polynomial.cpp | 中 |
| FFTTest | test_fft.cpp | 低 |
| LLLTest | test_lll.cpp | 低 |

### 5.2 测试结构

```
tests/
├── CMakeLists.txt
├── bignum/
│   ├── test_zz.cpp
│   ├── test_zz_p.cpp
│   ├── test_gf2x.cpp
│   ├── test_matrix.cpp
│   ├── test_polynomial.cpp
│   └── test_lll.cpp
└── ...
```

---

## 📜 Phase 6: 脚本清理

### 6.1 删除的脚本

```
scripts/
├── build_ntl.ps1           ❌ 删除
├── build_ntl_bundled.ps1   ❌ 删除
├── build_ntl_bundled.sh    ❌ 删除
├── compile_ntl_full.ps1    ❌ 删除
├── compile_ntl_optimized.ps1 ❌ 删除
├── compile_ntl_optimized.sh  ❌ 删除
└── migrate_ntl.py          ❌ 删除
```

### 6.2 更新的脚本

```
scripts/
├── build.ps1               ✅ 更新（动态库模式）
├── build.sh                ✅ 更新
├── build_gmp.ps1           ✅ 保留（一次性编译）
├── build_helib.ps1         ⚠️ 可选
├── build_seal_mingw.ps1    ⚠️ 可选
└── docker_build.sh         ✅ 更新
```

---

## 📅 执行时间表

| 阶段 | 任务 | 预计耗时 | 状态 |
|------|------|----------|------|
| Phase 1 | 删除不需要的文件 | 2 小时 | ⏳ 待开始 |
| Phase 2 | 重命名 NTL 宏 | 3 小时 | ⏳ 待开始 |
| Phase 3 | 头文件重构 | 8 小时 | ⏳ 待开始 |
| Phase 4 | 编译优化 | 2 小时 | ⏳ 待开始 |
| Phase 5 | 测试迁移 | 4 小时 | ⏳ 待开始 |
| Phase 6 | 脚本清理 | 1 小时 | ⏳ 待开始 |

**总计**: 约 20 小时工作量

---

## ⚠️ 风险和注意事项

1. **编译兼容性**: 删除文件后需要修复所有 `#include` 依赖
2. **功能完整性**: 确保 ECC、RSA、SM2 等核心功能不受影响
3. **性能回归**: 删除优化代码可能影响性能，需要 benchmark 验证
4. **API 稳定性**: 外部 API 不变，只重构内部实现

---

**文档状态**: 初版  
**最后更新**: 2026-01-19 (Beijing Time, UTC+8)
