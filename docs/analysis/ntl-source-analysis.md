# NTL 11.6.0 源码分析报告

**分析日期**: 2026-01-18 (北京时间)  
**NTL版本**: 11.6.0  
**分析目的**: 为kctsb项目迁移NTL核心数学模块提供技术依据

---

## 1. 源码分类分析

### 1.1 文件统计概览

| 分类 | 文件数量 | 估计行数 | 处理方式 |
|------|----------|----------|----------|
| 核心数学算法 | 62 | ~70,000 | **保留** |
| 测试文件 (*Test*.cpp) | 30 | ~3,700 | **转换为单元测试** |
| 环境检测文件 (Check*.cpp) | 17 | ~800 | **不需要** |
| 配置/构建文件 | 9 | ~2,500 | **不需要** |
| 时间/PID获取文件 | 8 | ~400 | **不需要** |
| lip.cpp 内置大数实现 | 1 | 9,342 | **需要修改** |
| gf2x相关实现 | 2 | ~100 | **需要修改** |

**总计**: 129个.cpp文件, 约87,000行代码

---

### 1.2 核心数学算法文件 (保留 - 62个文件)

#### A. 大整数模块 (ZZ)
```
ZZ.cpp              (4,284 行) - ZZ类核心实现, 依赖lip.h
ZZVec.cpp           (343 行)   - ZZ向量
vec_ZZ.cpp          (226 行)   - ZZ向量操作
```

#### B. 模整数模块 (ZZ_p, lzz_p)
```
ZZ_p.cpp            (359 行)   - 大模数整数环
ZZ_pE.cpp           (218 行)   - ZZ_p扩域
lzz_p.cpp           (467 行)   - 小模数整数环 (long精度)
lzz_pE.cpp          (218 行)   - lzz_p扩域
vec_ZZ_p.cpp        (201 行)   - ZZ_p向量
vec_ZZ_pE.cpp       (146 行)   - ZZ_pE向量
vec_lzz_p.cpp       (178 行)   - lzz_p向量
vec_lzz_pE.cpp      (146 行)   - lzz_pE向量
```

#### C. 整系数多项式 (ZZX)
```
ZZX.cpp             (1,142 行) - ZZX核心实现
ZZX1.cpp            (3,687 行) - ZZX高级运算
ZZXCharPoly.cpp     (226 行)   - 特征多项式
ZZXFactoring.cpp    (3,816 行) - 多项式因式分解
```

#### D. 模多项式 (ZZ_pX, lzz_pX)
```
ZZ_pX.cpp           (4,081 行) - ZZ_p[X]核心实现
ZZ_pX1.cpp          (2,230 行) - ZZ_pX高级运算
ZZ_pXCharPoly.cpp   (191 行)   - 特征多项式
ZZ_pXFactoring.cpp  (1,915 行) - 因式分解
ZZ_pEX.cpp          (3,764 行) - ZZ_pE[X]实现
ZZ_pEXFactoring.cpp (1,593 行) - ZZ_pE[X]因式分解

lzz_pX.cpp          (3,376 行) - lzz_p[X]核心实现
lzz_pX1.cpp         (2,146 行) - lzz_pX高级运算
lzz_pXCharPoly.cpp  (191 行)   - 特征多项式
lzz_pXFactoring.cpp (1,914 行) - 因式分解
lzz_pEX.cpp         (3,763 行) - lzz_pE[X]实现
lzz_pEXFactoring.cpp(1,593 行) - lzz_pE[X]因式分解
```

#### E. GF(2)多项式 (GF2X)
```
GF2.cpp             (148 行)   - GF(2)元素
GF2X.cpp            (2,014 行) - GF(2)[X]核心实现
GF2X1.cpp           (3,705 行) - GF2X高级运算 (含PCLMUL加速)
GF2XFactoring.cpp   (966 行)   - GF2X因式分解
GF2XVec.cpp         (113 行)   - GF2X向量
vec_GF2.cpp         (599 行)   - GF(2)位向量
vec_GF2E.cpp        (122 行)   - GF2E向量
GF2E.cpp            (231 行)   - GF(2)扩域
GF2EX.cpp           (3,952 行) - GF2E[X]实现
GF2EXFactoring.cpp  (2,162 行) - GF2E[X]因式分解
```

#### F. LLL格约化模块
```
LLL.cpp             (706 行)   - LLL算法主入口
LLL_FP.cpp          (1,692 行) - 浮点精度LLL
LLL_QP.cpp          (1,993 行) - 四精度LLL
LLL_RR.cpp          (1,356 行) - 任意精度LLL
LLL_XD.cpp          (1,226 行) - 扩展双精度LLL
G_LLL_FP.cpp        (1,569 行) - Givens旋转浮点LLL
G_LLL_QP.cpp        (2,062 行) - Givens旋转四精度LLL
G_LLL_RR.cpp        (1,366 行) - Givens旋转任意精度LLL
G_LLL_XD.cpp        (1,319 行) - Givens旋转扩展双精度LLL
```

#### G. FFT快速傅里叶变换
```
FFT.cpp             (3,213 行) - 核心FFT实现 (含David Harvey优化)
pd_FFT.cpp          (1,134 行) - AVX加速的packed-double FFT
```

#### H. 任意精度实数 (RR)
```
RR.cpp              (1,980 行) - 任意精度实数
vec_RR.cpp          (122 行)   - RR向量
mat_RR.cpp          (679 行)   - RR矩阵
```

#### I. 扩展精度浮点
```
xdouble.cpp         (913 行)   - 扩展双精度
quad_float.cpp      (415 行)   - 四倍精度浮点
quad_float1.cpp     (386 行)   - 四倍精度浮点辅助
```

#### J. 矩阵模块
```
mat_ZZ.cpp          (1,336 行) - 整数矩阵
mat_ZZ_p.cpp        (1,501 行) - 模整数矩阵
mat_ZZ_pE.cpp       (1,040 行) - ZZ_pE矩阵
mat_lzz_p.cpp       (8,220 行) - lzz_p矩阵 (大量优化)
mat_lzz_pE.cpp      (1,052 行) - lzz_pE矩阵
mat_GF2.cpp         (760 行)   - GF(2)矩阵
mat_GF2E.cpp        (993 行)   - GF2E矩阵
mat_poly_ZZ.cpp     (146 行)   - ZZ多项式矩阵
mat_poly_ZZ_p.cpp   (127 行)   - ZZ_p多项式矩阵
mat_poly_lzz_p.cpp  (127 行)   - lzz_p多项式矩阵
MatPrime.cpp        (518 行)   - 矩阵素数生成
```

#### K. 基础设施模块
```
tools.cpp           (152 行)   - 基础工具
ctools.cpp          (200 行)   - C工具 (含时间函数)
fileio.cpp          (165 行)   - 文件I/O
WordVector.cpp      (397 行)   - 字向量
FacVec.cpp          (219 行)   - 因子向量
thread.cpp          (36 行)    - 线程ID
BasicThreadPool.cpp (36 行)    - 线程池
```

#### L. 其他数学模块
```
HNF.cpp             (128 行)   - Hermite标准形
subset.cpp          (76 行)    - 子集枚举
newnames.cpp        (22 行)    - 命名兼容
```

---

### 1.3 测试文件 (转换为单元测试 - 30个文件)

| 文件名 | 行数 | 测试内容 |
|--------|------|----------|
| ZZTest.cpp | 302 | 大整数测试 |
| ZZ_pXTest.cpp | 416 | 模多项式测试 |
| ZZ_pEXTest.cpp | 57 | ZZ_pE多项式测试 |
| ZZ_pEXGCDTest.cpp | 108 | GCD测试 |
| ZZXFacTest.cpp | 77 | 因式分解测试 |
| LLLTest.cpp | 139 | LLL算法测试 |
| GF2XTest.cpp | 97 | GF2X测试 |
| GF2XTimeTest.cpp | 145 | GF2X性能测试 |
| GF2EXTest.cpp | 133 | GF2EX测试 |
| GF2EXGCDTest.cpp | 104 | GF2EX GCD测试 |
| lzz_pXTest.cpp | 380 | lzz_pX测试 |
| lzz_pEXTest.cpp | 57 | lzz_pEX测试 |
| lzz_pEXGCDTest.cpp | 108 | lzz_pE GCD测试 |
| mat_lzz_pTest.cpp | 291 | 矩阵测试 |
| MatrixTest.cpp | 58 | 通用矩阵测试 |
| BerlekampTest.cpp | 81 | Berlekamp算法测试 |
| BitMatTest.cpp | 81 | 位矩阵测试 |
| CanZassTest.cpp | 80 | Cantor-Zassenhaus测试 |
| CharPolyTest.cpp | 19 | 特征多项式测试 |
| QuadTest.cpp | 111 | quad_float测试 |
| RRTest.cpp | 27 | 任意精度实数测试 |
| QuickTest.cpp | 505 | 快速综合测试 |
| ExceptionTest.cpp | 70 | 异常测试 |
| ThreadTest.cpp | 139 | 多线程测试 |
| SSMulTest.cpp | 81 | SS乘法测试 |
| MoreFacTest.cpp | 66 | 更多因式分解测试 |
| Poly1TimeTest.cpp | 225 | 多项式性能测试1 |
| Poly2TimeTest.cpp | 165 | 多项式性能测试2 |
| Poly3TimeTest.cpp | 171 | 多项式性能测试3 |
| TestGetPID.cpp | 17 | PID获取测试 |
| TestGetTime.cpp | 52 | 时间获取测试 |

**总计**: ~3,700行测试代码

---

### 1.4 环境检测文件 (不需要 - 17个文件)

```
CheckAES_NI.cpp         - AES-NI指令检测
CheckALIGNED_ARRAY.cpp  - 对齐数组检测
CheckAVX.cpp            - AVX指令检测
CheckAVX2.cpp           - AVX2指令检测
CheckAVX512F.cpp        - AVX-512指令检测
CheckBUILTIN_CLZL.cpp   - __builtin_clzl检测
CheckCHRONO_TIME.cpp    - C++11 chrono检测
CheckCompile.cpp        - 编译器检测
CheckContract.cpp       - FP contract检测
CheckCOPY_TRAITS1.cpp   - 复制特性检测1
CheckCOPY_TRAITS2.cpp   - 复制特性检测2
CheckFMA.cpp            - FMA指令检测
CheckGMP.cpp            - GMP库检测
CheckKMA.cpp            - S390x KMA检测
CheckLL_TYPE.cpp        - long long类型检测
CheckMACOS_TIME.cpp     - macOS时间检测
CheckPCLMUL.cpp         - PCLMUL指令检测
CheckPOSIX_TIME.cpp     - POSIX时间检测
CheckSSSE3.cpp          - SSSE3指令检测
CheckThreads.cpp        - 线程支持检测
```

**估计行数**: ~800行 (可完全删除)

---

### 1.5 配置/构建文件 (不需要 - 9个文件)

```
MakeDesc.cpp        (1,261 行) - 机器描述生成
MakeDescAux.cpp     (175 行)   - 机器描述辅助
GenConfigInfo.cpp   (78 行)    - 配置信息生成
gen_gmp_aux.cpp     (167 行)   - GMP辅助生成
InitSettings.cpp    (15 行)    - 设置初始化
DispSettings.cpp    (35 行)    - 设置显示
Timing.cpp          (41 行)    - 计时工具
GF2EXDivCross.cpp   (46 行)    - 交叉优化参数
GF2EXGCDCross.cpp   (46 行)    - 交叉优化参数
GF2EXKarCross.cpp   (46 行)    - 交叉优化参数
GF2EXModCross.cpp   (46 行)    - 交叉优化参数
```

**估计行数**: ~2,000行 (可完全删除)

---

### 1.6 时间/PID获取文件 (不需要 - 8个文件)

```
GetTime0.cpp    - Windows时间实现
GetTime1.cpp    - POSIX times()
GetTime2.cpp    - POSIX getrusage()
GetTime3.cpp    - POSIX clock()
GetTime4.cpp    - macOS时间
GetTime5.cpp    - C++11 chrono
GetPID1.cpp     - POSIX getpid()
GetPID2.cpp     - Windows GetCurrentProcessId()
```

**估计行数**: ~400行 (可完全删除, 由kctsb自行实现跨平台时间)

---

## 2. 核心模块依赖关系

### 2.1 依赖层次图

```
Layer 5: Applications
    ├── LLL (LLL.cpp, LLL_FP.cpp, LLL_QP.cpp, LLL_RR.cpp, LLL_XD.cpp)
    ├── ZZXFactoring, ZZ_pXFactoring, GF2XFactoring
    └── HNF (Hermite Normal Form)
           │
           ▼
Layer 4: Polynomial Arithmetic
    ├── ZZX (ZZX.cpp, ZZX1.cpp)
    ├── ZZ_pX (ZZ_pX.cpp, ZZ_pX1.cpp)
    ├── ZZ_pEX (ZZ_pEX.cpp)
    ├── lzz_pX (lzz_pX.cpp, lzz_pX1.cpp)
    ├── GF2X (GF2X.cpp, GF2X1.cpp) ─── 依赖PCLMUL或gf2x库
    └── GF2EX (GF2EX.cpp)
           │
           ▼
Layer 3: Matrix/Vector
    ├── mat_ZZ, mat_ZZ_p, mat_lzz_p, mat_GF2
    ├── vec_ZZ, vec_ZZ_p, vec_lzz_p, vec_GF2
    └── MatPrime (FFT素数管理)
           │
           ▼
Layer 2: Ring Elements
    ├── ZZ_p (ZZ_p.cpp) ─── 模整数环
    ├── ZZ_pE (ZZ_pE.cpp) ─── ZZ_p扩域
    ├── lzz_p (lzz_p.cpp) ─── 小模数 (long精度)
    ├── lzz_pE (lzz_pE.cpp)
    ├── GF2 (GF2.cpp) ─── GF(2)
    └── GF2E (GF2E.cpp) ─── GF(2)扩域
           │
           ▼
Layer 1: Core Arithmetic
    ├── ZZ (ZZ.cpp) ─── 大整数
    ├── FFT (FFT.cpp, pd_FFT.cpp) ─── 快速傅里叶变换
    ├── RR (RR.cpp) ─── 任意精度实数
    ├── xdouble (xdouble.cpp) ─── 扩展双精度
    └── quad_float (quad_float.cpp) ─── 四倍精度
           │
           ▼
Layer 0: Low-Level
    ├── lip.cpp ─── 大整数底层实现 (包装GMP mpn层)
    ├── WordVector.cpp ─── 字向量
    ├── tools.cpp, ctools.cpp ─── 基础工具
    └── thread.cpp, BasicThreadPool.cpp ─── 线程支持
```

### 2.2 关键依赖关系

| 模块 | 直接依赖 | 硬件加速 |
|------|----------|----------|
| **ZZ** | lip.cpp (→ GMP mpn) | 无 |
| **ZZ_p** | ZZ, FFT | AVX2 (FFT加速) |
| **ZZX** | ZZ, ZZ_p | 无 |
| **GF2X** | lip.cpp, WordVector | **PCLMUL** (关键!) |
| **GF2E** | GF2X | PCLMUL |
| **LLL** | ZZ, RR, xdouble, quad_float, mat_ZZ | 无 |
| **FFT** | lzz_p, tools | **AVX2, FMA** |
| **pd_FFT** | FFT | **AVX2, FMA** (必需) |
| **RR** | ZZ | 无 |

---

## 3. 硬件加速特性分析

### 3.1 AES-NI

**头文件**: `<wmmintrin.h>`, `<emmintrin.h>`, `<tmmintrin.h>`  
**检测文件**: `CheckAES_NI.cpp`  
**使用位置**: `ZZ.cpp` (用于随机数生成的AES-CTR模式)

```cpp
// ZZ.cpp 中使用AES-NI加速伪随机数生成
#if defined(NTL_HAVE_AVX2)
#include <immintrin.h>
#elif defined(NTL_HAVE_SSSE3)
#include <emmintrin.h>
#include <tmmintrin.h>
#endif
```

### 3.2 PCLMUL (无进位乘法)

**头文件**: `<NTL/simde_pclmul.h>` (SIMDE包装)  
**检测文件**: `CheckPCLMUL.cpp`  
**使用位置**: `GF2X.cpp`, `GF2X1.cpp`

```cpp
// GF2X.cpp
#ifdef NTL_HAVE_PCLMUL
#include <NTL/simde_pclmul.h>
// 使用 _mm_clmulepi64_si128 进行GF(2)多项式乘法
#endif
```

**关键性**: ⚠️ **PCLMUL对GF2X性能至关重要**，可提升10-50倍性能

### 3.3 AVX/AVX2

**头文件**: `<immintrin.h>`  
**检测文件**: `CheckAVX.cpp`, `CheckAVX2.cpp`  
**使用位置**: 
- `FFT.cpp` - 向量化FFT蝶形运算
- `pd_FFT.cpp` - packed-double FFT (必须AVX2)
- `ZZ.cpp` - 向量化十六进制转换

```cpp
// pd_FFT.cpp (AVX2专用)
#ifdef NTL_ENABLE_AVX_FFT
#include <NTL/PD.h>  // packed double 类型
#include <immintrin.h>
// 使用 __m256d 进行4路并行FFT
#endif
```

### 3.4 FMA (融合乘加)

**头文件**: `<NTL/simde_fma.h>` (SIMDE包装)  
**检测文件**: `CheckFMA.cpp`  
**使用位置**: `pd_FFT.cpp`

```cpp
// pd_FFT.cpp
#if NTL_FMA_DETECTED
// 使用 _mm256_fmadd_pd 等FMA指令
#endif
```

### 3.5 SSSE3

**头文件**: `<tmmintrin.h>`  
**检测文件**: `CheckSSSE3.cpp`  
**使用位置**: `ZZ.cpp` (SSSE3 shuffle用于十六进制转换)

### 3.6 硬件加速使用汇总

| 特性 | 文件 | 作用 | 必需程度 |
|------|------|------|----------|
| **PCLMUL** | GF2X.cpp, GF2X1.cpp | GF(2)多项式乘法 | 高优先级 |
| **AVX2** | FFT.cpp, pd_FFT.cpp | FFT加速 | 高优先级 |
| **FMA** | pd_FFT.cpp | 融合乘加 | 中等 |
| **AES-NI** | ZZ.cpp | 随机数生成 | 可选 |
| **SSSE3** | ZZ.cpp | 十六进制转换 | 可选 |

---

## 4. lip.cpp分析与GMP替代可行性

### 4.1 lip.cpp结构分析

**文件大小**: 9,342行  
**功能**: 大整数底层实现，分为两种模式：

#### 模式1: GMP模式 (NTL_GMP_LIP定义时)
```cpp
#ifdef NTL_GMP_LIP
typedef mp_limb_t _ntl_limb_t;
#define NTL_MPN(fun) mpn_ ## fun  // 直接调用GMP mpn层
#include <gmp.h>
#endif
```

#### 模式2: 纯C++模式 (NTL_GMP_LIP未定义时)
```cpp
#ifndef NTL_GMP_LIP
typedef unsigned long _ntl_limb_t;
#define NTL_MPN(fun) _ntl_mpn_ ## fun  // 使用内置实现
// 约3000行内置mpn实现
#endif
```

### 4.2 核心函数列表

lip.cpp实现了以下关键函数（NTL_GMP_LIP模式下包装GMP mpn）：

| 函数 | 作用 | GMP对应 |
|------|------|---------|
| `_ntl_gadd` | 大整数加法 | `mpn_add` |
| `_ntl_gsub` | 大整数减法 | `mpn_sub` |
| `_ntl_gmul` | 大整数乘法 | `mpn_mul` |
| `_ntl_gdiv` | 大整数除法 | `mpn_tdiv_qr` |
| `_ntl_gmod` | 取模 | `mpn_tdiv_qr` |
| `_ntl_gpower` | 幂运算 | 自实现 |
| `_ntl_ggcd` | GCD | `mpn_gcd` |
| `_ntl_gexteucl` | 扩展欧几里得 | 自实现 |
| `_ntl_gpowermod` | 模幂 | 自实现 |
| `_ntl_gsqrt` | 整数平方根 | `mpn_sqrtrem` |
| `_ntl_gshift` | 移位 | `mpn_lshift/rshift` |

### 4.3 GMP替代可行性

✅ **可以完全用GMP替代**

**理由**:
1. NTL已原生支持GMP模式，且这是推荐配置
2. lip.cpp的"mini-LIP"仅用于无GMP环境的后备
3. kctsb已将GMP 6.3.0作为核心依赖

**替代方案**:
1. **方案A**: 强制启用`NTL_GMP_LIP`宏，删除~3000行内置mpn实现
2. **方案B**: 直接使用mpz_class C++接口重写ZZ类 (工作量大)

**推荐**: 采用方案A，保留lip.cpp但只编译GMP模式部分

### 4.4 需要修改的文件

| 文件 | 修改内容 |
|------|----------|
| `lip.cpp` | 删除`#ifndef NTL_GMP_LIP`块 (~3000行) |
| `lip.h` | 确保`NTL_GMP_LIP`始终定义 |
| `ctools.h` | 移除LIP相关的条件编译 |
| `gen_gmp_aux.cpp` | 不需要，删除 |

---

## 5. gf2x库集成分析

### 5.1 当前状态

NTL支持两种GF2X实现:
1. **内置实现**: GF2X.cpp, GF2X1.cpp中的PCLMUL加速代码
2. **外部gf2x库**: 通过`NTL_GF2X_LIB`宏启用

### 5.2 相关文件

```cpp
// GF2X.cpp
#ifdef NTL_GF2X_LIB
#include <gf2x.h>  // 使用外部gf2x库
#endif

// gf2x_version_1_2_or_later_required.cpp
// 检测gf2x版本是否≥1.2
```

### 5.3 建议

对于kctsb项目:
- **推荐使用内置PCLMUL实现**，因为:
  1. 现代x86 CPU普遍支持PCLMUL
  2. 减少外部依赖
  3. NTL内置实现已经过良好优化

- 如需外部gf2x库，需要:
  1. 编译gf2x 1.3.0+
  2. 定义`NTL_GF2X_LIB`宏

---

## 6. 建议的目录结构

### 6.1 src/math目录结构

```
kctsb/src/math/
├── ntl/
│   ├── CMakeLists.txt          # NTL子模块构建配置
│   │
│   ├── core/                   # Layer 0-1: 核心算术
│   │   ├── lip.cpp             # GMP包装层 (精简后~6000行)
│   │   ├── ZZ.cpp              # 大整数
│   │   ├── tools.cpp           # 工具函数
│   │   ├── ctools.cpp          # C工具
│   │   ├── WordVector.cpp      # 字向量
│   │   ├── thread.cpp          # 线程支持
│   │   └── BasicThreadPool.cpp # 线程池
│   │
│   ├── ring/                   # Layer 2: 环元素
│   │   ├── ZZ_p.cpp            # 模整数
│   │   ├── ZZ_pE.cpp           # ZZ_p扩域
│   │   ├── lzz_p.cpp           # 小模数
│   │   ├── lzz_pE.cpp          # lzz_p扩域
│   │   ├── GF2.cpp             # GF(2)
│   │   └── GF2E.cpp            # GF(2)扩域
│   │
│   ├── vector/                 # 向量模块
│   │   ├── vec_ZZ.cpp
│   │   ├── vec_ZZ_p.cpp
│   │   ├── vec_ZZ_pE.cpp
│   │   ├── vec_lzz_p.cpp
│   │   ├── vec_lzz_pE.cpp
│   │   ├── vec_GF2.cpp
│   │   ├── vec_GF2E.cpp
│   │   ├── vec_RR.cpp
│   │   ├── ZZVec.cpp
│   │   ├── GF2XVec.cpp
│   │   └── FacVec.cpp
│   │
│   ├── matrix/                 # Layer 3: 矩阵模块
│   │   ├── mat_ZZ.cpp
│   │   ├── mat_ZZ_p.cpp
│   │   ├── mat_ZZ_pE.cpp
│   │   ├── mat_lzz_p.cpp       # 最大文件，含大量优化
│   │   ├── mat_lzz_pE.cpp
│   │   ├── mat_GF2.cpp
│   │   ├── mat_GF2E.cpp
│   │   ├── mat_poly_ZZ.cpp
│   │   ├── mat_poly_ZZ_p.cpp
│   │   ├── mat_poly_lzz_p.cpp
│   │   ├── mat_RR.cpp
│   │   └── MatPrime.cpp
│   │
│   ├── poly/                   # Layer 4: 多项式模块
│   │   ├── ZZX.cpp
│   │   ├── ZZX1.cpp
│   │   ├── ZZXCharPoly.cpp
│   │   ├── ZZXFactoring.cpp
│   │   ├── ZZ_pX.cpp
│   │   ├── ZZ_pX1.cpp
│   │   ├── ZZ_pXCharPoly.cpp
│   │   ├── ZZ_pXFactoring.cpp
│   │   ├── ZZ_pEX.cpp
│   │   ├── ZZ_pEXFactoring.cpp
│   │   ├── lzz_pX.cpp
│   │   ├── lzz_pX1.cpp
│   │   ├── lzz_pXCharPoly.cpp
│   │   ├── lzz_pXFactoring.cpp
│   │   ├── lzz_pEX.cpp
│   │   ├── lzz_pEXFactoring.cpp
│   │   ├── GF2X.cpp            # 含PCLMUL加速
│   │   ├── GF2X1.cpp           # 含PCLMUL加速
│   │   ├── GF2XFactoring.cpp
│   │   ├── GF2EX.cpp
│   │   └── GF2EXFactoring.cpp
│   │
│   ├── fft/                    # FFT模块
│   │   ├── FFT.cpp             # 核心FFT
│   │   └── pd_FFT.cpp          # AVX2加速FFT
│   │
│   ├── precision/              # 精度扩展模块
│   │   ├── RR.cpp              # 任意精度实数
│   │   ├── xdouble.cpp         # 扩展双精度
│   │   ├── quad_float.cpp      # 四倍精度
│   │   └── quad_float1.cpp
│   │
│   ├── lattice/                # Layer 5: 格算法
│   │   ├── LLL.cpp             # LLL主入口
│   │   ├── LLL_FP.cpp          # 浮点LLL
│   │   ├── LLL_QP.cpp          # 四精度LLL
│   │   ├── LLL_RR.cpp          # 任意精度LLL
│   │   ├── LLL_XD.cpp          # 扩展双精度LLL
│   │   ├── G_LLL_FP.cpp        # Givens变换版本
│   │   ├── G_LLL_QP.cpp
│   │   ├── G_LLL_RR.cpp
│   │   ├── G_LLL_XD.cpp
│   │   └── HNF.cpp             # Hermite标准形
│   │
│   ├── io/                     # I/O模块
│   │   └── fileio.cpp
│   │
│   └── compat/                 # 兼容性
│       ├── newnames.cpp
│       └── subset.cpp
│
├── include/NTL/               # 头文件 (从deps/ntl-11.6.0/include/NTL复制)
│   ├── ZZ.h
│   ├── ZZ_p.h
│   ├── ... (所有头文件)
│   └── config.h               # 定制配置
│
└── tests/ntl/                 # 单元测试 (转换自原测试文件)
    ├── test_ZZ.cpp
    ├── test_ZZ_pX.cpp
    ├── test_GF2X.cpp
    ├── test_LLL.cpp
    └── ...
```

### 6.2 头文件处理

需要创建定制的配置头文件:

```cpp
// include/NTL/config.h
#ifndef NTL_CONFIG_H
#define NTL_CONFIG_H

// 强制使用GMP
#define NTL_GMP_LIP 1

// 启用硬件加速
#define NTL_HAVE_PCLMUL 1
#define NTL_HAVE_AVX2 1
#define NTL_HAVE_FMA 1
#define NTL_HAVE_AES_NI 1

// 线程支持
#define NTL_THREADS 1
#define NTL_THREAD_BOOST 1

// 64位
#define NTL_BITS_PER_LONG 64
#define NTL_BITS_PER_INT 32

// 禁用外部gf2x (使用内置PCLMUL)
// #define NTL_GF2X_LIB

#endif
```

---

## 7. 代码行数估算

### 7.1 保留代码

| 分类 | 行数 |
|------|------|
| 核心算术 (lip精简后, ZZ, FFT等) | ~18,000 |
| 环元素 | ~2,000 |
| 向量 | ~2,500 |
| 矩阵 | ~16,000 |
| 多项式 | ~38,000 |
| 精度扩展 | ~3,700 |
| 格算法 | ~13,000 |
| 基础设施 | ~1,000 |
| **保留总计** | **~94,000行** |

*注: 实际保留约70,000行 (删除lip.cpp中~3000行内置mpn)*

### 7.2 删除代码

| 分类 | 行数 |
|------|------|
| 测试文件 | ~3,700 |
| 环境检测 | ~800 |
| 配置/构建 | ~2,000 |
| 时间/PID | ~400 |
| lip.cpp内置mpn | ~3,000 |
| **删除总计** | **~10,000行** |

### 7.3 最终估算

- **原始代码**: ~87,000行
- **删除代码**: ~10,000行
- **保留代码**: ~70,000行 (实现代码)
- **转换为测试**: ~3,700行

---

## 8. 迁移建议与风险

### 8.1 迁移优先级

1. **Phase 1**: 核心算术 (lip.cpp, ZZ.cpp, FFT.cpp)
2. **Phase 2**: 环元素和向量
3. **Phase 3**: 多项式模块
4. **Phase 4**: 矩阵模块
5. **Phase 5**: 格算法 (LLL)
6. **Phase 6**: 精度扩展

### 8.2 潜在风险

| 风险 | 级别 | 缓解措施 |
|------|------|----------|
| GMP版本兼容性 | 低 | 使用GMP 6.3.0+ |
| 硬件加速不可用 | 中 | 编译时检测，提供fallback |
| 线程安全问题 | 中 | 保留NTL的TLS设计 |
| 命名冲突 | 低 | 使用kctsb_ntl命名空间 |
| 测试覆盖不足 | 中 | 转换所有原有测试 |

### 8.3 建议的构建配置

```cmake
# kctsb/src/math/ntl/CMakeLists.txt
target_compile_definitions(kctsb_ntl PRIVATE
    NTL_GMP_LIP=1
    NTL_THREADS=1
    NTL_THREAD_BOOST=1
)

# 检测并启用硬件加速
include(CheckCXXCompilerFlag)
check_cxx_compiler_flag("-mpclmul" HAVE_PCLMUL)
check_cxx_compiler_flag("-mavx2" HAVE_AVX2)
check_cxx_compiler_flag("-mfma" HAVE_FMA)

if(HAVE_PCLMUL)
    target_compile_definitions(kctsb_ntl PRIVATE NTL_HAVE_PCLMUL=1)
    target_compile_options(kctsb_ntl PRIVATE -mpclmul)
endif()

if(HAVE_AVX2)
    target_compile_definitions(kctsb_ntl PRIVATE NTL_HAVE_AVX2=1)
    target_compile_options(kctsb_ntl PRIVATE -mavx2)
endif()

if(HAVE_FMA)
    target_compile_definitions(kctsb_ntl PRIVATE NTL_HAVE_FMA=1)
    target_compile_options(kctsb_ntl PRIVATE -mfma)
endif()
```

---

## 9. 附录: 完整文件清单

### 9.1 保留文件 (62个)

<details>
<summary>点击展开完整列表</summary>

```
# Core
lip.cpp, ZZ.cpp, ZZVec.cpp, vec_ZZ.cpp
tools.cpp, ctools.cpp, fileio.cpp
WordVector.cpp, FacVec.cpp
thread.cpp, BasicThreadPool.cpp

# Ring
ZZ_p.cpp, ZZ_pE.cpp, lzz_p.cpp, lzz_pE.cpp
GF2.cpp, GF2E.cpp
vec_ZZ_p.cpp, vec_ZZ_pE.cpp, vec_lzz_p.cpp, vec_lzz_pE.cpp
vec_GF2.cpp, vec_GF2E.cpp, vec_RR.cpp, GF2XVec.cpp

# Matrix
mat_ZZ.cpp, mat_ZZ_p.cpp, mat_ZZ_pE.cpp
mat_lzz_p.cpp, mat_lzz_pE.cpp
mat_GF2.cpp, mat_GF2E.cpp
mat_poly_ZZ.cpp, mat_poly_ZZ_p.cpp, mat_poly_lzz_p.cpp
mat_RR.cpp, MatPrime.cpp

# Polynomial
ZZX.cpp, ZZX1.cpp, ZZXCharPoly.cpp, ZZXFactoring.cpp
ZZ_pX.cpp, ZZ_pX1.cpp, ZZ_pXCharPoly.cpp, ZZ_pXFactoring.cpp
ZZ_pEX.cpp, ZZ_pEXFactoring.cpp
lzz_pX.cpp, lzz_pX1.cpp, lzz_pXCharPoly.cpp, lzz_pXFactoring.cpp
lzz_pEX.cpp, lzz_pEXFactoring.cpp
GF2X.cpp, GF2X1.cpp, GF2XFactoring.cpp
GF2EX.cpp, GF2EXFactoring.cpp

# FFT
FFT.cpp, pd_FFT.cpp

# Precision
RR.cpp, xdouble.cpp, quad_float.cpp, quad_float1.cpp

# Lattice
LLL.cpp, LLL_FP.cpp, LLL_QP.cpp, LLL_RR.cpp, LLL_XD.cpp
G_LLL_FP.cpp, G_LLL_QP.cpp, G_LLL_RR.cpp, G_LLL_XD.cpp
HNF.cpp

# Compat
newnames.cpp, subset.cpp
```

</details>

### 9.2 删除文件 (67个)

<details>
<summary>点击展开完整列表</summary>

```
# Test Files (30)
BerlekampTest.cpp, BitMatTest.cpp, CanZassTest.cpp, CharPolyTest.cpp
ExceptionTest.cpp, GF2EXGCDTest.cpp, GF2EXTest.cpp, GF2XTest.cpp
GF2XTimeTest.cpp, LLLTest.cpp, lzz_pEXGCDTest.cpp, lzz_pEXTest.cpp
lzz_pXTest.cpp, MatrixTest.cpp, mat_lzz_pTest.cpp, MoreFacTest.cpp
Poly1TimeTest.cpp, Poly2TimeTest.cpp, Poly3TimeTest.cpp
QuadTest.cpp, QuickTest.cpp, RRTest.cpp, SSMulTest.cpp
TestGetPID.cpp, TestGetTime.cpp, ThreadTest.cpp
ZZTest.cpp, ZZXFacTest.cpp, ZZ_pEXGCDTest.cpp, ZZ_pEXTest.cpp, ZZ_pXTest.cpp

# Check Files (17)
CheckAES_NI.cpp, CheckALIGNED_ARRAY.cpp, CheckAVX.cpp, CheckAVX2.cpp
CheckAVX512F.cpp, CheckBUILTIN_CLZL.cpp, CheckCHRONO_TIME.cpp
CheckCompile.cpp, CheckContract.cpp, CheckCOPY_TRAITS1.cpp
CheckCOPY_TRAITS2.cpp, CheckFMA.cpp, CheckGMP.cpp, CheckKMA.cpp
CheckLL_TYPE.cpp, CheckMACOS_TIME.cpp, CheckPCLMUL.cpp
CheckPOSIX_TIME.cpp, CheckSSSE3.cpp, CheckThreads.cpp

# Config/Build (11)
MakeDesc.cpp, MakeDescAux.cpp, GenConfigInfo.cpp, gen_gmp_aux.cpp
InitSettings.cpp, DispSettings.cpp, Timing.cpp
GF2EXDivCross.cpp, GF2EXGCDCross.cpp, GF2EXKarCross.cpp, GF2EXModCross.cpp

# Time/PID (8)
GetTime0.cpp, GetTime1.cpp, GetTime2.cpp, GetTime3.cpp
GetTime4.cpp, GetTime5.cpp, GetPID1.cpp, GetPID2.cpp

# gf2x version check (1)
gf2x_version_1_2_or_later_required.cpp
```

</details>

---

**报告完成**: 2026-01-18 北京时间
