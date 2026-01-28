# kctsb - Knight's Cryptographic Trusted Security Base

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)](.)
[![C++](https://img.shields.io/badge/C++-17-blue.svg)](.)
[![CMake](https://img.shields.io/badge/CMake-3.20+-green.svg)](.)
[![Version](https://img.shields.io/badge/Version-5.0.0-brightgreen.svg)](.)

**kctsb** 是一个跨平台的 C/C++ 密码学和安全算法库，专为生产环境和安全研究设计。目标是成为 **OpenSSL/SEAL 的工业级现代替代品，并支持最前沿的安全与AI方向高效算法实践**。

## 🎉 v5.0.0 重大发布 (2026-01-26)

**完全自包含架构** - 移除所有外部数学库依赖，**DLL体积87%优化** (10.1MB → 1.3MB)：
- ✅ `kctsb::ZZ` - 完全自包含任意精度整数 (替代 NTL::ZZ)
- ✅ `kctsb::ZZ_p` - 模 p 剩余类环运算
- ✅ `kctsb::ZZX` - 整系数多项式环
- ✅ `kctsb::GF2X` - GF(2) 上的多项式 (无需 gf2x)
- ✅ `kctsb::GF2E` - GF(2^n) 扩展域
- ✅ **221 个测试全部通过，测试时间 12.7 秒**
- ✅ **Chow白盒AES重构** - 单文件实现，OpenSSL T-table优化
- ✅ **零外部依赖** - 核心库无需 GMP/NTL/gf2x

📖 **完整Release Notes**: [v5.0.0 Release](docs/releases/v5.0.0-release.md)
📊 **GmSSL性能分析**: [GmSSL Performance Analysis](docs/analysis/20260126_gmssl_performance_analysis.md)


## ✨ 特性

### 对称加密算法
- **AES** - AES-128/192/256，支持 **CTR/GCM** 模式（移除 ECB/CBC的不安全模式）
- **ChaCha20-Poly1305** - RFC 8439 AEAD 流密码
- **SM4-GCM** - 国密 SM4 分组密码，仅支持 GCM 认证加密模式

### AEAD 认证加密
- **AES-GCM** - Galois/Counter Mode，128-bit 认证标签
- **ChaCha20-Poly1305** - 256-bit 密钥，128-bit 标签

### 非对称加密算法
- **RSA** - RSA-3072/4096 OAEP加密/PSS签名 (PKCS#1 v2.2, SHA-256)
  - 固定窗口模幂预计算（5/6-bit 窗口、栈内表）以提升 RSA 运算性能
- **ECC** - 完整椭圆曲线密码（secp256k1, P-256）**原生实现**
- **ECDSA** - RFC 6979 确定性签名
- **ECDH** - RFC 5869 HKDF 密钥派生
- **ECIES** - 混合加密 (ECDH + AES-GCM)
- **SM2** - 国密 SM2 椭圆曲线
- **DH** - Diffie-Hellman 密钥交换 (RFC 3526)
- **DSA** - FIPS 186-4 数字签名

**RSA 安全策略（2026）**：仅保留 OAEP/PSS + SHA-256，禁用 PKCS#1 v1.5、Raw RSA、2048 位及以下密钥。

### 后量子密码
- **Kyber** - ML-KEM (FIPS 203), 512/768/1024
- **Dilithium** - ML-DSA (FIPS 204), Level 2/3/5

### 零知识证明
- **zk-SNARKs** - Groth16 协议 (BN254 曲线)
- **电路构建器** - 乘法门、加法门、布尔约束、范围证明

### SIMD 硬件加速 (v4.13.0 IFMA 优化)
- **AES-NI** - 硬件 AES-128/256 加速 (Intel Westmere+) ✅ **42x 提速**
- **PCLMUL** - GHASH 硬件加速 (GF(2^128) 乘法) ✅ **GCM 模式优化**
- **SHA-NI** - 硬件 SHA-256 加速 (Intel Goldmont+)
- **AVX2** - Keccak/SHA3-256 向量化优化
- **AVX-512** - 512-bit 向量化运算
- **AVX-512 IFMA** - 52-bit 精度融合乘加 ✅ **NTT 全向量化模乘** (Ice Lake+)
- **常量时间操作** - 防止侧信道攻击

### 哈希算法
- **SHA** - SHA-1/256/384/512 (SHA-NI 加速)
- **SHA3** - SHA3-256 (AVX2 优化)
- **SM3** - 国密 SM3 哈希
- **BLAKE2b** - RFC 7693 高性能哈希

### 安全原语
- **常量时间操作** - 防止时序攻击
- **安全内存** - 自动安全清零
- **CSPRNG** - 跨平台安全随机数

### 高级密码学原语
- **白盒密码** - Chow 白盒 AES/SM4 实现
- **秘密共享** - Shamir (t,n) 门限方案
- **同态加密** ✅ **三大方案完整实现 + NTT Barrett优化**
  - **BGV 方案** - 原生实现，精确整数同态加密 ✅
    - 密钥生成、加密/解密、加法/乘法/重线性化
    - 噪声预算管理、批量编码 (SIMD slots)
    - NTT+Barrett加速
  - **BFV 方案** - Scale-invariant 编码，复用 BGV 基础设施 ✅
    - 完整加密/解密/运算支持
    - BEHZ RNS 重缩放（开发中）
  - **vs Microsoft SEAL 4.1 性能对比** (n=8192, t=65537, 128-bit 安全) 📊
    | 操作 | kctsb (ms) | SEAL 4.1 (ms) | 比率 | 状态 |
    |------|------------|---------------|------|------|
    | Multiply CT-CT | 24.3 | 8.5 | 2.86x | OK |
    | Mul + Relin | 18.9 | 16.5 | 1.15x | ✅ 良好 |
    | Decrypt | 1.4 | 1.0 | 1.40x | OK |
    | Encrypt | 4.0 | 3.0 | 1.33x | OK |
    - **综合评估**: BFV 实现与 SEAL 性能接近 (1.2-2.9x)
  - **CKKS 方案** - 近似实数/复数同态加密 ✅ **RNS Key Switching 完整实现**
    - FFT 正则嵌入编码，支持复数向量
    - Rescale 机制控制精度和噪声
    - 多层乘法深度支持 (3-5 层)
    - **RNS 分解密钥切换** - CRT-based 低噪声 key switching
      - 每个模 q_j 生成独立密钥分量
      - 噪声增长 O(√(n*L)*σ) 而非 O(√n*‖c2‖)
      - 无需特殊素数 P，纯 RNS 操作
  - **vs Microsoft SEAL 4.1 性能对比** (n=8192, L=5, 128-bit 安全) 📊
    | 操作 | kctsb (ms) | SEAL 4.1 (ms) | 比率 | 状态 |
    |------|------------|---------------|------|------|
    | Multiply CT-CT | 2.15 | 9.0 | **0.24x** | ✅ 优秀 |
    | Decrypt | 0.83 | 1.5 | **0.56x** | ✅ 优秀 |
    | Relin Key Gen | 13.16 | 26.0 | **0.51x** | ✅ 优秀 |
    | Mul + Relin | 13.73 | 17.5 | **0.78x** | ✅ 良好 |
    | Encrypt | 5.41 | 3.5 | 1.55x | OK |
    | Encode (FFT) | 2693 | 0.25 | 10772x | ⚠️ 优化中 |
    - **综合性能**: 1.02x (核心操作与 SEAL 持平或更优)
    - **优势领域**: 乘法 (4.2x 加速)、解密 (1.8x 加速)、密钥生成 (2.0x 加速)
    - **待优化**: FFT 编码/解码 (需 SIMD/AVX2 加速)
  - **性能优化** - Harvey NTT + RNSPoly 架构 ✅
    - **Harvey NTT 算法**: SEAL-style lazy reduction, 正确的 Gentleman-Sande 逆NTT
    - **RNSPoly 类**: 独立的 RNS 多项式基础设施，NTT 变换支持
  - **BGV EvaluatorV2** - 纯 RNS 实现 ✅ **完成**
    - 零 ZZ_pX 依赖，全程 RNS 操作
    - 密钥/密文均存储在 NTT domain
    - `__int128` 高精度 CRT 重建，支持任意模数数量
    - BGV 正确编码：误差乘以明文模 t
    - **工业级 Hybrid Key Switching** - digit decomposition 降低噪声增长
  - **vs Microsoft SEAL 4.1 性能对比** (n=8192, t=65537) 📊
    - Relin Key Gen: **4.46x 加速** (1.42ms vs 6.32ms)
    - Mul + Relin: **1.46x 加速** (2.32ms vs 3.40ms)
    - Encrypt: 0.97x (3.75ms vs 3.62ms)
  - **工业级参数推荐** (128-bit 安全性) 📋
    - 轻量级: `n=4096, L=3, 50-bit primes, t=65537` (≤3次乘法)
    - 标准级: `n=8192, L=5, 50-bit primes, t=65537` (≤5次乘法)
    - 企业级: `n=16384, L=8, 50-bit primes, t=65537` (≤8次乘法)
    - 高安全: `n=32768, L=12, 45-bit primes, t=65537` (≤12次乘法)

- **隐私计算协议** ✅ **PSI/PIR 完整实现** (v4.14.0 增强)
  - **Piano-PSI** - O(√n) 通信复杂度隐私集合交集 🎯 **大规模平衡数据集首选**
    - Cuckoo 哈希 + 亚线性 PIR 技术
    - 支持大规模数据集 (百万级)
    - 使用场景：双方集合大小相近、半诚实安全模型
  - **OT-based PSI** - 基于混淆传输的 PSI 🛡️ **恶意安全模型首选**
    - IKNP OT Extension 协议 (生产级实现，参考 libOTe)
    - 支持半诚实/恶意安全模型
    - AES-NI/AVX2 硬件加速
    - 使用场景：需恶意安全、中小规模数据集
  - **Multi-party PSI** ✅ **v4.14.0 新增** - 3+ 参与方隐私集合交集
    - 星形/环形/树形拓扑
    - 支持 10+ 参与方
    - 使用场景：多方联合查询、联邦学习场景
  - **PSI-CA** ✅ **v4.14.0 新增** - PSI with Cardinality and Attributes
    - 基数模式：仅返回交集大小
    - 负载模式：返回交集元素及关联属性
    - 聚合模式：SUM/COUNT/AVG/MIN/MAX
    - 阈值模式：仅当交集满足条件时返回
    - 使用场景：隐私统计、条件披露
  - **Native PIR** - 原生 FHE-based 私密信息检索 ✅ **无 SEAL 依赖**
    - 支持 BGV/BFV/CKKS 三种方案
    - SIMD 批处理优化
    - 整数/浮点/二进制数据库
    - vs SEAL-PIR 性能: **1.23x 加速** (DB=1000)
  - **CUDA GPU PIR** ✅ **v4.14.0 验证完成** - GPU 加速私密信息检索
    - BFV/BGV/CKKS GPU 并行 (NTT/INTT/PolyMul)
    - CPU 自动回退 (无 CUDA 环境)
    - **实测性能** (RTX 4060 Laptop, CUDA 12.5):
      - n=65536: NTT **6.77x 加速**，PolyMul **7.17x 加速**
      - n=262144: NTT **20.11x 加速**，PolyMul **20.03x 加速**
      - n=1048576: NTT **51.56x 加速**，PolyMul **36.95x 加速**
    - 使用场景：大规模数据库 (n≥16K)、低延迟要求
  - **Unified CUDA FHE** ✅ **v4.15.0 新增** - 统一 CUDA 加速层
    - 位于 `src/advanced/cuda/` 独立模块
    - Harvey NTT + Shoup 预计算 (无除法热路径)
    - Tree-order 根表布局，CT-NTT/GS-INTT 正确性验证
    - **FHE 安全参数性能** (RTX 4060 Laptop, CUDA 12.5):
      - n=8192, L=3: CT Tensor Mul **5.22x**, NTT Inverse **2.72x**
      - n=16384, L=12: NTT Inverse **6.48x**, CT Tensor Mul **4.82x**
      - n=32768, L=12: **NTT Inverse 10.38x**, CT Tensor Mul **4.90x**, Poly Mul **3.48x**
    - 50-bit NTT 友好素数支持 (n≤16384)
    - 31-bit NTT 素数支持 (n≤2^27)
  - **PIR with Preprocessing** ✅ **v4.14.0 新增** - 离线/在线分离 PIR
    - 提示式 PIR：客户端存储 O(√N) 提示
    - 关键字 PIR：按关键字检索无需知道位置
    - 批量 PIR：多查询分摊成本
    - 使用场景：高频查询、客户端有存储空间
  - 详见 [PSI/PIR 性能基线](docs/PSI_PIR_PERFORMANCE.md)

  **🎯 PSI/PIR 方案选择指南**

  | 场景 | 推荐方案 | 理由 |
  |------|----------|------|
  | 大规模平衡数据集 (百万级) | Piano-PSI | O(√n) 通信，半诚实安全 |
  | 恶意安全要求 | OT-PSI | 支持恶意安全模型 |
  | 多方参与 (3+) | Multi-party PSI | 星形/环形拓扑优化 |
  | 仅需交集基数 | PSI-CA (基数模式) | 最小信息披露 |
  | 隐私统计聚合 | PSI-CA (聚合模式) | 支持 SUM/AVG 等 |
  | 大规模 PIR + GPU | CUDA PIR | 并行加速 (n≥16K, **20-50x 加速**) |
  | 高频 PIR 查询 | PIR Preprocessing | 离线预计算提速 |

## 🏗️ 项目结构

```shell
kctsb/
├── CMakeLists.txt              # 主构建配置 (CMake 3.20+, Ninja推荐)
├── README.md                   # 项目文档
├── AGENTS.md                   # AI开发指南
├── FHE_PERFORMANCE.md          # FHE 性能规范
├── OPENSSL_PERFORMANCE.md      # OpenSSL 性能规范
├── deps/                       # 第三方benchmark参考源码 (NTL, openssl, SEAL, HElib)
├── LICENSE                     # Apache 2.0 许可证
│
├── include/                    # ★所有头文件在这里★
│   └── kctsb/
│       ├── kctsb.h             # 主入口头文件
│       ├── core/               # 核心定义
│       ├── crypto/             # 标准密码算法公共头 (v3.4.0 简化)
│       │   ├── aes.h           # AES-GCM
│       │   ├── chacha20_poly1305.h  # ChaCha20-Poly1305
│       │   ├── sha256.h        # SHA-256 (FIPS 180-4)
│       │   ├── sha512.h        # SHA-512/384 (FIPS 180-4)
│       │   ├── sha3.h          # SHA3/SHAKE (FIPS 202)
│       │   ├── blake2.h        # BLAKE2b (RFC 7693)
│       │   ├── sm3.h           # SM3 (GB/T 32905-2016)
│       │   ├── sm4.h           # SM4-GCM (GB/T 32907-2016)
│       │   ├── ecc/, rsa/      # 非对称算法头
│       │   └── sm/             # 国密算法头 (ZUC)
│       ├── advanced/           # 高级密码学
│       │   ├── pqc/            # 后量子密码 (Kyber, Dilithium)
│       │   ├── zk/             # 零知识证明 (Groth16)
│       │   ├── fe/             # 功能加密
│       │   ├── sss/            # 秘密共享
│       │   └── whitebox/       # 白盒密码
│       ├── simd/               # SIMD 硬件加速
│       │   └── simd.h          # AVX2/AVX-512/AES-NI
│       ├── math/               # 数学工具
│       └── utils/              # 实用工具
│
├── src/                        # ★源代码实现 (v3.4.0 扁平化)★
│   ├── core/                   # 核心功能
│   ├── crypto/                 # 密码算法实现 (单文件单算法)
│   │   ├── sha256.cpp          # SHA-256 C++ 实现 + C ABI
│   │   ├── sha512.cpp          # SHA-512/384 C++ 实现 + C ABI
│   │   ├── sha3.cpp            # SHA3/SHAKE C++ 实现 + C ABI
│   │   ├── blake2.cpp          # BLAKE2b C++ 实现 + C ABI
│   │   ├── sm3.cpp             # SM3 C++ 实现 + C ABI
│   │   ├── sm4.cpp             # SM4-GCM C++ 实现 + C ABI
│   │   ├── aes/                # AES-GCM 实现
│   │   ├── chacha20/           # ChaCha20-Poly1305
│   │   ├── ecc/                # 椭圆曲线 (NTL实现)
│   │   └── rsa/                # RSA (NTL实现)
│   ├── advanced/               # 高级算法实现
│   │   ├── pqc/                # 后量子密码实现
│   │   └── zk/                 # 零知识证明实现
│   ├── simd/                   # SIMD 加速实现
│   ├── cli/                    # 命令行工具
│   └── math/                   # 数学库
│
├── tests/                      # GoogleTest测试代码
├── benchmarks/                 # 性能对比测试 (vs OpenSSL)
├── thirdparty/                 # ★第三方库统一目录★
│   ├── win-x64/                # Windows x64 平台特定库 (可选)
│   ├── linux-x64/              # Linux x64 平台特定库 (可选)
│   ├── macos-x64/              # macOS x64 平台特定库 (可选)
│   ├── include/                # NTL/, gf2x/, gmp.h, SEAL-4.1/, helib/
│   └── lib/                    # libntl.a, libgf2x.a, libgmp.a, etc.
├── release/                    # ★跨平台发布目录★
│   ├── win-x64/                # Windows x64 构建产物
│   │   ├── bin/kctsb.exe       # CLI 工具 (全静态链接)
│   │   ├── lib/
│   │   │   ├── libkctsb.a      # 静态库
│   │   │   └── libkctsb_bundled.a  # ★ 打包库（含所有依赖）★
│   │   └── include/kctsb_api.h # 唯一公共头文件
│   ├── linux-x64/              # Linux x64 构建产物
│   │   ├── bin/kctsb           # CLI 工具 (全静态链接)
│   │   ├── lib/
│   │   │   ├── libkctsb.a      # 静态库
│   │   │   └── libkctsb_bundled.a  # ★ 打包库（含所有依赖）★
│   │   └── include/kctsb_api.h # 唯一公共头文件
│   └── cuda-win-x64/           # ★ CUDA GPU 加速库 (Windows x64) ★
│       ├── bin/                # CUDA 测试和 benchmark 工具
│       ├── lib/kctsb_cuda.lib  # CUDA 静态库
│       ├── include/cuda_api.h  # CUDA API 头文件
│       └── README.md           # CUDA 库使用文档
├── docs/                       # 文档
│   ├── releases/               # 版本发布说明
│   └── third-party-dependencies.md  # 源码安装指南
├── scripts/                    # 构建脚本
└── cmake/                      # CMake 模块
```



## 🚀 快速开始

### 系统要求

- **CMake**: 3.20 或更高版本
- **构建工具**: Ninja (推荐)
- **编译器**:
  - Windows: MinGW-w64 GCC 13+
  - Linux: GCC 12+
  - macOS:  GCC 12+
- **C++ 标准**: C++17
- **C 标准**: C11

### Windows 构建 (推荐 Ninja)

```powershell
# 进入项目目录
cd D:\pyproject\kctsb

# 配置 (使用Ninja构建)
cmake -B build -G Ninja `
    -DCMAKE_BUILD_TYPE=Release `
    -DKCTSB_BUILD_CLI=ON `
    -DKCTSB_BUILD_TESTS=ON

# 构建
cmake --build build-release --parallel
#或者
ninja.exe -C build-release -j8 2>&1

#或直接一句话：
$env:PATH="C:\msys64\mingw64\bin;$env:PATH"; cmake -B build-release -G Ninja -DCMAKE_BUILD_TYPE=Release -DKCTSB_BUILD_BENCHMARKS=ON
$env:PATH="C:\msys64\mingw64\bin;$env:PATH"; cmake --build build-release --parallel; .\build-release\bin\kctsb_benchmark.exe aes
```

# 运行测试
$env:PATH="C:\msys64\mingw64\bin;$env:PATH"; ctest --test-dir build --output-on-failure
$env:PATH="C:\msys64\mingw64\bin;$env:PATH"; ctest --test-dir build-release --output-on-failure

# 使用CLI工具
```shell
.\build-release\bin\kctsb.exe version
.\build-release\bin\kctsb.exe hash --sha3-256 "Hello, World!"
```

**Windows 环境变量统一（MSYS2）**

为避免多套编译器/`cmake` 冲突，建议在系统环境中固定以下变量，并重启终端生效：

- `MSYS2_ROOT = C:\msys64`
- `MSYS2_MINGW64_BIN = C:\msys64\mingw64\bin`
- `CC = C:\msys64\mingw64\bin\gcc.exe`
- `CXX = C:\msys64\mingw64\bin\g++.exe`
- `CMAKE_MAKE_PROGRAM = C:\msys64\mingw64\bin\ninja.exe`
- `VCPKG_ROOT = D:\vcpkg`

确保 `PATH` 以 `C:\msys64\mingw64\bin;C:\msys64\usr\bin` 开头。

### 构建脚本选项

```powershell
# 快速构建 + 单元/集成测试（推荐日常使用，约1分钟）
.\scripts\build.ps1 -All

# 完整构建 + 所有测试 + OpenSSL对比基准测试
.\scripts\build.ps1 -Full

# 仅构建，不运行测试
.\scripts\build.ps1 -Clean

# 按标签运行测试
ctest -L unit --test-dir build           # 仅单元测试
ctest -L integration --test-dir build    # 仅集成测试
ctest -L performance --test-dir build    # 仅性能测试
```

### Linux Docker 构建 (CentOS 7, glibc 2.17)

使用 Docker 在 CentOS 7 环境下构建，确保最大的 Linux 兼容性：

```bash
# 在 WSL2 或原生 Linux 下执行
cd /path/to/kctsb
./scripts/docker_build.sh

# 构建产物位于 release/linux-x64/
ls -la release/linux-x64/bin/     # CLI 工具: kctsb
ls -la release/linux-x64/lib/     # 静态库: libkctsb.a (1.4 MB)
ls -la release/linux-x64/include/ # 头文件
```

**Docker 构建特性**:
- 基于 CentOS 7 + devtoolset-11 (GCC 11.2.1)
- glibc 2.17 兼容性（支持 RHEL 7+, Ubuntu 18.04+, Debian 9+）
- CMake 3.28.3, NTL 11.6.0, GMP 6.3.0 内置
- 自动生成平台特定命名: `kctsb-linux-x64`, `libkctsb-linux-x64.a`

### Linux/macOS 原生构建

```bash
# 1. 克隆项目
cd /path/to/kctsb

# 2. 使用构建脚本
./scripts/build.sh --test

# 或手动构建
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel $(nproc)

# 3. 运行测试
cd build && ctest --output-on-failure

# 4. 运行示例
./build/bin/kctsb_demo
```

### VS Code 集成

1. 打开 `kctsb` 目录作为工作区
2. 安装推荐扩展：C/C++, CMake Tools
3. 使用 `Ctrl+Shift+B` 构建
4. 使用 `F5` 调试

## 📖 使用示例

### Secure Computation Demo (Headless)

`docs/examples/psi/SecureComputationDemo.py` 仅生成 HTML 报告与日志输出，不会弹出图形窗口或生成图像文件。


**Release 包内容**
```
release/
├── linux-x64/
│   ├── bin/kctsb                    # CLI 工具 (1.5 MB, 全静态链接)
│   ├── lib/
│   │   ├── libkctsb.a               # 静态库 (4.7 MB, 需链接 NTL/GMP 等)
│   │   └── libkctsb_bundled.a       # ★ 打包库 (13 MB, 包含所有依赖) ★
│   └── include/kctsb_api.h          # 唯一公共头文件
│
├── win-x64/
│   ├── bin/kctsb.exe                # CLI 工具 (3.3 MB, 仅需Windows系统DLL)
│   ├── lib/
│   │   ├── libkctsb.a               # 静态库 (4.7 MB)
│   │   └── libkctsb_bundled.a       # ★ 打包库 (6.2 MB) ★
│   └── include/kctsb_api.h          # 唯一公共头文件
│
├── macos-x64/                       # ★ macOS 动态库版本 (v5.0.0) ★
│   ├── bin/kctsb                    # CLI 工具 (74 KB)
│   ├── lib/
│   │   ├── libkctsb.5.0.0.dylib     # 共享库 (1.5 MB, 自包含)
│   │   ├── libkctsb.5.dylib         # 版本符号链接
│   │   └── libkctsb.dylib           # 通用符号链接
│   ├── include/kctsb_api.h          # 唯一公共头文件
│   ├── README.md                    # macOS 使用指南
│   └── RELEASE_INFO.txt             # 详细构建信息
│
└── cuda-win-x64/                    # ★ CUDA GPU 加速库 (v4.14.0+) ★
    ├── bin/                         # CUDA 测试和 benchmark 工具
    │   ├── test_cuda_runtime.exe    # CUDA 环境验证
    │   ├── test_modular_ops.exe     # 模算术正确性测试
    │   └── benchmark_ntt_final.exe  # NTT 性能基准测试
    ├── lib/kctsb_cuda.lib           # CUDA 静态库
    ├── include/cuda_api.h           # CUDA API 头文件
    └── README.md                    # 使用文档 (环境要求/集成示例/性能基线)
```


### 集成示例 (推荐: Bundled 库)

**Linux (GCC)**:
```bash
# 方法1: 使用 bundled 库（推荐，单文件链接）
g++ -O3 myapp.cpp -I./include -L./lib -lkctsb_bundled -lz -lpthread -ldl -o myapp

# 方法2: 使用标准库（需要链接所有依赖）
g++ -O3 myapp.cpp -I./include -L./lib \
    -lkctsb -lntl -lgmp -lgf2x -lseal-4.1 -lhelib \
    -lz -lpthread -o myapp
```

**Windows (MinGW-w64)**:
```powershell
# 方法1: 使用 bundled 库（推荐）
g++ -O3 myapp.cpp -I.\include -L.\lib -lkctsb_bundled -lbcrypt -lws2_32 -o myapp.exe

# 方法2: 标准库
g++ -O3 myapp.cpp -I.\include -L.\lib `
    -lkctsb -lntl -lgmp -lgf2x -lseal-4.1 -lhelib `
    -lbcrypt -lws2_32 -o myapp.exe
```

**macOS (Clang)**:
```bash
# 使用动态库（v5.0.0 自包含）
clang++ -std=c++17 myapp.cpp -I./include -L./lib -lkctsb -o myapp

# 方法1: 使用 DYLD_LIBRARY_PATH
export DYLD_LIBRARY_PATH=/path/to/release/macos-x64/lib:$DYLD_LIBRARY_PATH
./myapp

# 方法2: 使用 install_name_tool（推荐分发）
install_name_tool -change @rpath/libkctsb.5.dylib \
  /absolute/path/to/lib/libkctsb.5.dylib myapp
./myapp

# 详见 release/macos-x64/README.md
```

**CMake 项目集成**:
```cmake
# Linux/Windows - 使用 bundled 库（推荐）
add_executable(myapp main.cpp)
target_include_directories(myapp PRIVATE ${KCTSB_DIR}/include)
target_link_libraries(myapp PRIVATE
    ${KCTSB_DIR}/lib/libkctsb_bundled.a
    ZLIB::ZLIB
    Threads::Threads
    ${CMAKE_DL_LIBS}
)
if(WIN32)
    target_link_libraries(myapp PRIVATE bcrypt ws2_32)
endif()

# macOS - 使用动态库
if(APPLE)
    find_library(KCTSB_LIB kctsb PATHS ${KCTSB_DIR}/lib)
    target_link_libraries(myapp PRIVATE ${KCTSB_LIB})
    # 设置 rpath
    set_target_properties(myapp PROPERTIES
        BUILD_RPATH "${KCTSB_DIR}/lib"
        INSTALL_RPATH "@executable_path/../lib"
    )
endif()
```

## CMake 选项

| 选项 | 默认值 | 说明 |
|------|--------|------|
| `KCTSB_BUILD_SHARED` | ON | 构建共享库 |
| `KCTSB_BUILD_STATIC` | ON | 构建静态库 |
| `KCTSB_BUILD_TESTS` | ON | 构建测试 |
| `KCTSB_BUILD_EXAMPLES` | ON | 构建示例 |
| `KCTSB_BUILD_BENCHMARKS` | ON | 构建性能对比测试 |
| `KCTSB_ENABLE_NTL` | **ON** | 使用NTL库 (ECC/RSA/格密码) |
| `KCTSB_ENABLE_GMP` | **ON** | 使用GMP库 (高精度运算) |
| `KCTSB_ENABLE_OPENSSL` | **ON** | 使用OpenSSL (性能对比) |
| `KCTSB_ENABLE_SEAL` | **ON** | 使用Microsoft SEAL (同态加密) |
| `KCTSB_ENABLE_HELIB` | **ON** | 使用HElib (函数加密) |

```powershell
ninja.exe -C build -j8 2>&1
```

### 🚀 CUDA GPU 加速构建 (v4.14.0+)

CUDA 库采用**独立构建系统**，因为 Windows 上 CUDA 需要 MSVC 编译器，而主库需要 GCC（支持 `__int128`）。

**系统要求**:
- CUDA Toolkit 11.0+ (推荐 12.x)
- MSVC 2019+ (Visual Studio)
- NVIDIA GPU (推荐 SM 8.0+，如 RTX 30/40 系列)

**构建步骤 (PowerShell)**:

```powershell
# 1. 进入 kctsb 目录
cd D:\pyproject\kctsb

# 2. 设置 CUDA 路径
$env:CUDA_PATH = "D:\cuda125"  # 根据实际 CUDA 安装路径修改

# 3. 配置 CUDA 独立项目 (需要 VS Developer 环境)
# 打开 x64 Native Tools Command Prompt for VS 2022，或运行:
cmd.exe /c '"D:\vsstudio2022\VC\Auxiliary\Build\vcvarsall.bat" x64 && cmake -B build-cuda -S src/advanced/psi/cuda -G Ninja -DCMAKE_BUILD_TYPE=Release'

# 4. 构建 CUDA 库和测试
cmd.exe /c '"D:\vsstudio2022\VC\Auxiliary\Build\vcvarsall.bat" x64 && cmake --build build-cuda --parallel'

# 5. 运行 CUDA 测试
.\build-cuda\test_cuda_runtime.exe       # 验证 CUDA 环境
.\build-cuda\test_modular_ops.exe        # 验证模算术正确性
.\build-cuda\benchmark_ntt_final.exe     # 运行 NTT 性能基准测试
```

**CUDA Benchmark 结果 (RTX 4060 Laptop, CUDA 12.5)**:

| 操作 | 数据规模 n | CPU (ms) | GPU (ms) | 加速比 | 正确性 |
|------|------------|----------|----------|--------|--------|
| NTT | 1,024 | 0.017 | 0.085 | 0.20x | ✅ |
| NTT | 16,384 | 0.410 | 0.166 | **2.47x** | ✅ |
| NTT | 65,536 | 1.630 | 0.241 | **6.77x** | ✅ |
| NTT | 262,144 | 10.40 | 0.517 | **20.11x** | ✅ |
| NTT | 1,048,576 | 76.21 | 1.478 | **51.56x** | ✅ |
| PolyMul | 65,536 | 0.065 | 0.009 | **7.17x** | ✅ |
| PolyMul | 1,048,576 | 1.328 | 0.036 | **36.95x** | ✅ |

**使用建议**:
- n < 4,096: 使用 CPU（GPU 内核启动开销大于计算时间）
- n ≥ 16,384: 推荐使用 GPU（明显加速）
- n ≥ 262,144: 强烈推荐 GPU（20x+ 加速）

**产物位置**:
- `build-cuda/kctsb_cuda.lib` - CUDA 静态库
- `build-cuda/benchmark_ntt_final.exe` - 性能测试工具


## 📚 API 文档

### 统一公共 API

从 v3.4.0 开始，所有公共 API 都集中在单个头文件中：

- **[kctsb_api.h](include/kctsb/kctsb_api.h)** - 唯一公共头文件 (推荐)
  - 包含所有算法的公共 API
  - 平台检测和导出宏
  - 错误码定义
  - 可选的 C++ 命名空间

### 内部头文件 (仅供库内部使用)

以下头文件供库开发维护使用，外部用户无需关心：

- [core/common.h](include/kctsb/core/common.h) - 错误码和通用定义
- [crypto/aes.h](include/kctsb/crypto/aes.h) - AES 加密实现
- [crypto/sha256.h](include/kctsb/crypto/sha256.h) - SHA-256 实现
- [crypto/sha3.h](include/kctsb/crypto/sha3.h) - SHA3 实现
- [crypto/blake2.h](include/kctsb/crypto/blake2.h) - BLAKE2 实现
- [crypto/chacha20_poly1305.h](include/kctsb/crypto/chacha20_poly1305.h) - ChaCha20-Poly1305 实现
- [gm/sm3.h](include/kctsb/gm/sm3.h) - SM3 国密哈希
- [gm/sm4.h](include/kctsb/gm/sm4.h) - SM4 国密对称加密



## 🔒 变更策略

本项目仅允许核心维护者进行代码变更，外部或非授权修改不予接受。

### 开源协议

本项目采用 **Apache License 2.0**，允许商业使用、修改和分发。

## 📄 许可证

本项目采用 Apache License 2.0 许可证 - 详见 [LICENSE](LICENSE) 文件。

## 👤 作者

**knightc** (owner: tsb)

Copyright © 2019-2026 knightc. All rights reserved.

## 🔗 参考资料

### 标准文档
- [FIPS 180-4 (SHA-256/384/512)](https://csrc.nist.gov/publications/detail/fips/180/4/final)
- [FIPS 197 (AES)](https://csrc.nist.gov/publications/detail/fips/197/final)
- [FIPS 202 (SHA-3)](https://csrc.nist.gov/publications/detail/fips/202/final)
- [RFC 7539 (ChaCha20-Poly1305)](https://tools.ietf.org/html/rfc7539)
- [RFC 7693 (BLAKE2b)](https://tools.ietf.org/html/rfc7693)
- GM/T 0002-2012 (SM4), GM/T 0003-2012 (SM2), GM/T 0004-2012 (SM3)

### 依赖库
- [GMP: The GNU Multiple Precision Arithmetic Library](https://gmplib.org/)
