# AGENTS.md - kctsb AI Development Guidelines

> **项目**: kctsb - C/C++ 可信安全算法库
> **版本**: 1.0.0
> **更新时间**: 2025-01-17

---

## 🎯 项目概述

kctsb (Knight's Cryptographic Trusted Security Base) 是一个跨平台的C/C++密码学和安全算法库，专为安全研究和教育用途设计。

### 核心设计原则

1. **跨平台兼容**: 支持 Windows/Linux/macOS
2. **双语言接口**: 提供纯C和C++两套API
3. **教育优先**: 算法实现注重可读性和教学价值
4. **安全研究导向**: 面向专业密码学研究人员

---

## 📁 目录结构

```
kctsb/
├── CMakeLists.txt          # 主构建配置
├── include/                # 公共头文件
│   └── kctsb/
│       ├── kctsb.h         # 主入口头文件
│       ├── core/           # 核心定义
│       ├── crypto/         # 标准密码算法
│       ├── advanced/       # 高级密码学
│       ├── math/           # 数学工具
│       └── utils/          # 实用工具
├── src/                    # 源代码实现
│   ├── core/               # 核心功能实现
│   ├── crypto/             # 密码算法实现
│   ├── advanced/           # 高级算法实现
│   ├── math/               # 数学库实现
│   └── utils/              # 工具函数实现
├── tests/                  # 测试代码
│   ├── unit/               # 单元测试
│   └── integration/        # 集成测试
├── examples/               # 示例代码
├── scripts/                # 构建脚本
├── cmake/                  # CMake模块
└── docs/                   # 文档
```

---

## 🔧 开发约束

### 代码风格

1. **命名规范**
   - C函数: `kctsb_<module>_<action>()` 格式
   - C++类: `PascalCase` 命名
   - 私有成员: `m_` 前缀
   - 常量: `KCTSB_<NAME>` 大写

2. **头文件结构**
   ```c
   #ifndef KCTSB_<MODULE>_<NAME>_H
   #define KCTSB_<MODULE>_<NAME>_H

   #include "kctsb/core/common.h"

   #ifdef __cplusplus
   extern "C" {
   #endif

   // C API declarations

   #ifdef __cplusplus
   } // extern "C"

   namespace kctsb {
   // C++ API declarations
   } // namespace kctsb
   #endif

   #endif // KCTSB_<MODULE>_<NAME>_H
   ```

3. **文档注释**
   - 每个公共函数必须有Doxygen注释
   - 参数和返回值必须详细说明
   - 安全注意事项必须标注

### 构建要求

1. **CMake 最低版本**: 3.20
2. **C++ 标准**: C++17
3. **C 标准**: C11
4. **编译器支持**: GCC 9+, Clang 10+, MSVC 2019+

### 依赖管理

- **必需依赖**: 无 (核心库纯C/C++实现)
- **可选依赖**:
  - NTL: 数论库
  - GMP: 大整数运算
  - OpenSSL: 对比测试
  - SEAL: 同态加密
  - HElib: 同态加密

### 测试要求

1. 使用 GoogleTest 框架
2. 每个算法至少包含:
   - 标准测试向量验证
   - 边界条件测试
   - 性能基准测试
3. 代码覆盖率目标: 80%+

---

## 📋 算法模块说明

### crypto/ - 标准密码算法

| 模块 | 功能 | 实现状态 |
|------|------|----------|
| aes.h | AES-128/192/256 加密 | ✅ 完成 |
| sha.h | SHA-1/256/384/512 哈希 | 🔄 进行中 |
| sm2.h | 国密SM2椭圆曲线 | 📋 计划中 |
| sm3.h | 国密SM3哈希 | 📋 计划中 |
| sm4.h | 国密SM4分组密码 | 📋 计划中 |
| rsa.h | RSA加密签名 | 📋 计划中 |
| ecc.h | 椭圆曲线密码 | 📋 计划中 |

### advanced/ - 高级密码学

| 模块 | 功能 | 实现状态 |
|------|------|----------|
| whitebox.h | 白盒AES/SM4 | 📋 计划中 |
| sss.h | Shamir秘密共享 | 📋 计划中 |
| zk.h | 零知识证明 | 📋 计划中 |
| lattice.h | 格密码 | 📋 计划中 |

---

## 🚀 构建命令

### Windows (PowerShell)

```powershell
# 配置并构建
cmake -B build -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel

# 运行测试
cd build; ctest --output-on-failure

# 使用构建脚本
.\scripts\build.ps1 -BuildType Release -Test
```

### Linux/macOS

```bash
# 配置并构建
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel $(nproc)

# 运行测试
cd build && ctest --output-on-failure

# 使用构建脚本
./scripts/build.sh --test
```

---

## ⚠️ 安全注意事项

1. **教育用途**: 本库主要用于教育和研究，不建议直接用于生产环境
2. **侧信道防护**: 当前实现未考虑时间侧信道攻击防护
3. **内存安全**: 使用 `kctsb_secure_memzero()` 清理敏感数据
4. **随机数**: 使用平台原生CSPRNG（Windows BCrypt, Unix /dev/urandom）

---

## 📝 贡献指南

1. 所有代码变更需通过CI测试
2. 新算法必须附带测试向量
3. 文档更新与代码同步
4. 遵循现有代码风格

---

## 🔗 相关资源

- FIPS 197 (AES): https://csrc.nist.gov/publications/detail/fips/197/final
- FIPS 180-4 (SHA): https://csrc.nist.gov/publications/detail/fips/180/4/final
- GM/T 0002-2012 (SM4)
- GM/T 0003-2012 (SM2)
- GM/T 0004-2012 (SM3)
