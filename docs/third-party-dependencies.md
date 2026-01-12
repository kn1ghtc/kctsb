# 第三方依赖安装与编译指南

**文档版本**: 1.0.0  
**更新日期**: 2026-01-12 (UTC+8)  
**适用版本**: kctsb v3.0.0+

---

## 目录

1. [概述](#概述)
2. [依赖总览](#依赖总览)
3. [NTL 源码编译安装](#ntl-源码编译安装)
4. [vcpkg 依赖安装](#vcpkg-依赖安装)
5. [OpenSSL 安装](#openssl-安装)
6. [Microsoft SEAL 安装](#microsoft-seal-安装)
7. [依赖升级指南](#依赖升级指南)
8. [故障排除](#故障排除)

---

## 概述

kctsb 密码学库支持多种可选依赖，用于增强性能和扩展功能：

- **NTL (Number Theory Library)**: 大整数运算、多项式运算、有限域运算
- **GMP (GNU Multiple Precision)**: 高性能任意精度算术
- **OpenSSL**: 性能基准对比测试
- **Microsoft SEAL**: 同态加密支持

### 依赖策略

| 依赖 | 安装方式 | 必需性 | 用途 | 状态 |
|------|----------|--------|------|------|
| NTL | **源码编译** | 推荐 | ECC/RSA加速、数论运算 | ⚠️ 头文件存在，需编译库 |
| GMP | Strawberry Perl | 推荐 | NTL依赖、大整数运算 | ✅ 已安装 |
| OpenSSL | vcpkg | 可选 | 性能对比测试 | ✅ 已安装 (3.6.0) |
| SEAL | vcpkg | 可选 | 同态加密 | ✅ 已安装 (4.1.2) |

---

## 依赖总览

### 版本要求

| 依赖 | 最低版本 | 推荐版本 | 备注 |
|------|----------|----------|------|
| NTL | 11.5.0 | **11.6.0** | 最新稳定版 |
| GMP | 6.2.0 | 6.3.0 | NTL 依赖 |
| OpenSSL | 3.0.0 | 3.2.0 | 仅用于测试对比 |
| SEAL | 4.0.0 | 4.1.2 | 可选 |

### 目录结构

建议将第三方库安装到统一目录：

```
d:\pyproject\kctsb\
├── deps/                    # 第三方依赖目录
│   ├── ntl/                 # NTL 安装目录
│   │   ├── include/NTL/     # NTL 头文件
│   │   └── lib/             # NTL 库文件
│   ├── gmp/                 # GMP (vcpkg 自动管理)
│   └── openssl/             # OpenSSL (vcpkg 自动管理)
└── vcpkg/                   # vcpkg 安装目录
```

---

## NTL 源码编译安装

NTL (Number Theory Library) 提供高性能数论运算，是 ECC 和 RSA 算法的核心依赖。

### 为什么源码编译？

1. **性能优化**: 源码编译可针对本机 CPU 指令集优化
2. **GMP 集成**: 与 GMP 配合获得最佳性能
3. **配置灵活**: 可自定义编译选项

### Windows 编译方法

#### 方法一：MinGW/MSYS2 编译（推荐）

```powershell
# 1. 安装 MSYS2 (如果尚未安装)
# 下载: https://www.msys2.org/
# 安装后打开 MSYS2 MinGW 64-bit 终端

# 2. 安装编译工具
pacman -S mingw-w64-x86_64-gcc mingw-w64-x86_64-gmp mingw-w64-x86_64-make

# 3. 下载 NTL 源码
cd /d/pyproject/kctsb
mkdir -p deps && cd deps
wget https://libntl.org/ntl-11.6.0.tar.gz
tar -xzf ntl-11.6.0.tar.gz
cd ntl-11.6.0/src

# 4. 配置编译
./configure PREFIX=/d/pyproject/kctsb/deps/ntl \
            GMP_PREFIX=/mingw64 \
            SHARED=on \
            NTL_THREADS=on \
            NTL_THREAD_BOOST=on \
            NTL_STD_CXX14=on \
            TUNE=x86

# 5. 编译
make -j8

# 6. 测试
make check

# 7. 安装
make install
```

#### 方法二：Cygwin 编译

```bash
# 1. 安装 Cygwin 及开发包
# 选择: gcc-g++, make, libgmp-devel, wget

# 2. 在 Cygwin 终端中
cd /cygdrive/d/pyproject/kctsb/deps
wget https://libntl.org/ntl-11.6.0.tar.gz
tar -xzf ntl-11.6.0.tar.gz
cd ntl-11.6.0/src

# 3. 配置并编译
./configure PREFIX=/cygdrive/d/pyproject/kctsb/deps/ntl
make -j8
make check
make install
```

#### 方法三：Visual Studio 编译

```powershell
# 1. 下载 WinNTL
# https://libntl.org/download.html -> WinNTL-11.6.0.zip

# 2. 解压到 d:\pyproject\kctsb\deps\WinNTL-11.6.0

# 3. 打开 Visual Studio Developer Command Prompt

# 4. 编译所有源文件
cd d:\pyproject\kctsb\deps\WinNTL-11.6.0\src
for %f in (*.cpp) do cl /c /O2 /EHsc /I..\include %f

# 5. 创建静态库
lib /OUT:ntl.lib *.obj

# 6. 复制文件到安装目录
mkdir d:\pyproject\kctsb\deps\ntl\lib
mkdir d:\pyproject\kctsb\deps\ntl\include
copy ntl.lib d:\pyproject\kctsb\deps\ntl\lib\
xcopy /E ..\include\NTL d:\pyproject\kctsb\deps\ntl\include\NTL\
```

### 配置选项说明

| 选项 | 说明 | 推荐值 |
|------|------|--------|
| `PREFIX` | 安装路径 | 项目 deps 目录 |
| `GMP_PREFIX` | GMP 安装路径 | vcpkg 或系统路径 |
| `SHARED` | 构建共享库 | on |
| `NTL_THREADS` | 多线程支持 | on |
| `NTL_THREAD_BOOST` | 线程加速 | on |
| `NTL_STD_CXX14` | C++14 标准 | on |
| `TUNE` | 性能调优 | x86/generic |

### 验证安装

```cpp
// test_ntl.cpp
#include <NTL/ZZ.h>
#include <iostream>

int main() {
    NTL::ZZ a, b, c;
    a = NTL::conv<NTL::ZZ>("12345678901234567890");
    b = NTL::conv<NTL::ZZ>("98765432109876543210");
    c = a * b;
    std::cout << "NTL test: " << c << std::endl;
    return 0;
}
```

```powershell
# MinGW 编译测试
g++ -o test_ntl test_ntl.cpp -I d:\pyproject\kctsb\deps\ntl\include \
    -L d:\pyproject\kctsb\deps\ntl\lib -lntl -lgmp
.\test_ntl.exe
```

---

## vcpkg 依赖安装

### vcpkg 初始化

vcpkg 已统一安装到 `D:\vcpkg`，环境变量 `VCPKG_ROOT` 已配置。

```powershell
# 确认环境变量
$env:VCPKG_ROOT   # 应输出 D:\vcpkg

# 更新 vcpkg (可选)
cd D:\vcpkg
git pull
.\bootstrap-vcpkg.bat
```

### 安装依赖

```powershell
# 使用环境变量定位 vcpkg
cd $env:VCPKG_ROOT

# OpenSSL - 性能对比测试 (已安装: 3.6.0)
.\vcpkg install openssl:x64-windows

# Microsoft SEAL - 同态加密 (已安装: 4.1.2)
.\vcpkg install seal:x64-windows

# 一次性安装所有推荐依赖
.\vcpkg install openssl:x64-windows seal:x64-windows zlib:x64-windows zstd:x64-windows
```

### GMP (已安装)

GMP 库已通过 Strawberry Perl 安装，CMake 会自动检测：

| 组件 | 路径 |
|------|------|
| 头文件 | `C:\Strawberry\c\include\gmp.h` |
| 库文件 | `C:\Strawberry\c\lib\libgmp.a` (953 KB) |

CMake FindGMP.cmake 模块已配置自动检测 Strawberry 路径。

**注意**: vcpkg 的 GMP 包在 Windows 下编译常失败，建议使用 Strawberry 自带版本。

### vcpkg 与 CMake 集成

```powershell
# 配置项目时指定 vcpkg 工具链 (使用环境变量)
cmake -B build -G "MinGW Makefiles" `
    -DCMAKE_TOOLCHAIN_FILE="$env:VCPKG_ROOT\scripts\buildsystems\vcpkg.cmake" `
    -DCMAKE_BUILD_TYPE=Release `
    -DKCTSB_ENABLE_NTL=ON `
    -DKCTSB_ENABLE_GMP=ON `
    -DKCTSB_ENABLE_OPENSSL=ON `
    -DKCTSB_BUILD_BENCHMARKS=ON
```

### 已安装包查看

```powershell
# 使用环境变量
& "$env:VCPKG_ROOT\vcpkg.exe" list

# 当前已安装包 (2026-01-12):
# - openssl:x64-windows     3.6.0
# - seal:x64-windows        4.1.2 (ms-gsl, zlib, zstd)
# - zlib:x64-windows        1.3.1
# - zstd:x64-windows        1.5.7
```

---

## OpenSSL 安装

OpenSSL 用于性能基准对比测试，验证 kctsb 算法实现的效率。

### vcpkg 安装（推荐）

```powershell
cd d:\pyproject\kctsb\vcpkg
.\vcpkg install openssl:x64-windows
```

### 预编译二进制安装

1. 下载: https://slproweb.com/products/Win32OpenSSL.html
2. 选择 `Win64 OpenSSL v3.x.x` 完整版
3. 安装到 `d:\pyproject\kctsb\deps\openssl`

### CMake 查找配置

```cmake
# 在 CMakeLists.txt 中
find_package(OpenSSL REQUIRED)
target_link_libraries(your_target PRIVATE OpenSSL::SSL OpenSSL::Crypto)
```

---

## Microsoft SEAL 安装

SEAL 用于同态加密功能。

### vcpkg 安装

```powershell
.\vcpkg install seal:x64-windows
```

### 源码编译

```powershell
cd d:\pyproject\kctsb\deps
git clone https://github.com/microsoft/SEAL.git
cd SEAL
cmake -B build -DSEAL_BUILD_EXAMPLES=OFF -DSEAL_BUILD_TESTS=OFF
cmake --build build --config Release
cmake --install build --prefix d:\pyproject\kctsb\deps\seal
```

---

## 依赖升级指南

### NTL 升级

```bash
# 1. 下载新版本
cd /d/pyproject/kctsb/deps
wget https://libntl.org/ntl-NEW_VERSION.tar.gz

# 2. 备份旧版本
mv ntl ntl-old

# 3. 解压并编译新版本
tar -xzf ntl-NEW_VERSION.tar.gz
cd ntl-NEW_VERSION/src
./configure PREFIX=/d/pyproject/kctsb/deps/ntl [OPTIONS]
make -j8
make check
make install

# 4. 验证新版本工作正常后删除备份
rm -rf ntl-old
```

### vcpkg 依赖升级

```powershell
cd d:\pyproject\kctsb\vcpkg

# 更新 vcpkg 本身
git pull
.\bootstrap-vcpkg.bat

# 升级所有包
.\vcpkg upgrade --no-dry-run

# 或升级特定包
.\vcpkg upgrade gmp:x64-windows --no-dry-run
```

---

## 故障排除

### NTL 编译问题

**问题**: `gmp.h not found`
```bash
# 解决: 指定 GMP 路径
./configure GMP_PREFIX=/path/to/gmp
```

**问题**: `undefined reference to GMP functions`
```bash
# 解决: 确保链接 GMP 库
g++ -o program program.cpp -lntl -lgmp
```

### vcpkg 问题

**问题**: 包安装失败
```powershell
# 清理并重试
.\vcpkg remove gmp:x64-windows
.\vcpkg install gmp:x64-windows --clean-after-build
```

**问题**: CMake 找不到包
```powershell
# 确保使用 vcpkg 工具链
cmake -DCMAKE_TOOLCHAIN_FILE="path/to/vcpkg/scripts/buildsystems/vcpkg.cmake" ..
```

### 链接问题

**问题**: 运行时找不到 DLL
```powershell
# 解决: 复制 DLL 到可执行文件目录或添加到 PATH
$env:PATH += ";d:\pyproject\kctsb\vcpkg\installed\x64-windows\bin"
```

---

## 参考资源

- [NTL 官方文档](https://libntl.org/doc/tour.html)
- [NTL GitHub](https://github.com/libntl/ntl)
- [GMP 官网](https://gmplib.org/)
- [vcpkg 文档](https://vcpkg.io/en/docs/README.html)
- [OpenSSL 文档](https://www.openssl.org/docs/)
- [Microsoft SEAL](https://github.com/microsoft/SEAL)

---

**维护者**: knightc  
**许可证**: Apache-2.0
