# MSYS2 安装指南

**目的**: 为kctsb项目编译SEAL、HElib和GMP C++支持

**日期**: 2026-01-12  
**版本**: MSYS2 2024.01.13+

---

## 📋 安装步骤

### 1. 下载MSYS2安装程序

访问官方网站下载最新版本：
- **官网**: https://www.msys2.org/
- **直接下载**: https://github.com/msys2/msys2-installer/releases/latest/download/msys2-x86_64-latest.exe

**推荐版本**: 2024.01.13或更新

### 2. 运行安装程序

1. 双击 `msys2-x86_64-latest.exe`
2. **重要**: 安装到默认路径 `C:\msys64`（脚本依赖此路径）
3. 完成安装后，勾选 `Run MSYS2 now` 启动终端

### 3. 更新系统包

在MSYS2终端执行：

```bash
# 更新核心包数据库
pacman -Syu
```

**注意**: 如果提示关闭窗口，请关闭后重新打开MSYS2终端，再执行一次：

```bash
pacman -Su
```

### 4. 安装MinGW-w64工具链

```bash
# 安装GCC编译器和构建工具
pacman -S mingw-w64-x86_64-gcc \
          mingw-w64-x86_64-make \
          mingw-w64-x86_64-cmake \
          mingw-w64-x86_64-ninja \
          base-devel \
          git \
          tar \
          unzip
```

确认安装（输入 `Y` 确认）。

### 5. 验证安装

在MSYS2 MinGW64终端（**不是MSYS2 MSYS终端**）执行：

```bash
# 打开MinGW64终端（开始菜单搜索 "MSYS2 MinGW 64-bit"）
gcc --version
cmake --version
make --version
```

**预期输出**:
- GCC: 13.x 或更高
- CMake: 3.27 或更高
- Make: 4.x

### 6. 配置环境变量（可选）

为了让Windows PowerShell可以直接调用MSYS2工具，添加到PATH：

1. 打开 `系统属性` → `高级` → `环境变量`
2. 在 `系统变量` 中找到 `Path`，点击 `编辑`
3. 添加以下路径（按顺序）：
   ```
   C:\msys64\mingw64\bin
   C:\msys64\usr\bin
   ```
4. 点击 `确定` 保存

**验证**: 在新PowerShell窗口执行：
```powershell
gcc --version
```

---

## 🔧 常见问题

### Q1: `pacman -Syu` 卡住不动

**原因**: 镜像源速度慢

**解决**: 更换中国镜像源

编辑 `C:\msys64\etc\pacman.d\mirrorlist.mingw64`，在文件开头添加：

```
Server = https://mirrors.tuna.tsinghua.edu.cn/msys2/mingw/mingw64/
Server = https://mirrors.ustc.edu.cn/msys2/mingw/mingw64/
```

编辑 `C:\msys64\etc\pacman.d\mirrorlist.msys`，添加：

```
Server = https://mirrors.tuna.tsinghua.edu.cn/msys2/msys/$arch/
Server = https://mirrors.ustc.edu.cn/msys2/msys/$arch/
```

然后重新执行 `pacman -Syyu`。

### Q2: 找不到 `gcc` 命令

**原因**: 使用了错误的终端

**解决**: 
- ❌ 不要使用 "MSYS2 MSYS" 终端
- ✅ 使用 "MSYS2 MinGW 64-bit" 终端（紫色图标）

### Q3: CMake找不到编译器

**原因**: PATH环境变量未正确设置

**解决**: 在MSYS2终端执行：
```bash
export PATH=/mingw64/bin:$PATH
```

或在脚本中显式指定工具链文件。

### Q4: 安装后磁盘占用较大

**正常情况**: MSYS2完整安装约占用 2-3 GB

**清理方法**:
```bash
# 清理包缓存
pacman -Scc
```

---

## 📦 后续步骤

MSYS2安装完成后，按顺序执行以下脚本：

### 1. 编译GMP（C++支持）

```powershell
cd D:\pyproject\kctsb
.\scripts\build_gmp.ps1
```

**输出**: `D:\libs\gmp\` (libgmp.a, libgmpxx.a, gmp.h, gmpxx.h)

### 2. 编译Microsoft SEAL

```powershell
.\scripts\build_seal_mingw.ps1
```

**输出**: `D:\libs\seal\` (libseal-4.1.a)

### 3. 编译HElib

```powershell
.\scripts\build_helib.ps1
```

**输出**: `D:\libs\helib\` (libhelib.a)

**预计总时间**: 1.5-2小时（自动化执行）

---

## ✅ 验证清单

安装完成后，确认以下文件存在：

- [x] `C:\msys64\msys2_shell.cmd`
- [x] `C:\msys64\mingw64\bin\gcc.exe`
- [x] `C:\msys64\mingw64\bin\g++.exe`
- [x] `C:\msys64\mingw64\bin\cmake.exe`
- [x] `C:\msys64\mingw64\bin\make.exe`

执行检查脚本：

```powershell
# 在PowerShell中执行
Test-Path "C:\msys64\msys2_shell.cmd"  # 应返回 True
& "C:\msys64\mingw64\bin\gcc.exe" --version  # 应显示GCC版本
```

---

## 📚 参考资料

- **MSYS2官网**: https://www.msys2.org/
- **MSYS2 Wiki**: https://www.msys2.org/wiki/Home/
- **pacman使用指南**: https://www.msys2.org/docs/package-management/
- **清华大学镜像**: https://mirrors.tuna.tsinghua.edu.cn/help/msys2/

---

**作者**: knightc  
**项目**: kctsb v3.0.1  
**更新日期**: 2026-01-12
