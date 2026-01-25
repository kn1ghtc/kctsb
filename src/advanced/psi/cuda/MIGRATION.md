# PSI CUDA 代码迁移通知

**重要**: PSI/PIR 的 CUDA 代码已迁移至统一的 CUDA 目录。

## 新位置

```
kctsb/src/advanced/cuda/
```

## 构建指令

从 kctsb 根目录:

```powershell
# 设置 CUDA 环境
$env:CUDA_PATH = "D:\cuda125"

# 配置 (使用 VS2022 MSVC)
cmd.exe /c '"D:\vsstudio2022\VC\Auxiliary\Build\vcvarsall.bat" x64 && cmake -B build-cuda -S src/advanced/cuda -G Ninja -DCMAKE_BUILD_TYPE=Release'

# 构建
cmd.exe /c '"D:\vsstudio2022\VC\Auxiliary\Build\vcvarsall.bat" x64 && cmake --build build-cuda --parallel'
```

## 包含的功能

- **NTT/INTT**: Harvey 蝴蝶算法，Shoup 预计算
- **FHE 操作**: BGV/BFV/CKKS 密文加法、乘法、重线性化
- **PIR 操作**: 内积计算，批量查询
- **RNS 多项式**: 加法、减法、乘法

## 此目录保留文件

- `pir_cuda_kernels.cu` - 原始 PIR 内核 (参考实现)
- `CMakeLists.txt` - 已弃用，请使用 `src/advanced/cuda/CMakeLists.txt`
