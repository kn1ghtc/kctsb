# kctsb CUDA GPU Acceleration Library

**Version**: v5.0.0  
**Platform**: Windows x64  
**CUDA Requirement**: CUDA Toolkit 11.0+ (推荐 12.x)  
**GPU Requirement**: NVIDIA GPU with SM 8.0+ (RTX 30/40 系列)

## 📦 包内容

```
cuda-win-x64/
├── lib/
│   └── kctsb_cuda.lib          # CUDA 静态库
├── bin/
│   ├── test_cuda_runtime.exe   # CUDA 环境验证工具
│   ├── test_modular_ops.exe    # 模算术正确性测试
│   └── benchmark_ntt_final.exe # NTT 性能基准测试
├── include/
│   └── cuda_api.h              # CUDA API 公共头文件
└── README.md                   # 本文档
```

## 🚀 快速开始

### 1. 验证 CUDA 环境

```powershell
.\bin\test_cuda_runtime.exe
```

**预期输出**:
```
CUDA Device Count: 1
Device 0: NVIDIA GeForce RTX 4060 Laptop GPU
  Compute Capability: 8.9
  Total Memory: 8188 MB
```

### 2. 运行性能测试

```powershell
.\bin\benchmark_ntt_final.exe
```

### 3. 集成到你的项目

**CMake 项目**:
```cmake
# 设置 CUDA 路径
set(CUDA_TOOLKIT_ROOT_DIR "D:/cuda125")  # 根据实际修改

# 链接 kctsb CUDA 库
add_executable(myapp main.cpp)
target_include_directories(myapp PRIVATE 
    ${KCTSB_CUDA_DIR}/include
)
target_link_libraries(myapp PRIVATE
    ${KCTSB_CUDA_DIR}/lib/kctsb_cuda.lib
    ${CUDA_TOOLKIT_ROOT_DIR}/lib/x64/cudart_static.lib
)
```

**Visual Studio 项目**:
1. 项目属性 → C/C++ → 附加包含目录：添加 `cuda_api.h` 所在目录
2. 链接器 → 附加库目录：添加 `lib/` 目录
3. 链接器 → 输入 → 附加依赖项：添加 `kctsb_cuda.lib; cudart_static.lib`

## 📊 性能基线

**RTX 4060 Laptop GPU + CUDA 12.5**

| 操作 | 数据规模 n | CPU (ms) | GPU (ms) | 加速比 | 正确性 |
|------|-----------|----------|----------|--------|--------|
| NTT | 65,536 | 1.630 | 0.241 | **6.77x** | ✅ |
| NTT | 262,144 | 10.40 | 0.517 | **20.11x** | ✅ |
| NTT | 1,048,576 | 76.21 | 1.478 | **51.56x** | ✅ |
| PolyMul | 65,536 | 0.065 | 0.009 | **7.17x** | ✅ |
| PolyMul | 1,048,576 | 1.328 | 0.036 | **36.95x** | ✅ |

## 💡 使用建议

- **n < 4,096**: 使用 CPU（GPU 内核启动开销大于计算时间）
- **n ≥ 16,384**: 推荐使用 GPU（明显加速）
- **n ≥ 262,144**: 强烈推荐 GPU（20x+ 加速）

## 🔧 环境要求

1. **CUDA Toolkit**: 下载地址 https://developer.nvidia.com/cuda-downloads
2. **NVIDIA Driver**: 支持 CUDA 12.x 的驱动程序
3. **Visual Studio**: 2019+ (含 MSVC v142+)

## 📝 API 示例

```cpp
#include "cuda_api.h"
#include <iostream>

int main() {
    // 初始化 CUDA
    kctsb_cuda_init();
    
    // 检查 GPU 设备
    int device_count = kctsb_cuda_get_device_count();
    std::cout << "CUDA Devices: " << device_count << std::endl;
    
    // 执行 NTT 计算
    const size_t n = 65536;
    uint64_t* data = new uint64_t[n];
    // ... 填充数据 ...
    
    kctsb_cuda_ntt(data, n, modulus);
    
    // 清理
    delete[] data;
    kctsb_cuda_cleanup();
    
    return 0;
}
```

## 🐛 故障排查

**问题**: "找不到 cudart64_12.dll"  
**解决**: 将 `%CUDA_PATH%\bin` 添加到系统 PATH 环境变量

**问题**: "no CUDA-capable device is detected"  
**解决**: 确认安装了 NVIDIA 驱动程序，运行 `nvidia-smi` 验证

**问题**: 性能不如预期  
**解决**: 检查是否启用了 GPU 加速模式，关闭节能模式

## 📄 许可证

Apache License 2.0

## 👤 作者

**knightc** (kctsb project)  
Copyright © 2019-2026 knightc. All rights reserved.
