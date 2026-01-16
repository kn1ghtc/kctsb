# kctsb CI/CD & Performance Gateway 规划

**文档日期**: 2026年1月16日（北京时间 UTC+8）  
**版本**: v1.0 - 规划阶段  
**优先级**: v3.5.0 实现  

---

## 🎯 目标

建立持续集成/持续部署（CI/CD）管道和**性能门槛机制**，防止性能回退，确保每个版本都满足基准要求。

---

## 📋 需求分析

### 当前痛点
1. ❌ 无自动化测试流程
2. ❌ 性能基准无版本追踪
3. ❌ PR合并无性能检查
4. ❌ 编译器差异无覆盖（仅MinGW-w64）
5. ❌ 多平台构建无自动化

### 解决方案
✅ GitHub Actions CI流程  
✅ 性能基准自动收集与对比  
✅ PR检查门槛（单元测试 + 性能）  
✅ 多编译器测试（GCC/Clang/MSVC）  
✅ 跨平台构建（Windows/Linux）  

---

## 🏗️ CI/CD 架构

```
┌─────────────────────────────────────────────────────────────┐
│                    GitHub Push Event                         │
│               (Push to main / PR opened)                     │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│              Workflow: Unit Tests + Build                    │
├─────────────────────────────────────────────────────────────┤
│ • Compile (Debug): GCC + Clang + MSVC                       │
│ • Unit Tests: 152 tests pass check                          │
│ • Integration Tests: All pass                               │
│ • Build Time: Record for regression                         │
└─────────────────────────────────────────────────────────────┘
                              │
                ┌─────────────┼─────────────┐
                │ All Pass?   │             │ Failed
                ▼ Yes         │             ▼
         ┌──────────────┐     │      ┌──────────────┐
         │ Continue     │     │      │ Block Merge  │
         └──────────────┘     │      │ + Notify     │
                │             │      └──────────────┘
                │             │
                ▼             │
    ┌───────────────────────────────┐
    │ Workflow: Performance Bench    │
    │ (Only on Release branches)     │
    ├───────────────────────────────┤
    │ • Build Release: -O3 -march    │
    │ • Run: hash benchmark          │
    │ • Collect metrics:             │
    │   - SHA3-256, SHA-256, BLAKE2b │
    │   - vs OpenSSL baseline        │
    └───────────────────────────────┘
                │
                ▼
    ┌───────────────────────────────┐
    │ Compare with Baseline          │
    │ (Threshold: ±5% deviation)     │
    ├───────────────────────────────┤
    │ Metric              Min   Max  │
    │ SHA3-256:          540   600   │
    │ SHA-256:          1850  2200   │
    │ BLAKE2b:           800   1000  │
    └───────────────────────────────┘
                │
      ┌─────────┴─────────┐
      │ Pass?             │ Fail
      ▼ Yes               ▼
   Merge          Alert + Logs
 Approved      (perf-regression)
                  Review Required
```

---

## 📝 实现计划

### Phase 1: 基础CI (Week 1-2, v3.5.0)

#### 1.1 GitHub Actions工作流：`ci.yml`
```yaml
name: Unit Tests & Build

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  build-and-test:
    strategy:
      matrix:
        os: [ubuntu-latest, windows-latest]
        compiler: [gcc-13, clang-16, msvc-2022]
    
    runs-on: ${{ matrix.os }}
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Install dependencies (Ubuntu)
        if: runner.os == 'Linux'
        run: |
          sudo apt-get update
          sudo apt-get install -y cmake ninja-build gcc-13 clang-16
      
      - name: Build Debug
        run: |
          cmake -B build_debug -DCMAKE_BUILD_TYPE=Debug
          cmake --build build_debug --parallel
      
      - name: Run Tests
        run: |
          cd build_debug
          ctest --output-on-failure
      
      - name: Upload test results
        if: always()
        uses: actions/upload-artifact@v3
        with:
          name: test-results-${{ matrix.os }}-${{ matrix.compiler }}
          path: build_debug/test-results.xml
```

#### 1.2 单元测试门槛
- **标准**: 152/152测试通过
- **检查**: GitHub Actions自动检查
- **阻挡**: 如果任何测试失败，阻止PR合并

### Phase 2: 性能基准CI (Week 3-4, v3.5.0)

#### 2.1 GitHub Actions工作流：`performance.yml`
```yaml
name: Performance Benchmark

on:
  push:
    branches: [main]  # 仅在main分支
  workflow_dispatch:  # 手动触发

jobs:
  benchmark:
    runs-on: ubuntu-latest  # 统一硬件环境
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Build Release
        run: |
          cmake -B build_release -DCMAKE_BUILD_TYPE=Release
          cmake --build build_release --parallel
      
      - name: Run Hash Benchmark
        run: |
          ./build_release/bin/kctsb_benchmark hash > bench-results.txt
      
      - name: Parse results
        id: parse
        run: |
          python scripts/parse_benchmark.py bench-results.txt
          echo "sha3_256_mbps=$SHA3_256_MBPS" >> $GITHUB_OUTPUT
          echo "blake2b_mbps=$BLAKE2B_MBPS" >> $GITHUB_OUTPUT
      
      - name: Compare with baseline
        run: |
          python scripts/check_performance.py \
            --sha3-256=${{ steps.parse.outputs.sha3_256_mbps }} \
            --threshold=5  # ±5%差异告警
      
      - name: Store results
        uses: actions/upload-artifact@v3
        with:
          name: benchmark-results
          path: bench-results.txt
      
      - name: Post to database
        if: success()
        run: |
          curl -X POST https://perf-db.example.com/api/metrics \
            -H "Authorization: Bearer ${{ secrets.PERF_DB_TOKEN }}" \
            -d @bench-results.json
      
      - name: Create comment on PR
        if: failure()
        uses: actions/github-script@v7
        with:
          script: |
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: '⚠️ **Performance Regression Detected**\n' +
                    'SHA3-256: 490 MB/s (expected: 540-600)\n' +
                    'Review performance analysis for details.'
            })
```

#### 2.2 性能门槛定义

```python
# scripts/check_performance.py

PERFORMANCE_BASELINE = {
    "sha3_256": {
        "min_mbps": 540,      # -5% from 567MB/s target
        "max_mbps": 600,      # +5% tolerance
        "unit": "MB/s"
    },
    "sha_256": {
        "min_mbps": 1850,
        "max_mbps": 2200,
        "unit": "MB/s"
    },
    "blake2b_512": {
        "min_mbps": 800,
        "max_mbps": 1000,
        "unit": "MB/s"
    },
    "sha3_512": {
        "min_mbps": 280,
        "max_mbps": 350,
        "unit": "MB/s"
    },
    "sm3": {
        "min_mbps": 300,
        "max_mbps": 400,
        "unit": "MB/s"
    }
}

def check_performance(results, threshold=5):
    """检查性能是否在可接受范围内"""
    for algo, baseline in PERFORMANCE_BASELINE.items():
        actual = results[algo]
        expected = (baseline["min_mbps"] + baseline["max_mbps"]) / 2
        deviation = abs(actual - expected) / expected * 100
        
        if deviation > threshold:
            print(f"❌ {algo}: {actual} MB/s (expected: {expected} ±{threshold}%)")
            return False
        else:
            print(f"✅ {algo}: {actual} MB/s (OK)")
    return True
```

### Phase 3: 多编译器支持 (Week 5, v3.5.0)

#### 3.1 编译器矩阵配置
```yaml
strategy:
  matrix:
    include:
      - { os: ubuntu-latest, cc: gcc-13, cxx: g++-13 }
      - { os: ubuntu-latest, cc: gcc-14, cxx: g++-14 }
      - { os: ubuntu-latest, cc: clang-16, cxx: clang++-16 }
      - { os: ubuntu-latest, cc: clang-17, cxx: clang++-17 }
      - { os: macos-latest, cc: clang, cxx: clang++ }
      - { os: windows-latest, cc: cl.exe, cxx: cl.exe }  # MSVC
```

#### 3.2 编译器特定优化
```cmake
# CMakeLists.txt中的编译器特定优化
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    # GCC 13+特定优化
    add_compile_options(-fno-semantic-interposition)
    add_compile_options(-ftree-vectorize)
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    # Clang特定优化
    add_compile_options(-fvectorize)
    add_compile_options(-fslp-vectorize-aggressive)
elseif(MSVC)
    # MSVC特定优化
    add_compile_options(/arch:AVX2)
    add_compile_options(/Qpar)  # 自动并行化
endif()
```

---

## 🔍 性能监控仪表板

### 目标：建立性能追踪系统
```
┌────────────────────────────────────────┐
│  kctsb Performance Dashboard (v3.5+)   │
├────────────────────────────────────────┤
│                                        │
│  SHA3-256:  520 MB/s [━━━━━━━━━━━━]   │
│             ↑ +2.8% vs baseline       │
│                                        │
│  SHA-256:  1950 MB/s [━━━━━━━━━━━━━]  │
│             ↑ -5.2% vs baseline       │
│                                        │
│  BLAKE2b:   920 MB/s [━━━━━━━━━━━━━]  │
│             ↑ +5.1% vs baseline ✅     │
│                                        │
│  [Last 10 commits] [Trends] [Details] │
└────────────────────────────────────────┘
```

### 实现选项
1. **GitHub Pages +静态HTML** (简易)
2. **Grafana + InfluxDB** (专业)
3. **自建Node.js + SQLite** (中等)

---

## ⚙️ 性能门槛规则

### 规则1：提交前检查 (Pre-commit Hook)
```bash
#!/bin/bash
# scripts/pre-commit-perf.sh

# 仅在Debug版本运行快速检查
cmake -B build_quick -DCMAKE_BUILD_TYPE=Debug -DKCTSB_QUICK_BENCH=ON
cmake --build build_quick --parallel

# 检查单元测试
ctest -quick || exit 1

echo "✅ Performance pre-commit check passed"
```

### 规则2：PR门槛 (Merge Block)
- **单元测试**: 152/152必须通过
- **编译**: 无致命错误（警告允许）
- **代码**: 除非明确标记为性能优化PR，否则性能不能下降

### 规则3：发布门槛 (Release Gate)
- **性能基准**: SHA3-256 ≥ 540 MB/s
- **对标**: 与OpenSSL差异 ±5%以内
- **兼容性**: 所有支持平台编译通过
- **安全**: 无新增漏洞告警

---

## 📊 成功指标

| 指标 | 目标值 | v3.4.1 | v3.5.0目标 |
|------|------|--------|-----------|
| CI可用 | 100% | ❌ | ✅ |
| 测试通过率 | 100% | 100% | 100% |
| 性能基准追踪 | 自动 | ❌ | ✅ |
| SHA3-256吞吐量 | 567 MB/s | 507 MB/s | 567+ MB/s |
| 性能回退告警 | <5min | - | ✅ |

---

## 📅 实现时间表

```
v3.5.0 Roadmap:
├── Week 1-2: 基础CI (单元测试)
│   └── GitHub Actions ci.yml
│   └── 多编译器矩阵
├── Week 3-4: 性能基准CI
│   └── performance.yml
│   └── 性能门槛脚本
├── Week 5: 监控仪表板
│   └── 性能追踪DB
│   └── 趋势分析
└── Week 6: 测试与文档
    └── CI文档
    └── 故障排查指南
```

---

## 🎬 下一步行动

### v3.4.1 (当前版本)
- ✅ 完成BLAKE2s移除
- ✅ 收集hash基准数据
- 📋 **本文档：CI/CD规划**

### v3.5.0 (下一版本)
1. **周期1**: 实现GitHub Actions基础CI
2. **周期2**: 实现性能基准CI + 门槛
3. **周期3**: 性能监控仪表板
4. **周期4**: 发布v3.5.0

---

## 📚 参考资源

- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [CMake CI Integration](https://cmake.org/cmake/help/latest/guide/using-dependencies/index.html)
- [Performance Benchmarking Best Practices](https://easyperf.net/blog/)
- [Linux Perf Tool](https://perf.wiki.kernel.org/)

---

**文档所有者**: kn1ghtc  
**创建日期**: 2026-01-16  
**计划实现**: v3.5.0  
**状态**: 📋 规划阶段  
