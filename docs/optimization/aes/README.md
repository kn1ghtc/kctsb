# AES算法优化指南

**版本**: v3.4.0+  
**日期**: 2026-01-16

## 📊 当前状态

kctsb实现的AES算法：
- AES-128/192/256 (ECB/CBC/CTR/GCM模式)
- 硬件加速: AES-NI支持
- 性能基线待建立

## 🎯 优化方向

### 待优化项
- [ ] 建立OpenSSL性能基线
- [ ] AES-NI intrinsics优化
- [ ] GCM模式CLMUL加速
- [ ] CTR模式并行化

### 已知最佳实践
- 使用`_mm_aesenc_si128`等intrinsics
- GCM使用`_mm_clmulepi64_si128`加速
- 表查找vs S-box权衡

---

**TODO**: 补充详细优化经验
