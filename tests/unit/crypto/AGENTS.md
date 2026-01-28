# AGENTS.md - tests/unit/crypto

## Scope
- 使用 GoogleTest 的单元测试目录。

## 约束
- 仅测试对外 C ABI 与稳定接口，禁止依赖私有实现细节。
- RSA 测试必须使用标准向量（如 Wycheproof），覆盖 OAEP 与 PSS。
- 禁止引入 2048 位 RSA 或 PKCS#1 v1.5 相关用例。
