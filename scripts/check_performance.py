#!/usr/bin/env python3
"""
kctsb Performance Regression检测器
用于CI/CD性能门禁，检测benchmark结果是否低于baseline阈值。

Usage:
    python check_performance.py \
        --baseline docs/PERFORMANCE_BASELINE.md \
        --current benchmark_results.txt \
        --fail-on-regression \
        --threshold 5 \
        --blake2b-threshold 3

Exit Codes:
    0 - 性能达标或提升
    1 - 性能回退超过阈值 (CI失败)
    2 - 脚本执行错误 (文件不存在等)
"""

import argparse
import re
import sys
from pathlib import Path
from typing import Dict, Tuple


class PerformanceChecker:
    """性能回归检测器"""

    # 从PERFORMANCE_BASELINE.md提取的baseline数据 (10MB)
    BASELINE = {
        "SHA3-256": 492.84,    # MB/s
        "SHA3-512": 291.80,    # MB/s
        "BLAKE2b-512": 933.96, # MB/s
        "SM3": 355.35,         # MB/s
        "SHA-256": 1929.70,    # MB/s
        "SHA-512": 753.44,     # MB/s
        "AES-256-GCM Encrypt": 1667.75,  # MB/s
        "AES-256-GCM Decrypt": 1637.57,  # MB/s
        "ChaCha20-Poly1305 Enc": 449.30, # MB/s
        "ChaCha20-Poly1305 Dec": 458.08, # MB/s
    }

    def __init__(self, baseline_file: Path, current_file: Path,
                 threshold: float = 5.0, blake2b_threshold: float = 3.0):
        """
        初始化性能检查器

        Args:
            baseline_file: PERFORMANCE_BASELINE.md路径
            current_file: 当前benchmark结果文件路径
            threshold: 通用性能回退阈值 (%)
            blake2b_threshold: BLAKE2b特殊阈值 (%)
        """
        self.baseline_file = baseline_file
        self.current_file = current_file
        self.threshold = threshold
        self.blake2b_threshold = blake2b_threshold
        self.current_results: Dict[str, float] = {}
        self.regressions: list = []

    def parse_benchmark_results(self) -> None:
        """解析当前benchmark结果文件，提取10MB数据的kctsb性能"""
        if not self.current_file.exists():
            raise FileNotFoundError(f"Benchmark results not found: {self.current_file}")

        # 尝试多种编码
        encodings = ['utf-8', 'utf-8-sig', 'utf-16', 'latin-1']
        content = None
        for enc in encodings:
            try:
                content = self.current_file.read_text(encoding=enc)
                break
            except (UnicodeDecodeError, UnicodeError):
                continue

        if content is None:
            raise ValueError(f"Failed to decode {self.current_file} with encodings: {encodings}")

        # 正则提取10MB数据的kctsb性能
        # 格式: "SHA3-256                 kctsb              492.84 MB/s     20.29 ms"
        pattern = r'^(\S+(?:\s+\S+)*?)\s+(kctsb)\s+(\d+\.\d+)\s+MB/s'

        in_10mb_section = False
        for line in content.split('\n'):
            # 检测10MB数据区域
            if '--- Data Size: 10 MB ---' in line:
                in_10mb_section = True
                continue
            elif '--- Data Size:' in line and '10 MB' not in line:
                in_10mb_section = False
                continue

            if not in_10mb_section:
                continue

            match = re.match(pattern, line.strip())
            if match:
                algo_name = match.group(1).strip()
                throughput = float(match.group(3))

                # 标准化算法名称
                if "BLAKE2b-512" in algo_name or "BLAKE2b" in algo_name:
                    algo_name = "BLAKE2b-512"
                elif "SHA3-256" in algo_name:
                    algo_name = "SHA3-256"
                elif "SHA3-512" in algo_name:
                    algo_name = "SHA3-512"
                elif algo_name == "SM3":
                    algo_name = "SM3"
                elif algo_name == "SHA-256":
                    algo_name = "SHA-256"
                elif algo_name == "SHA-512":
                    algo_name = "SHA-512"
                elif "AES-256-GCM Encrypt" in algo_name:
                    algo_name = "AES-256-GCM Encrypt"
                elif "AES-256-GCM Decrypt" in algo_name:
                    algo_name = "AES-256-GCM Decrypt"
                elif "ChaCha20-Poly1305 Enc" in algo_name:
                    algo_name = "ChaCha20-Poly1305 Enc"
                elif "ChaCha20-Poly1305 Dec" in algo_name:
                    algo_name = "ChaCha20-Poly1305 Dec"

                self.current_results[algo_name] = throughput

        if not self.current_results:
            raise ValueError("No 10MB benchmark data found in results file")

    def check_regressions(self) -> bool:
        """
        检查性能回退

        Returns:
            True: 无回退或回退在阈值内
            False: 存在超出阈值的性能回退
        """
        has_regression = False

        print("=" * 80)
        print("📊 Performance Regression Check")
        print("=" * 80)
        print(f"{'Algorithm':<30} {'Baseline':<12} {'Current':<12} {'Change':<10} {'Status'}")
        print("-" * 80)

        for algo, baseline in self.BASELINE.items():
            if algo not in self.current_results:
                print(f"{algo:<30} {baseline:>10.2f} MB/s  {'N/A':<12} {'N/A':<10} ⚠️ MISSING")
                continue

            current = self.current_results[algo]
            change_percent = ((current - baseline) / baseline) * 100

            # 确定阈值
            if "BLAKE2b" in algo:
                threshold = self.blake2b_threshold
            else:
                threshold = self.threshold

            # 判断状态
            if change_percent >= 0:
                status = f"✅ +{change_percent:.2f}%"
            elif abs(change_percent) <= threshold:
                status = f"✅ {change_percent:.2f}%"
            else:
                status = f"❌ {change_percent:.2f}% (>{threshold}% threshold)"
                has_regression = True
                self.regressions.append({
                    "algorithm": algo,
                    "baseline": baseline,
                    "current": current,
                    "change_percent": change_percent,
                    "threshold": threshold
                })

            print(f"{algo:<30} {baseline:>10.2f} MB/s  {current:>10.2f} MB/s  "
                  f"{change_percent:>8.2f}%  {status}")

        print("=" * 80)

        return not has_regression

    def generate_report(self) -> str:
        """生成详细的性能报告"""
        report = ["", "📈 Performance Regression Summary", "=" * 80, ""]

        if not self.regressions:
            report.append("✅ All algorithms passed performance gates!")
            report.append(f"   Threshold: {self.threshold}% (BLAKE2b: {self.blake2b_threshold}%)")
        else:
            report.append(f"❌ {len(self.regressions)} algorithm(s) failed performance gates:")
            report.append("")
            for reg in self.regressions:
                report.append(f"  • {reg['algorithm']}")
                report.append(f"    Baseline:  {reg['baseline']:.2f} MB/s")
                report.append(f"    Current:   {reg['current']:.2f} MB/s")
                report.append(f"    Change:    {reg['change_percent']:.2f}% (threshold: {reg['threshold']}%)")
                report.append("")

            report.append("⚠️ Action Required:")
            report.append("  1. 检查代码变更是否引入性能回退")
            report.append("  2. 运行profiler定位性能瓶颈")
            report.append("  3. 优化算法实现或恢复之前版本")
            report.append("  4. 或更新baseline (如果性能牺牲是预期的)")

        report.append("=" * 80)
        return "\n".join(report)

    def run(self, fail_on_regression: bool = True) -> int:
        """
        执行性能检查

        Args:
            fail_on_regression: 性能回退时是否返回错误码

        Returns:
            0 - 成功
            1 - 性能回退 (fail_on_regression=True时)
            2 - 执行错误
        """
        try:
            self.parse_benchmark_results()
            passed = self.check_regressions()
            report = self.generate_report()
            print(report)

            if not passed and fail_on_regression:
                print("\n❌ CI FAILED: Performance regression detected!", file=sys.stderr)
                return 1
            elif not passed:
                print("\n⚠️ WARNING: Performance regression detected (not enforced)", file=sys.stderr)
                return 0
            else:
                print("\n✅ CI PASSED: All performance gates met!")
                return 0

        except Exception as e:
            print(f"\n❌ ERROR: {e}", file=sys.stderr)
            import traceback
            traceback.print_exc()
            return 2


def main():
    parser = argparse.ArgumentParser(
        description="kctsb Performance Regression Detector for CI/CD",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Check performance with 5% threshold
  python check_performance.py \\
      --baseline docs/PERFORMANCE_BASELINE.md \\
      --current benchmark_results.txt \\
      --fail-on-regression

  # Custom thresholds
  python check_performance.py \\
      --baseline docs/PERFORMANCE_BASELINE.md \\
      --current benchmark_results.txt \\
      --threshold 10 \\
      --blake2b-threshold 5
        """
    )

    parser.add_argument(
        "--baseline",
        type=Path,
        required=True,
        help="Path to PERFORMANCE_BASELINE.md"
    )
    parser.add_argument(
        "--current",
        type=Path,
        required=True,
        help="Path to current benchmark results file"
    )
    parser.add_argument(
        "--fail-on-regression",
        action="store_true",
        help="Exit with code 1 if performance regression detected"
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=5.0,
        help="General performance regression threshold (%%) [default: 5]"
    )
    parser.add_argument(
        "--blake2b-threshold",
        type=float,
        default=3.0,
        help="BLAKE2b-specific threshold (%%) [default: 3]"
    )

    args = parser.parse_args()

    checker = PerformanceChecker(
        baseline_file=args.baseline,
        current_file=args.current,
        threshold=args.threshold,
        blake2b_threshold=args.blake2b_threshold
    )

    return checker.run(fail_on_regression=args.fail_on_regression)


if __name__ == "__main__":
    sys.exit(main())
