#!/usr/bin/env python3
"""
PSI/PIR Demonstration - Python Integration with kctsb Library

This module demonstrates how to use kctsb's PSI/PIR algorithms
from Python using ctypes FFI.

Usage:
    python psi_demo.py

Requirements:
    - kctsb library built and installed
    - Python 3.8+

Author: kn1ghtc
Version: 3.2.0
Date: 2026-01-14
"""

import ctypes
import logging
import os
import platform
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Tuple

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


# ============================================================================
# Constants
# ============================================================================

KCTSB_PSI_SUCCESS = 0
KCTSB_PSI_ERROR_INVALID_PARAM = -1
KCTSB_PSI_ERROR_MEMORY = -2
KCTSB_PSI_ERROR_HASH_FAILED = -3
KCTSB_PSI_ERROR_CUCKOO_FAILED = -4


# ============================================================================
# ctypes Structures
# ============================================================================

class KctsbPsiConfig(ctypes.Structure):
    """PSI configuration structure (maps to kctsb_psi_config_t)."""
    _fields_ = [
        ("hash_table_size", ctypes.c_size_t),
        ("num_hash_functions", ctypes.c_size_t),
        ("bucket_size", ctypes.c_size_t),
        ("sublinear_factor", ctypes.c_size_t),
        ("statistical_security", ctypes.c_double),
        ("max_cuckoo_iterations", ctypes.c_size_t),
        ("load_factor_threshold", ctypes.c_double),
        ("min_query_batch_size", ctypes.c_size_t),
        ("enable_batch_optimization", ctypes.c_bool),
        ("malicious_security", ctypes.c_bool),
    ]


class KctsbPsiResult(ctypes.Structure):
    """PSI result structure (maps to kctsb_psi_result_t)."""
    _fields_ = [
        ("intersection_size", ctypes.c_size_t),
        ("intersection_elements", ctypes.POINTER(ctypes.c_int64)),
        ("execution_time_ms", ctypes.c_double),
        ("client_time_ms", ctypes.c_double),
        ("server_time_ms", ctypes.c_double),
        ("communication_bytes", ctypes.c_double),
        ("hash_table_load_factor", ctypes.c_double),
        ("is_correct", ctypes.c_bool),
        ("error_message", ctypes.c_char * 256),
    ]


# ============================================================================
# Python Wrapper Classes
# ============================================================================

@dataclass
class PSIResult:
    """Python-friendly PSI result."""
    intersection: List[int] = field(default_factory=list)
    intersection_size: int = 0
    execution_time_ms: float = 0.0
    client_time_ms: float = 0.0
    server_time_ms: float = 0.0
    communication_bytes: float = 0.0
    hash_table_load_factor: float = 0.0
    is_correct: bool = False
    error_message: str = ""


def find_kctsb_library() -> Optional[Path]:
    """
    Find the kctsb shared library.
    
    Returns:
        Path to library if found, None otherwise.
    """
    # Project root directory (assuming this script is in docs/examples/psi)
    script_dir = Path(__file__).parent
    project_root = script_dir.parent.parent.parent
    
    # Possible library locations
    system = platform.system()
    
    if system == "Windows":
        lib_names = ["kctsb.dll", "libkctsb.dll"]
        search_paths = [
            project_root / "build" / "bin",
            project_root / "build" / "lib",
            project_root / "build" / "Release",
            Path("C:/msys64/mingw64/bin"),
            Path(os.environ.get("KCTSB_LIB_PATH", "")),
        ]
    elif system == "Darwin":  # macOS
        lib_names = ["libkctsb.dylib", "libkctsb.so"]
        search_paths = [
            project_root / "build" / "lib",
            Path("/usr/local/lib"),
            Path("/opt/homebrew/lib"),
            Path(os.environ.get("KCTSB_LIB_PATH", "")),
        ]
    else:  # Linux
        lib_names = ["libkctsb.so"]
        search_paths = [
            project_root / "build" / "lib",
            Path("/usr/local/lib"),
            Path("/usr/lib"),
            Path(os.environ.get("KCTSB_LIB_PATH", "")),
        ]
    
    for search_path in search_paths:
        if not search_path.exists():
            continue
        for lib_name in lib_names:
            lib_path = search_path / lib_name
            if lib_path.exists():
                return lib_path
    
    return None


class KctsbPSI:
    """
    Python wrapper for kctsb PSI algorithms.
    
    Example:
        >>> psi = KctsbPSI()
        >>> client_set = [1, 2, 3, 4, 5]
        >>> server_set = [3, 4, 5, 6, 7]
        >>> result = psi.compute_piano_psi(client_set, server_set)
        >>> print(f"Intersection: {result.intersection}")
    """
    
    def __init__(self, lib_path: Optional[str] = None):
        """
        Initialize the PSI wrapper.
        
        Args:
            lib_path: Optional path to kctsb library.
        """
        self._lib = None
        self._lib_path = None
        
        if lib_path:
            self._lib_path = Path(lib_path)
        else:
            self._lib_path = find_kctsb_library()
        
        if self._lib_path and self._lib_path.exists():
            try:
                self._lib = ctypes.CDLL(str(self._lib_path))
                self._setup_functions()
                logger.info(f"Loaded kctsb library from: {self._lib_path}")
            except Exception as e:
                logger.warning(f"Failed to load kctsb library: {e}")
                self._lib = None
        else:
            logger.warning("kctsb library not found, using pure Python fallback")
    
    def _setup_functions(self) -> None:
        """Set up ctypes function signatures."""
        if not self._lib:
            return
        
        # kctsb_psi_config_init
        self._lib.kctsb_psi_config_init.argtypes = [
            ctypes.POINTER(KctsbPsiConfig)
        ]
        self._lib.kctsb_psi_config_init.restype = None
        
        # kctsb_simple_psi_compute
        self._lib.kctsb_simple_psi_compute.argtypes = [
            ctypes.POINTER(ctypes.c_int64), ctypes.c_size_t,  # client
            ctypes.POINTER(ctypes.c_int64), ctypes.c_size_t,  # server
            ctypes.POINTER(KctsbPsiResult),                    # result
        ]
        self._lib.kctsb_simple_psi_compute.restype = ctypes.c_int
        
        # kctsb_psi_result_free
        self._lib.kctsb_psi_result_free.argtypes = [
            ctypes.POINTER(KctsbPsiResult)
        ]
        self._lib.kctsb_psi_result_free.restype = None
    
    def is_native_available(self) -> bool:
        """Check if native library is available."""
        return self._lib is not None
    
    def compute_simple_psi(
        self,
        client_set: List[int],
        server_set: List[int]
    ) -> PSIResult:
        """
        Compute PSI using simple hash-based method.
        
        Args:
            client_set: Client's input set.
            server_set: Server's input set.
        
        Returns:
            PSI computation result.
        """
        if self._lib:
            return self._compute_simple_psi_native(client_set, server_set)
        else:
            return self._compute_simple_psi_python(client_set, server_set)
    
    def _compute_simple_psi_native(
        self,
        client_set: List[int],
        server_set: List[int]
    ) -> PSIResult:
        """Native implementation using ctypes."""
        import time
        start = time.perf_counter()
        
        # Convert to ctypes arrays
        client_arr = (ctypes.c_int64 * len(client_set))(*client_set)
        server_arr = (ctypes.c_int64 * len(server_set))(*server_set)
        
        result = KctsbPsiResult()
        
        ret = self._lib.kctsb_simple_psi_compute(
            client_arr, len(client_set),
            server_arr, len(server_set),
            ctypes.byref(result)
        )
        
        py_result = PSIResult()
        
        if ret == KCTSB_PSI_SUCCESS:
            py_result.intersection_size = result.intersection_size
            py_result.intersection = [
                result.intersection_elements[i]
                for i in range(result.intersection_size)
            ]
            py_result.execution_time_ms = result.execution_time_ms
            py_result.is_correct = result.is_correct
            py_result.hash_table_load_factor = result.hash_table_load_factor
            
            # Free native memory
            self._lib.kctsb_psi_result_free(ctypes.byref(result))
        else:
            py_result.error_message = result.error_message.decode("utf-8", errors="ignore")
        
        elapsed = (time.perf_counter() - start) * 1000
        if py_result.execution_time_ms == 0:
            py_result.execution_time_ms = elapsed
        
        return py_result
    
    def _compute_simple_psi_python(
        self,
        client_set: List[int],
        server_set: List[int]
    ) -> PSIResult:
        """Pure Python fallback implementation."""
        import time
        start = time.perf_counter()
        
        s1 = set(client_set)
        s2 = set(server_set)
        intersection = list(s1 & s2)
        
        elapsed = (time.perf_counter() - start) * 1000
        
        return PSIResult(
            intersection=intersection,
            intersection_size=len(intersection),
            execution_time_ms=elapsed,
            is_correct=True
        )


def run_cli_demo() -> None:
    """Run kctsb CLI tool demo for PSI."""
    # Find CLI tool
    script_dir = Path(__file__).parent
    project_root = script_dir.parent.parent.parent
    
    if platform.system() == "Windows":
        cli_path = project_root / "build" / "bin" / "kctsb.exe"
    else:
        cli_path = project_root / "build" / "bin" / "kctsb"
    
    if not cli_path.exists():
        logger.warning(f"CLI tool not found at {cli_path}")
        return
    
    logger.info(f"Running CLI tool: {cli_path}")
    
    # Run version command
    result = subprocess.run(
        [str(cli_path), "version"],
        capture_output=True,
        text=True
    )
    print(result.stdout)


def main() -> None:
    """Main demonstration function."""
    print("=" * 60)
    print("  kctsb PSI/PIR Demonstration")
    print("=" * 60)
    print()
    
    # Initialize PSI wrapper
    psi = KctsbPSI()
    
    if psi.is_native_available():
        print("✓ Using native kctsb library")
    else:
        print("⚠ Native library not found, using Python fallback")
    
    print()
    
    # Test data
    client_set = list(range(1, 101))  # 1-100
    server_set = list(range(50, 151))  # 50-150
    
    print(f"Client set size: {len(client_set)}")
    print(f"Server set size: {len(server_set)}")
    print()
    
    # Compute PSI
    print("Computing PSI...")
    result = psi.compute_simple_psi(client_set, server_set)
    
    print()
    print("Results:")
    print(f"  Intersection size: {result.intersection_size}")
    print(f"  Execution time: {result.execution_time_ms:.3f} ms")
    print(f"  Is correct: {result.is_correct}")
    
    # Verify
    expected = set(client_set) & set(server_set)
    actual = set(result.intersection)
    
    if expected == actual:
        print("  ✓ Verification passed!")
    else:
        print("  ✗ Verification failed!")
        print(f"    Expected: {sorted(expected)[:10]}...")
        print(f"    Got: {sorted(actual)[:10]}...")
    
    print()
    
    # Try CLI demo
    print("-" * 40)
    print("CLI Tool Demo:")
    run_cli_demo()


if __name__ == "__main__":
    main()
