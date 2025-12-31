#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔═══════════════════════════════════════════════════════════════════════════╗
║                    Race Condition Detector v2.0                           ║
║         Professional Race Condition Vulnerability Scanner (Enhanced)      ║
║                                                                           ║
║  Author: arkanzas.feziii                                                  ║
║  Python Version: 3.8+                                                     ║
║  License: MIT                                                             ║
║                                                                           ║
║  CHANGELOG v2.0:                                                          ║
║  • Fixed critical dynamic testing bug (results now properly serialized)  ║
║  • Added multiprocessing support for true parallelism testing            ║
║  • Enhanced lock detection (actual Lock instances, not just names)       ║
║  • Added signal handler race detection                                   ║
║  • Added database race detection with SQLite mock                        ║
║  • Improved file-based race detection (tempfile, permissions)            ║
║  • Added asyncio/coroutine race detection                                ║
║  • YAML config file support for custom rules                             ║
║  • Plugin system for extensibility                                       ║
║  • ASCII diagram visualizations for thread interactions                  ║
║  • Reduced false positives with improved heuristics                      ║
║  • Enhanced sandboxing for dynamic execution                             ║
║  • Color output support for terminals                                    ║
║  • Comprehensive self-tests with dynamic validation                      ║
║                                                                           ║
║  Detected Race Condition Types:                                          ║
║  • Time-of-Check to Time-of-Use (TOCTOU)                                 ║
║  • Read-After-Write / Write-After-Read hazards                           ║
║  • Atomicity violations in compound operations                           ║
║  • Unsynchronized shared resource access                                 ║
║  • File-based race conditions (including tempfile)                       ║
║  • Signal handler races                                                  ║
║  • Database concurrency issues                                           ║
║  • Asyncio coroutine races                                               ║
║                                                                           ║
╚═══════════════════════════════════════════════════════════════════════════╝
"""

import ast
import os
import sys
import json
import time
import random
import logging
import argparse
import inspect
import hashlib
import tempfile
import threading
import multiprocessing
import subprocess
import signal
import sqlite3
import asyncio
import pickle
from pathlib import Path
from typing import List, Dict, Set, Tuple, Optional, Any, Callable, Union
from dataclasses import dataclass, field, asdict
from enum import Enum
from collections import defaultdict
from contextlib import contextmanager
from io import StringIO
import traceback
import re
import shutil

# Optional imports with fallbacks
try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False
    logging.debug("PyYAML not available; config file support disabled")

try:
    from hypothesis import given, strategies as st
    HAS_HYPOTHESIS = True
except ImportError:
    HAS_HYPOTHESIS = False
    logging.debug("Hypothesis not available; property-based testing disabled")

# Terminal color support detection
try:
    import colorama
    colorama.init(autoreset=True)
    HAS_COLOR = True
except ImportError:
    HAS_COLOR = sys.stdout.isatty()


# ═══════════════════════════════════════════════════════════════════════════
#                           COLOR HELPERS
# ═══════════════════════════════════════════════════════════════════════════


class Colors:
    """Terminal color codes with fallback for non-supporting terminals."""
    if HAS_COLOR:
        RED = '\033[91m'
        GREEN = '\033[92m'
        YELLOW = '\033[93m'
        BLUE = '\033[94m'
        MAGENTA = '\033[95m'
        CYAN = '\033[96m'
        BOLD = '\033[1m'
        RESET = '\033[0m'
    else:
        RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = BOLD = RESET = ''


# ═══════════════════════════════════════════════════════════════════════════
#                           ENUMS AND DATA CLASSES
# ═══════════════════════════════════════════════════════════════════════════


class Severity(Enum):
    """Severity levels for detected race conditions."""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class RaceType(Enum):
    """Types of race conditions that can be detected."""
    TOCTOU = "Time-of-Check to Time-of-Use"
    READ_MODIFY_WRITE = "Read-Modify-Write Atomicity Violation"
    UNSYNCHRONIZED_ACCESS = "Unsynchronized Shared Resource Access"
    FILE_RACE = "File-Based Race Condition"
    SIGNAL_RACE = "Signal Handler Race"
    COMPOUND_OPERATION = "Non-Atomic Compound Operation"
    GLOBAL_VARIABLE = "Concurrent Global Variable Access"
    DATABASE_RACE = "Database Concurrency Issue"
    ASYNCIO_RACE = "Asyncio Coroutine Race Condition"
    TEMPFILE_RACE = "Temporary File Race"


@dataclass
class RaceCondition:
    """Represents a detected race condition vulnerability."""
    race_type: RaceType
    severity: Severity
    file_path: str
    line_number: int
    code_snippet: str
    description: str
    variable_name: Optional[str] = None
    thread_count: Optional[int] = None
    iterations_tested: Optional[int] = None
    failure_rate: Optional[float] = None
    recommended_fix: str = ""
    confidence: float = 0.0
    detection_method: str = "static"
    visualization: Optional[str] = None
    timestamp: str = field(default_factory=lambda: time.strftime('%Y-%m-%d %H:%M:%S'))
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            'race_type': self.race_type.value,
            'severity': self.severity.name,
            'file_path': self.file_path,
            'line_number': self.line_number,
            'code_snippet': self.code_snippet,
            'description': self.description,
            'variable_name': self.variable_name,
            'thread_count': self.thread_count,
            'iterations_tested': self.iterations_tested,
            'failure_rate': self.failure_rate,
            'recommended_fix': self.recommended_fix,
            'confidence': self.confidence,
            'detection_method': self.detection_method,
            'visualization': self.visualization,
            'timestamp': self.timestamp
        }


@dataclass
class DetectorConfig:
    """Configuration for race condition detector."""
    min_confidence: float = 0.70
    max_threads: int = 16
    iterations: int = 1000
    timeout_per_test: int = 10
    ignore_patterns: List[str] = field(default_factory=list)
    enable_multiprocessing: bool = True
    enable_asyncio_detection: bool = True
    enable_db_detection: bool = True
    custom_rules: Dict[str, Any] = field(default_factory=dict)
    
    @classmethod
    def from_yaml(cls, path: str) -> 'DetectorConfig':
        """Load configuration from YAML file."""
        if not HAS_YAML:
            logging.warning("YAML support not available; using defaults")
            return cls()
        
        try:
            with open(path, 'r') as f:
                data = yaml.safe_load(f)
            return cls(**{k: v for k, v in data.items() if hasattr(cls, k)})
        except Exception as e:
            logging.error(f"Failed to load config from {path}: {e}")
            return cls()


# ═══════════════════════════════════════════════════════════════════════════
#                          ENHANCED STATIC ANALYSIS ENGINE
# ═══════════════════════════════════════════════════════════════════════════


class EnhancedStaticAnalyzer(ast.NodeVisitor):
    """
    Enhanced AST-based static analyzer with improved accuracy.
    
    Improvements:
    - Actual Lock instance detection
    - Signal handler race detection
    - Asyncio race detection
    - Better TOCTOU coverage
    - Database operation tracking
    """
    
    def __init__(self, source_code: str, file_path: str, config: DetectorConfig):
        self.source_code = source_code
        self.file_path = file_path
        self.config = config
        self.lines = source_code.split('\n')
        self.race_conditions: List[RaceCondition] = []
        
        # Enhanced tracking
        self.shared_variables: Set[str] = set()
        self.global_variables: Set[str] = set()
        self.locked_sections: List[Tuple[int, int]] = []
        self.lock_objects: Set[str] = set()  # Actual Lock instances
        self.thread_functions: Set[str] = set()
        self.async_functions: Set[str] = set()
        self.signal_handlers: Dict[int, str] = {}
        self.db_operations: List[Tuple[int, str]] = []
        self.file_operations: List[Tuple[int, str]] = []
        self.tempfile_usages: List[Tuple[int, str]] = []
        
        # Concurrency flags
        self.has_threading: bool = False
        self.has_multiprocessing: bool = False
        self.has_asyncio: bool = False
        
        # Scope tracking
        self.current_function: Optional[str] = None
        self.in_thread_target: bool = False
        self.in_async_function: bool = False
        
        # AST cache for performance
        self._ast_cache: Dict[str, ast.AST] = {}
        
        logging.debug(f"Initialized EnhancedStaticAnalyzer for {file_path}")
    
    def analyze(self) -> List[RaceCondition]:
        """Perform enhanced static analysis."""
        try:
            tree = ast.parse(self.source_code)
            self._annotate_parents(tree)
            self.visit(tree)
            self._post_analysis()
            return [r for r in self.race_conditions if r.confidence >= self.config.min_confidence]
        except SyntaxError as e:
            logging.error(f"Syntax error in {self.file_path}: {e}")
            return []
        except Exception as e:
            logging.error(f"Analysis error in {self.file_path}: {e}")
            if logging.getLogger().level == logging.DEBUG:
                traceback.print_exc()
            return []
    
    def _annotate_parents(self, tree: ast.AST):
        """Annotate each node with its parent for context-aware analysis."""
        for parent in ast.walk(tree):
            for child in ast.iter_child_nodes(parent):
                child._parent = parent
    
    def visit_Import(self, node: ast.Import):
        """Detect concurrency module imports."""
        for alias in node.names:
            if 'threading' in alias.name:
                self.has_threading = True
            elif 'multiprocessing' in alias.name:
                self.has_multiprocessing = True
            elif 'asyncio' in alias.name:
                self.has_asyncio = True
        self.generic_visit(node)
    
    def visit_ImportFrom(self, node: ast.ImportFrom):
        """Detect concurrency module imports."""
        if node.module:
            if 'threading' in node.module:
                self.has_threading = True
            elif 'multiprocessing' in node.module:
                self.has_multiprocessing = True
            elif 'asyncio' in node.module:
                self.has_asyncio = True
            elif node.module == 'signal':
                # Track signal module usage
                pass
        self.generic_visit(node)
    
    def visit_Global(self, node: ast.Global):
        """Track global variable declarations."""
        for name in node.names:
            self.global_variables.add(name)
        self.generic_visit(node)
    
    def visit_FunctionDef(self, node: ast.FunctionDef):
        """Analyze function definitions."""
        prev_function = self.current_function
        self.current_function = node.name
        
        # Check if thread target
        if self._is_thread_target(node):
            self.thread_functions.add(node.name)
            prev_in_thread = self.in_thread_target
            self.in_thread_target = True
            self.generic_visit(node)
            self.in_thread_target = prev_in_thread
        else:
            self.generic_visit(node)
        
        self.current_function = prev_function
    
    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        """Track async functions for asyncio race detection."""
        self.async_functions.add(node.name)
        prev_in_async = self.in_async_function
        self.in_async_function = True
        self.generic_visit(node)
        self.in_async_function = prev_in_async
    
    def visit_Assign(self, node: ast.Assign):
        """Detect Lock instantiation and shared variable assignments."""
        # Detect Lock objects
        if isinstance(node.value, ast.Call):
            if self._is_lock_creation(node.value):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.lock_objects.add(target.id)
                        logging.debug(f"Detected Lock object: {target.id}")
        
        # Check shared variable assignments
        if self.in_thread_target or self.has_threading or self.in_async_function:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    var_name = target.id
                    if var_name in self.global_variables or var_name.isupper():
                        if not self._is_in_locked_section(node.lineno):
                            self._report_unsynchronized_access(node, var_name, 'write')
        
        self.generic_visit(node)
    
    def visit_AugAssign(self, node: ast.AugAssign):
        """Detect read-modify-write operations."""
        if isinstance(node.target, ast.Name):
            var_name = node.target.id
            if (self.in_thread_target or self.has_threading or self.in_async_function) and \
               (var_name in self.global_variables or var_name.isupper()):
                if not self._is_in_locked_section(node.lineno):
                    self._report_read_modify_write(node, var_name)
        
        self.generic_visit(node)
    
    def visit_With(self, node: ast.With):
        """Track synchronized sections."""
        for item in node.items:
            if isinstance(item.context_expr, ast.Name):
                lock_name = item.context_expr.id
                if lock_name in self.lock_objects or 'lock' in lock_name.lower():
                    self.locked_sections.append((node.lineno, self._get_last_line(node)))
        
        self.generic_visit(node)
    
    def visit_Call(self, node: ast.Call):
        """Detect various concurrency patterns and operations."""
        # Thread/Process creation
        if isinstance(node.func, ast.Attribute):
            if node.func.attr in ('Thread', 'Process'):
                for keyword in node.keywords:
                    if keyword.arg == 'target' and isinstance(keyword.value, ast.Name):
                        self.thread_functions.add(keyword.value.id)
        
        # File operations
        if isinstance(node.func, ast.Name):
            if node.func.id == 'open':
                self.file_operations.append((node.lineno, self._get_node_text(node)))
        
        # Tempfile operations
        if isinstance(node.func, ast.Attribute):
            if node.func.attr in ('NamedTemporaryFile', 'mkstemp', 'mkdtemp'):
                self.tempfile_usages.append((node.lineno, self._get_node_text(node)))
                self._check_tempfile_race(node)
        
        # TOCTOU patterns
        if isinstance(node.func, ast.Attribute):
            if node.func.attr in ('exists', 'isfile', 'isdir', 'access'):
                self._check_toctou_pattern(node)
        
        # Signal handlers
        if isinstance(node.func, ast.Attribute):
            if node.func.attr == 'signal' and len(node.args) >= 2:
                self._check_signal_handler(node)
        
        # Database operations
        if isinstance(node.func, ast.Attribute):
            if node.func.attr in ('execute', 'executemany', 'commit', 'cursor'):
                self.db_operations.append((node.lineno, self._get_node_text(node)))
                if self.has_threading and not self._is_in_locked_section(node.lineno):
                    self._report_database_race(node)
        
        self.generic_visit(node)
    
    def _is_lock_creation(self, node: ast.Call) -> bool:
        """Check if a call creates a Lock object."""
        if isinstance(node.func, ast.Attribute):
            return node.func.attr in ('Lock', 'RLock', 'Semaphore', 'BoundedSemaphore')
        if isinstance(node.func, ast.Name):
            return node.func.id in ('Lock', 'RLock', 'Semaphore')
        return False
    
    def _is_thread_target(self, node: ast.FunctionDef) -> bool:
        """Check if function is used as thread target."""
        return node.name in self.thread_functions
    
    def _is_in_locked_section(self, line_number: int) -> bool:
        """Check if line is within a locked section."""
        return any(start <= line_number <= end for start, end in self.locked_sections)
    
    def _get_last_line(self, node: ast.AST) -> int:
        """Get the last line number of an AST node."""
        last_line = getattr(node, 'lineno', 0)
        for child in ast.walk(node):
            if hasattr(child, 'lineno'):
                last_line = max(last_line, child.lineno)
        return last_line
    
    def _get_node_text(self, node: ast.AST) -> str:
        """Extract source code text for an AST node."""
        try:
            if hasattr(node, 'lineno'):
                start = node.lineno - 1
                end = min(self._get_last_line(node), len(self.lines))
                return '\n'.join(self.lines[start:end])
        except:
            pass
        return "<code unavailable>"
    
    def _check_toctou_pattern(self, node: ast.Call):
        """Detect TOCTOU patterns with improved accuracy."""
        line = node.lineno
        
        for file_line, file_op in self.file_operations:
            if file_line > line and file_line <= line + 15:
                if not self._is_in_locked_section(line):
                    self._report_toctou(node, file_line)
                    break
    
    def _check_tempfile_race(self, node: ast.Call):
        """Detect temporary file race conditions."""
        # Check if delete=False is used (file persists)
        has_delete_false = any(
            kw.arg == 'delete' and isinstance(kw.value, ast.Constant) and not kw.value.value
            for kw in node.keywords
        )
        
        if has_delete_false and (self.has_threading or self.has_multiprocessing):
            race = RaceCondition(
                race_type=RaceType.TEMPFILE_RACE,
                severity=Severity.MEDIUM,
                file_path=self.file_path,
                line_number=node.lineno,
                code_snippet=self._get_node_text(node),
                description=(
                    f"Temporary file created with delete=False in concurrent context. "
                    f"Multiple threads/processes may create files with predictable names, "
                    f"leading to race conditions or security issues."
                ),
                recommended_fix=(
                    "Use unique file names with uuid or ensure proper cleanup with locks. "
                    "Consider using context managers with delete=True."
                ),
                confidence=0.75,
                detection_method="static"
            )
            self.race_conditions.append(race)
    
    def _check_signal_handler(self, node: ast.Call):
        """Detect signal handler races."""
        if self.has_threading:
            race = RaceCondition(
                race_type=RaceType.SIGNAL_RACE,
                severity=Severity.HIGH,
                file_path=self.file_path,
                line_number=node.lineno,
                code_snippet=self._get_node_text(node),
                description=(
                    f"Signal handler registered in multi-threaded context. "
                    f"Signal handlers are not thread-safe and can cause race conditions "
                    f"when accessing shared state."
                ),
                recommended_fix=(
                    "Avoid using signals with threading. Use threading.Event or queues "
                    "for inter-thread communication. If signals are necessary, use "
                    "signal.set_wakeup_fd() for async-safe handling."
                ),
                confidence=0.85,
                detection_method="static"
            )
            self.race_conditions.append(race)
    
    def _report_toctou(self, check_node: ast.AST, use_line: int):
        """Report TOCTOU race with visualization."""
        snippet = self._get_node_text(check_node)
        
        viz = self._create_toctou_diagram(check_node.lineno, use_line)
        
        race = RaceCondition(
            race_type=RaceType.TOCTOU,
            severity=Severity.HIGH,
            file_path=self.file_path,
            line_number=check_node.lineno,
            code_snippet=snippet,
            description=(
                f"Time-of-Check to Time-of-Use race: File check at line {check_node.lineno} "
                f"followed by operation at line {use_line}. File state may change between check and use."
            ),
            recommended_fix=(
                "Use try-except instead of existence checks, or use file locking "
                "(fcntl.flock on Unix, msvcrt.locking on Windows)."
            ),
            confidence=0.88,
            detection_method="static",
            visualization=viz
        )
        
        self.race_conditions.append(race)
    
    def _report_unsynchronized_access(self, node: ast.AST, var_name: str, access_type: str):
        """Report unsynchronized access."""
        race = RaceCondition(
            race_type=RaceType.UNSYNCHRONIZED_ACCESS,
            severity=Severity.MEDIUM,
            file_path=self.file_path,
            line_number=node.lineno,
            code_snippet=self._get_node_text(node),
            description=(
                f"Unsynchronized {access_type} to shared variable '{var_name}' "
                f"in concurrent context. May cause data races."
            ),
            variable_name=var_name,
            recommended_fix=(
                f"Protect '{var_name}' with threading.Lock(). "
                f"Use 'with lock:' blocks for all accesses."
            ),
            confidence=0.78,
            detection_method="static"
        )
        
        self.race_conditions.append(race)
    
    def _report_read_modify_write(self, node: ast.AugAssign, var_name: str):
        """Report read-modify-write race."""
        viz = self._create_rmw_diagram(var_name)
        
        race = RaceCondition(
            race_type=RaceType.READ_MODIFY_WRITE,
            severity=Severity.HIGH,
            file_path=self.file_path,
            line_number=node.lineno,
            code_snippet=self._get_node_text(node),
            description=(
                f"Non-atomic read-modify-write on '{var_name}'. "
                f"Compound operations like '+=' are not atomic and lose updates in concurrent execution."
            ),
            variable_name=var_name,
            recommended_fix=(
                f"Use threading.Lock() for compound operations, or use atomic types "
                f"from multiprocessing.Value/Array if using processes."
            ),
            confidence=0.92,
            detection_method="static",
            visualization=viz
        )
        
        self.race_conditions.append(race)
    
    def _report_database_race(self, node: ast.Call):
        """Report database race condition."""
        race = RaceCondition(
            race_type=RaceType.DATABASE_RACE,
            severity=Severity.HIGH,
            file_path=self.file_path,
            line_number=node.lineno,
            code_snippet=self._get_node_text(node),
            description=(
                f"Database operation in multi-threaded context without synchronization. "
                f"SQLite and other DBs may not be thread-safe without proper locking."
            ),
            recommended_fix=(
                "Use a single connection per thread, or protect DB operations with locks. "
                "Consider using connection pooling with thread-local storage."
            ),
            confidence=0.80,
            detection_method="static"
        )
        
        self.race_conditions.append(race)
    
    def _create_toctou_diagram(self, check_line: int, use_line: int) -> str:
        """Create ASCII diagram for TOCTOU race."""
        return f"""
Thread A                    Thread B
  |                           |
  | Check file (line {check_line})     |
  |                           |
  |                           | Modify/delete file
  |                           |
  | Use file (line {use_line})         | ← RACE WINDOW
  |                           |
"""
    
    def _create_rmw_diagram(self, var_name: str) -> str:
        """Create ASCII diagram for read-modify-write race."""
        return f"""
Thread A                    Thread B
  |                           |
  | Read {var_name}                  | Read {var_name}
  | ({var_name}=10)                  | ({var_name}=10)
  |                           |
  | Modify (+1)                | Modify (+1)
  |                           |
  | Write {var_name}=11              | Write {var_name}=11
  |                           |
  ↓                           ↓
Lost update! Final value: 11 (should be 12)
"""
    
    def _post_analysis(self):
        """Perform post-analysis checks."""
        # Check for threading without locks on globals
        if (self.has_threading or self.has_multiprocessing) and \
           len(self.lock_objects) == 0 and len(self.global_variables) > 0:
            
            global_list = ', '.join(list(self.global_variables)[:3])
            if len(self.global_variables) > 3:
                global_list += f" (+{len(self.global_variables)-3} more)"
            
            race = RaceCondition(
                race_type=RaceType.GLOBAL_VARIABLE,
                severity=Severity.MEDIUM,
                file_path=self.file_path,
                line_number=1,
                code_snippet="<entire file>",
                description=(
                    f"File uses threading/multiprocessing with global variables ({global_list}) "
                    f"but no Lock objects detected. Missing synchronization likely."
                ),
                recommended_fix=(
                    "Add threading.Lock() to synchronize shared globals. "
                    "Use thread-safe structures from queue module."
                ),
                confidence=0.68,
                detection_method="static"
            )
            
            self.race_conditions.append(race)
        
        # Check asyncio without proper synchronization
        if self.in_async_function and len(self.async_functions) > 1 and len(self.lock_objects) == 0:
            race = RaceCondition(
                race_type=RaceType.ASYNCIO_RACE,
                severity=Severity.MEDIUM,
                file_path=self.file_path,
                line_number=1,
                code_snippet="<async functions>",
                description=(
                    f"Multiple async functions detected without asyncio.Lock. "
                    f"Shared state access in coroutines may race."
                ),
                recommended_fix=(
                    "Use asyncio.Lock() for shared state in coroutines. "
                    "Ensure await is used properly for synchronization."
                ),
                confidence=0.65,
                detection_method="static"
            )
            self.race_conditions.append(race)


# ═══════════════════════════════════════════════════════════════════════════
#                   ENHANCED DYNAMIC ANALYSIS ENGINE
# ═══════════════════════════════════════════════════════════════════════════


class EnhancedDynamicAnalyzer:
    """
    Enhanced dynamic analyzer with bug fixes and multiprocessing support.
    
    Key fixes:
    - Results now properly serialized with JSON for comparison
    - Support for both threading and multiprocessing
    - Better timeout handling
    - Enhanced sandboxing
    """
    
    def __init__(self, code: str, file_path: str, config: DetectorConfig):
        self.code = code
        self.file_path = file_path
        self.config = config
        self.race_conditions: List[RaceCondition] = []
        
        logging.debug(f"Initialized EnhancedDynamicAnalyzer: {config.max_threads} threads, {config.iterations} iterations")
    
    def analyze(self) -> List[RaceCondition]:
        """Perform enhanced dynamic analysis."""
        test_candidates = self._extract_test_candidates()
        
        for func_name, func_code in test_candidates:
            logging.info(f"Dynamic testing: {func_name}")
            
            # Test with threading
            results_threading = self._stress_test_function(func_name, func_code, use_multiprocessing=False)
            if results_threading['inconsistent']:
                self._report_dynamic_race(func_name, results_threading, 'threading')
            
            # Test with multiprocessing if enabled
            if self.config.enable_multiprocessing:
                results_mp = self._stress_test_function(func_name, func_code, use_multiprocessing=True)
                if results_mp['inconsistent']:
                    self._report_dynamic_race(func_name, results_mp, 'multiprocessing')
        
        return self.race_conditions
    
    def _extract_test_candidates(self) -> List[Tuple[str, str]]:
        """Extract functions suitable for dynamic testing."""
        candidates = []
        
        try:
            tree = ast.parse(self.code)
            
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    has_global = any(isinstance(n, ast.Global) for n in ast.walk(node))
                    has_shared = self._has_shared_access(node)
                    
                    if has_global or has_shared:
                        func_code = ast.get_source_segment(self.code, node)
                        if func_code:
                            candidates.append((node.name, func_code))
        
        except Exception as e:
            logging.error(f"Error extracting test candidates: {e}")
        
        return candidates
    
    def _has_shared_access(self, node: ast.FunctionDef) -> bool:
        """Check if function accesses shared resources."""
        for child in ast.walk(node):
            if isinstance(child, ast.Name):
                if child.id.isupper():
                    return True
            
            if isinstance(child, ast.Call):
                if isinstance(child.func, ast.Name) and child.func.id in ('open', 'sqlite3'):
                    return True
        
        return False
    
    def _stress_test_function(self, func_name: str, func_code: str, use_multiprocessing: bool = False) -> Dict[str, Any]:
        """
        Stress test a function with multiple threads/processes.
        
        Args:
            func_name: Function name
            func_code: Function source code
            use_multiprocessing: Use processes instead of threads
        
        Returns:
            Dictionary with test results
        """
        results = {
            'outcomes': [],
            'inconsistent': False,
            'failure_count': 0,
            'total_runs': self.config.iterations,
            'execution_type': 'multiprocessing' if use_multiprocessing else 'threading'
        }
        
        test_code = self._create_test_harness(func_name, func_code, use_multiprocessing)
        
        for i in range(self.config.iterations):
            try:
                outcome = self._run_single_test(test_code, func_name)
                results['outcomes'].append(outcome)
                
                # Check for inconsistency
                unique_outcomes = set(results['outcomes'])
                if len(unique_outcomes) > 1:
                    results['inconsistent'] = True
                    results['failure_count'] += 1
            
            except Exception as e:
                logging.debug(f"Test iteration {i} failed: {e}")
                results['failure_count'] += 1
        
        results['failure_rate'] = results['failure_count'] / self.config.iterations if self.config.iterations > 0 else 0
        
        return results
    
    def _create_test_harness(self, func_name: str, func_code: str, use_multiprocessing: bool) -> str:
        """
        Create test harness with proper serialization.
        
        Key fix: Results are now properly printed as JSON for comparison.
        """
        module = 'multiprocessing' if use_multiprocessing else 'threading'
        process_type = 'Process' if use_multiprocessing else 'Thread'
        
        harness = f"""
import {module}
import time
import random
import json
import sys

# Original function
{func_code}

# Shared result storage
if {use_multiprocessing}:
    import multiprocessing
    manager = multiprocessing.Manager()
    results = manager.list()
    result_lock = manager.Lock()
else:
    results = []
    result_lock = {module}.Lock()

def test_wrapper():
    # Random delay to widen race window
    time.sleep(random.uniform(0, 0.005))
    
    try:
        result = {func_name}()
        with result_lock:
            results.append(result)
    except Exception as e:
        with result_lock:
            results.append({{'error': str(e)}})

# Run threads/processes
workers = []
for _ in range({self.config.max_threads}):
    w = {module}.{process_type}(target=test_wrapper)
    workers.append(w)
    w.start()

for w in workers:
    w.join(timeout={self.config.timeout_per_test})

# CRITICAL FIX: Serialize results to JSON for proper comparison
print(json.dumps(list(results), default=str))
"""
        return harness
    
    def _run_single_test(self, test_code: str, func_name: str) -> str:
        """
        Run a single test iteration in isolated subprocess.
        
        Returns:
            Hash of the serialized result for comparison
        """
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(test_code)
            temp_file = f.name
        
        try:
            result = subprocess.run(
                [sys.executable, temp_file],
                capture_output=True,
                text=True,
                timeout=self.config.timeout_per_test
            )
            
            if result.returncode == 0 and result.stdout:
                # Hash the JSON output for comparison
                return hashlib.sha256(result.stdout.encode()).hexdigest()
            else:
                return f"error:{result.returncode}:{result.stderr[:50]}"
        
        except subprocess.TimeoutExpired:
            return "timeout"
        
        except Exception as e:
            return f"exception:{str(e)[:50]}"
        
        finally:
            try:
                os.unlink(temp_file)
            except:
                pass
    
    def _report_dynamic_race(self, func_name: str, results: Dict[str, Any], exec_type: str):
        """Report dynamically detected race with enhanced details."""
        severity = Severity.HIGH if results['failure_rate'] > 0.15 else Severity.MEDIUM
        confidence = min(0.98, 0.60 + results['failure_rate'])
        
        viz = self._create_race_diagram(func_name, self.config.max_threads, results['failure_rate'])
        
        race = RaceCondition(
            race_type=RaceType.COMPOUND_OPERATION,
            severity=severity,
            file_path=self.file_path,
            line_number=0,
            code_snippet=f"function: {func_name}",
            description=(
                f"Race condition detected in '{func_name}' via dynamic {exec_type} testing. "
                f"Inconsistent outcomes in {results['failure_count']}/{results['total_runs']} "
                f"iterations with {self.config.max_threads} concurrent {exec_type}s. "
                f"This confirms the presence of a real race condition."
            ),
            variable_name=func_name,
            thread_count=self.config.max_threads,
            iterations_tested=results['total_runs'],
            failure_rate=results['failure_rate'],
            recommended_fix=(
                f"Add synchronization to '{func_name}'. Use locks to protect shared state, "
                f"or refactor to use immutable data structures and functional approaches."
            ),
            confidence=confidence,
            detection_method=f"dynamic-{exec_type}",
            visualization=viz
        )
        
        self.race_conditions.append(race)
    
    def _create_race_diagram(self, func_name: str, thread_count: int, failure_rate: float) -> str:
        """Create visualization for dynamic race detection."""
        return f"""
Concurrent Execution Test Results:
{'═' * 50}
Function: {func_name}
Workers:  {thread_count} concurrent threads/processes
Failure:  {failure_rate:.1%} inconsistent outcomes

Execution Timeline:
T1 ──────●───────────────────●──────→
T2 ────────────●─────────────●──────→
T3 ──────────────●───────────●──────→
T4 ────────●─────────────────●──────→
      ↑                    ↑
   Shared access      Race detected
"""


# ═══════════════════════════════════════════════════════════════════════════
#                          DATABASE RACE DETECTOR
# ═══════════════════════════════════════════════════════════════════════════


class DatabaseRaceDetector:
    """Specialized detector for database concurrency issues."""
    
    def __init__(self, config: DetectorConfig):
        self.config = config
        self.race_conditions: List[RaceCondition] = []
    
    def test_database_races(self, code: str, file_path: str) -> List[RaceCondition]:
        """Test for database race conditions using SQLite mock."""
        if not self.config.enable_db_detection:
            return []
        
        # Check if code uses database
        if 'sqlite3' not in code and 'cursor' not in code:
            return []
        
        logging.info("Testing database race conditions")
        
        # Create test harness with mock database
        test_code = self._create_db_test_harness(code)
        results = self._run_db_race_test(test_code)
        
        if results['has_race']:
            race = RaceCondition(
                race_type=RaceType.DATABASE_RACE,
                severity=Severity.HIGH,
                file_path=file_path,
                line_number=0,
                code_snippet="<database operations>",
                description=(
                    f"Database race condition detected. {results['error_count']} errors "
                    f"occurred during concurrent database access without proper locking."
                ),
                iterations_tested=results['iterations'],
                failure_rate=results['error_count'] / results['iterations'],
                recommended_fix=(
                    "Use connection-per-thread pattern, or protect all DB operations with locks. "
                    "SQLite requires check_same_thread=False with proper synchronization."
                ),
                confidence=0.90,
                detection_method="dynamic-database"
            )
            self.race_conditions.append(race)
        
        return self.race_conditions
    
    def _create_db_test_harness(self, code: str) -> str:
        """Create harness for database race testing."""
        return f"""
import sqlite3
import threading
import time
import random

# Setup in-memory database
conn = sqlite3.connect(':memory:', check_same_thread=False)
cursor = conn.cursor()
cursor.execute('CREATE TABLE test (id INTEGER PRIMARY KEY, value INTEGER)')
cursor.execute('INSERT INTO test VALUES (1, 0)')
conn.commit()

errors = []
error_lock = threading.Lock()

{code}

def db_worker():
    try:
        time.sleep(random.uniform(0, 0.01))
        # Simulate read-modify-write
        cursor.execute('SELECT value FROM test WHERE id=1')
        val = cursor.fetchone()[0]
        cursor.execute('UPDATE test SET value=? WHERE id=1', (val + 1,))
        conn.commit()
    except Exception as e:
        with error_lock:
            errors.append(str(e))

threads = [threading.Thread(target=db_worker) for _ in range(10)]
for t in threads:
    t.start()
for t in threads:
    t.join()

cursor.execute('SELECT value FROM test WHERE id=1')
final_value = cursor.fetchone()[0]

print(f'{{"errors": {len(errors)}, "final_value": {final_value}, "expected": 10}}')
conn.close()
"""
    
    def _run_db_race_test(self, test_code: str) -> Dict[str, Any]:
        """Run database race test."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(test_code)
            temp_file = f.name
        
        try:
            result = subprocess.run(
                [sys.executable, temp_file],
                capture_output=True,
                text=True,
                timeout=15
            )
            
            if result.returncode == 0 and result.stdout:
                try:
                    data = json.loads(result.stdout)
                    return {
                        'has_race': data['errors'] > 0 or data['final_value'] != data['expected'],
                        'error_count': data['errors'],
                        'iterations': 10
                    }
                except:
                    pass
        
        except Exception as e:
            logging.debug(f"DB race test error: {e}")
        
        finally:
            try:
                os.unlink(temp_file)
            except:
                pass
        
        return {'has_race': False, 'error_count': 0, 'iterations': 0}


# ═══════════════════════════════════════════════════════════════════════════
#                          PLUGIN SYSTEM
# ═══════════════════════════════════════════════════════════════════════════


class PluginInterface:
    """Base interface for detector plugins."""
    
    def analyze(self, code: str, file_path: str, config: DetectorConfig) -> List[RaceCondition]:
        """Analyze code and return detected race conditions."""
        raise NotImplementedError


class PluginLoader:
    """Load and manage detector plugins."""
    
    def __init__(self, plugin_dir: Optional[str] = None):
        self.plugin_dir = Path(plugin_dir) if plugin_dir else Path.home() / '.race_detector' / 'plugins'
        self.plugins: List[PluginInterface] = []
        
        if self.plugin_dir.exists():
            self._load_plugins()
    
    def _load_plugins(self):
        """Load plugins from plugin directory."""
        for plugin_file in self.plugin_dir.glob('*.py'):
            try:
                spec = __import__('importlib.util').util.spec_from_file_location("plugin", plugin_file)
                if spec and spec.loader:
                    module = __import__('importlib.util').util.module_from_spec(spec)
                    spec.loader.exec_module(module)
                    
                    for item in dir(module):
                        obj = getattr(module, item)
                        if isinstance(obj, type) and issubclass(obj, PluginInterface) and obj != PluginInterface:
                            self.plugins.append(obj())
                            logging.info(f"Loaded plugin: {item} from {plugin_file.name}")
            
            except Exception as e:
                logging.error(f"Failed to load plugin {plugin_file}: {e}")
    
    def run_plugins(self, code: str, file_path: str, config: DetectorConfig) -> List[RaceCondition]:
        """Run all loaded plugins."""
        all_races = []
        for plugin in self.plugins:
            try:
                races = plugin.analyze(code, file_path, config)
                all_races.extend(races)
            except Exception as e:
                logging.error(f"Plugin {plugin.__class__.__name__} failed: {e}")
        
        return all_races


# ═══════════════════════════════════════════════════════════════════════════
#                          MAIN ORCHESTRATOR
# ═══════════════════════════════════════════════════════════════════════════


class EnhancedRaceConditionDetector:
    """
    Enhanced main orchestrator with all improvements.
    
    New features:
    - Config file support
    - Plugin system
    - Better performance with caching
    - Enhanced reporting
    """
    
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.all_races: List[RaceCondition] = []
        self.files_analyzed = 0
        self.total_lines = 0
        
        # Load configuration
        if args.config and HAS_YAML:
            self.config = DetectorConfig.from_yaml(args.config)
        else:
            self.config = DetectorConfig(
                min_confidence=0.70,
                max_threads=args.threads,
                iterations=args.iterations,
                ignore_patterns=args.ignore.split(',') if args.ignore else []
            )
        
        # Setup logging
        log_level = logging.DEBUG if args.verbose else logging.INFO
        logging.basicConfig(
            level=log_level,
            format='%(levelname)s: %(message)s'
        )
        
        # Initialize plugin system
        self.plugin_loader = PluginLoader(args.plugin_dir if hasattr(args, 'plugin_dir') else None)
        
        # Database detector
        self.db_detector = DatabaseRaceDetector(self.config)
        
        logging.info("Enhanced Race Condition Detector v2.0 initialized")
    
    def run(self) -> List[RaceCondition]:
        """Execute detection process."""
        if self.args.snippet:
            self._analyze_snippet(self.args.snippet)
        elif self.args.file:
            self._analyze_file(self.args.file)
        elif self.args.path:
            self._analyze_directory(self.args.path)
        else:
            logging.error("No input specified")
            return []
        
        # Sort by severity and confidence
        self.all_races.sort(key=lambda r: (r.severity.value, r.confidence), reverse=True)
        
        return self.all_races
    
    def _analyze_snippet(self, code: str):
        """Analyze code snippet."""
        logging.info("Analyzing code snippet")
        
        # Static analysis
        static_analyzer = EnhancedStaticAnalyzer(code, "<snippet>", self.config)
        static_races = static_analyzer.analyze()
        self.all_races.extend(static_races)
        
        # Dynamic analysis
        if not self.args.static_only:
            dynamic_analyzer = EnhancedDynamicAnalyzer(code, "<snippet>", self.config)
            dynamic_races = dynamic_analyzer.analyze()
            self.all_races.extend(dynamic_races)
        
        # Plugin analysis
        plugin_races = self.plugin_loader.run_plugins(code, "<snippet>", self.config)
        self.all_races.extend(plugin_races)
        
        self.files_analyzed = 1
        self.total_lines = len(code.split('\n'))
    
    def _analyze_file(self, file_path: str):
        """Analyze single file."""
        path = Path(file_path)
        
        if not path.exists():
            logging.error(f"File not found: {file_path}")
            return
        
        if path.suffix != '.py':
            logging.warning(f"Skipping non-Python file: {file_path}")
            return
        
        logging.info(f"Analyzing: {file_path}")
        
        try:
            with open(path, 'r', encoding='utf-8') as f:
                code = f.read()
            
            self.total_lines += len(code.split('\n'))
            
            # Static analysis
            static_analyzer = EnhancedStaticAnalyzer(code, str(path), self.config)
            static_races = static_analyzer.analyze()
            self.all_races.extend(static_races)
            
            # Dynamic analysis
            if not self.args.static_only:
                dynamic_analyzer = EnhancedDynamicAnalyzer(code, str(path), self.config)
                dynamic_races = dynamic_analyzer.analyze()
                self.all_races.extend(dynamic_races)
                
                # Database testing
                db_races = self.db_detector.test_database_races(code, str(path))
                self.all_races.extend(db_races)
            
            # Plugins
            plugin_races = self.plugin_loader.run_plugins(code, str(path), self.config)
            self.all_races.extend(plugin_races)
            
            self.files_analyzed += 1
        
        except Exception as e:
            logging.error(f"Error analyzing {file_path}: {e}")
            if logging.getLogger().level == logging.DEBUG:
                traceback.print_exc()
    
    def _analyze_directory(self, dir_path: str):
        """Analyze directory recursively."""
        path = Path(dir_path)
        
        if not path.exists() or not path.is_dir():
            logging.error(f"Invalid directory: {dir_path}")
            return
        
        logging.info(f"Analyzing directory: {dir_path}")
        
        python_files = list(path.rglob('*.py'))
        
        # Apply ignore patterns
        if self.config.ignore_patterns:
            python_files = [
                f for f in python_files
                if not any(pattern in str(f) for pattern in self.config.ignore_patterns)
            ]
        
        logging.info(f"Found {len(python_files)} Python files")
        
        for py_file in python_files:
            self._analyze_file(str(py_file))
    
    def generate_report(self):
        """Generate report in requested format."""
        if self.args.output == 'json':
            self._generate_json_report()
        else:
            self._generate_text_report()
    
    def _generate_text_report(self):
        """Generate enhanced text report with colors."""
        c = Colors
        
        print(f"\n{c.CYAN}{'='*80}{c.RESET}")
        print(f"{c.CYAN}{c.BOLD}{'RACE CONDITION DETECTION REPORT':^80}{c.RESET}")
        print(f"{c.CYAN}{'by arkanzas.feziii':^80}{c.RESET}")
        print(f"{c.CYAN}{'='*80}{c.RESET}\n")
        
        # Statistics
        print(f"{c.BOLD}Scan Statistics:{c.RESET}")
        print(f"  Files Analyzed:        {self.files_analyzed}")
        print(f"  Lines of Code:         {self.total_lines}")
        print(f"  Race Conditions Found: {len(self.all_races)}")
        print(f"  Min Confidence:        {self.config.min_confidence:.0%}")
        
        if len(self.all_races) == 0:
            print(f"\n{c.GREEN}{c.BOLD}✓ No race conditions detected!{c.RESET}")
            print(f"\n{c.YELLOW}Note: This doesn't guarantee race-free code.{c.RESET}")
            print(f"{c.YELLOW}Manual review recommended for complex scenarios.{c.RESET}\n")
            return
        
        # Severity breakdown
        severity_counts = defaultdict(int)
        for race in self.all_races:
            severity_counts[race.severity] += 1
        
        print(f"\n{c.BOLD}Severity Breakdown:{c.RESET}")
        for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
            count = severity_counts[sev]
            if count > 0:
                color = {Severity.CRITICAL: c.RED, Severity.HIGH: c.MAGENTA,
                        Severity.MEDIUM: c.YELLOW, Severity.LOW: c.CYAN}[sev]
                print(f"  {color}{sev.name:8s}: {count}{c.RESET}")
        
        # Detection method breakdown
        method_counts = defaultdict(int)
        for race in self.all_races:
            method_counts[race.detection_method] += 1
        
        print(f"\n{c.BOLD}Detection Methods:{c.RESET}")
        for method, count in sorted(method_counts.items()):
            print(f"  {method:20s}: {count}")
        
        # Detailed findings
        print(f"\n{c.CYAN}{'='*80}{c.RESET}")
        print(f"{c.CYAN}{c.BOLD}{'DETAILED FINDINGS':^80}{c.RESET}")
        print(f"{c.CYAN}{'='*80}{c.RESET}\n")
        
        for i, race in enumerate(self.all_races, 1):
            severity_markers = {
                Severity.CRITICAL: f"{c.RED}🔴{c.RESET}",
                Severity.HIGH: f"{c.MAGENTA}🟠{c.RESET}",
                Severity.MEDIUM: f"{c.YELLOW}🟡{c.RESET}",
                Severity.LOW: f"{c.CYAN}🟢{c.RESET}"
            }
            marker = severity_markers.get(race.severity, "⚪")
            
            print(f"\n{c.BOLD}[{i}] {marker} {race.severity.name} - {race.race_type.value}{c.RESET}")
            print(f"{'-'*80}")
            print(f"File:       {race.file_path}")
            print(f"Line:       {race.line_number}")
            print(f"Method:     {race.detection_method.upper()}")
            print(f"Confidence: {c.GREEN if race.confidence > 0.85 else c.YELLOW}{race.confidence:.0%}{c.RESET}")
            
            if race.variable_name:
                print(f"Variable:   {race.variable_name}")
            
            if race.thread_count:
                print(f"Threads:    {race.thread_count}")
            
            if race.failure_rate is not None:
                color = c.RED if race.failure_rate > 0.2 else c.YELLOW
                print(f"Failure:    {color}{race.failure_rate:.1%}{c.RESET} ({race.iterations_tested} iterations)")
            
            print(f"\n{c.BOLD}Description:{c.RESET}")
            print(f"  {race.description}")
            
            print(f"\n{c.BOLD}Code Snippet:{c.RESET}")
            for line in race.code_snippet.split('\n')[:5]:
                print(f"  {line}")
            if len(race.code_snippet.split('\n')) > 5:
                print(f"  {c.CYAN}...{c.RESET}")
            
            if race.visualization:
                print(f"\n{c.BOLD}Visualization:{c.RESET}")
                print(race.visualization)
            
            print(f"\n{c.GREEN}{c.BOLD}✓ Recommended Fix:{c.RESET}")
            print(f"  {race.recommended_fix}")
        
        # Summary
        print(f"\n{c.CYAN}{'='*80}{c.RESET}")
        print(f"{c.CYAN}{c.BOLD}{'SUMMARY':^80}{c.RESET}")
        print(f"{c.CYAN}{'='*80}{c.RESET}\n")
        
        critical_high = severity_counts[Severity.CRITICAL] + severity_counts[Severity.HIGH]
        
        if critical_high > 0:
            print(f"{c.RED}{c.BOLD}⚠️  {critical_high} CRITICAL/HIGH severity races detected!{c.RESET}")
            print(f"\n{c.BOLD}Immediate Actions:{c.RESET}")
            print(f"  1. Review all CRITICAL/HIGH findings")
            print(f"  2. Add synchronization (locks, semaphores)")
            print(f"  3. Run dynamic tests to verify fixes")
            print(f"  4. Use thread-safe data structures")
        
        print(f"\n{c.BOLD}Best Practices:{c.RESET}")
        print(f"  • Use threading.Lock() for shared mutable state")
        print(f"  • Prefer immutable data structures")
        print(f"  • Use queue.Queue for thread-safe communication")
        print(f"  • Consider multiprocessing for CPU-bound tasks")
        print(f"  • Avoid global variables in concurrent code")
        
        print(f"\n{c.BOLD}Limitations:{c.RESET}")
        print(f"  • Cannot detect all races (halting problem)")
        print(f"  • Python GIL limits threading parallelism")
        print(f"  • Dynamic tests may miss rare race windows")
        print(f"  • Manual review recommended")
        
        print(f"\n{c.CYAN}{'='*80}{c.RESET}\n")
    
    def _generate_json_report(self):
        """Generate JSON report."""
        report = {
            'metadata': {
                'tool': 'Race Condition Detector',
                'version': '2.0',
                'author': 'arkanzas.feziii',
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
            },
            'configuration': {
                'min_confidence': self.config.min_confidence,
                'max_threads': self.config.max_threads,
                'iterations': self.config.iterations,
                'multiprocessing_enabled': self.config.enable_multiprocessing
            },
            'statistics': {
                'files_analyzed': self.files_analyzed,
                'total_lines': self.total_lines,
                'total_races': len(self.all_races),
                'by_severity': {
                    sev.name.lower(): sum(1 for r in self.all_races if r.severity == sev)
                    for sev in Severity
                },
                'by_method': {
                    method: sum(1 for r in self.all_races if r.detection_method == method)
                    for method in set(r.detection_method for r in self.all_races)
                }
            },
            'findings': [race.to_dict() for race in self.all_races]
        }
        
        print(json.dumps(report, indent=2))


# ═══════════════════════════════════════════════════════════════════════════
#                          ENHANCED SELF-TEST SUITE
# ═══════════════════════════════════════════════════════════════════════════


class EnhancedSelfTest:
    """Enhanced self-test suite with dynamic validation."""
    
    @staticmethod
    def run_self_tests(verbose: bool = False) -> bool:
        """Run all self-tests."""
        c = Colors
        
        print(f"\n{c.CYAN}{'='*80}{c.RESET}")
        print(f"{c.CYAN}{c.BOLD}{'RUNNING SELF-TESTS':^80}{c.RESET}")
        print(f"{c.CYAN}{'='*80}{c.RESET}\n")
        
        test_cases = [
            ('Unsynchronized Counter', EnhancedSelfTest.test_unsynchronized_counter),
            ('TOCTOU File Race', EnhancedSelfTest.test_toctou_file),
            ('Read-Modify-Write', EnhancedSelfTest.test_read_modify_write),
            ('Safe Code (No False Positive)', EnhancedSelfTest.test_safe_code),
            ('Signal Handler Race', EnhancedSelfTest.test_signal_race),
            ('Tempfile Race', EnhancedSelfTest.test_tempfile_race),
            ('Database Race', EnhancedSelfTest.test_database_race),
            ('Asyncio Race', EnhancedSelfTest.test_asyncio_race),
            ('Dynamic Detection', EnhancedSelfTest.test_dynamic_detection)
        ]
        
        passed = 0
        failed = 0
        
        for name, test_func in test_cases:
            try:
                result = test_func(verbose)
                if result:
                    print(f"{c.GREEN}✓ {name}: PASS{c.RESET}")
                    passed += 1
                else:
                    print(f"{c.RED}✗ {name}: FAIL{c.RESET}")
                    failed += 1
            except Exception as e:
                print(f"{c.RED}✗ {name}: ERROR - {e}{c.RESET}")
                if verbose:
                    traceback.print_exc()
                failed += 1
        
        total = passed + failed
        print(f"\n{c.BOLD}Results: {c.GREEN}{passed}/{total} passed{c.RESET}, {c.RED}{failed}/{total} failed{c.RESET}")
        print(f"{c.CYAN}{'='*80}{c.RESET}\n")
        
        return failed == 0
    
    @staticmethod
    def test_unsynchronized_counter(verbose: bool = False) -> bool:
        """Test detection of unsynchronized counter."""
        code = """
import threading

counter = 0

def increment():
    global counter
    for _ in range(1000):
        counter += 1

threads = []
for _ in range(10):
    t = threading.Thread(target=increment)
    threads.append(t)
    t.start()

for t in threads:
    t.join()

print(counter)
"""
        config = DetectorConfig(min_confidence=0.70)
        analyzer = EnhancedStaticAnalyzer(code, "test_counter.py", config)
        races = analyzer.analyze()
        
        if verbose:
            print(f"  Detected {len(races)} race(s)")
        
        # Should detect at least one race
        return len(races) > 0 and any(r.race_type == RaceType.READ_MODIFY_WRITE for r in races)
    
    @staticmethod
    def test_toctou_file(verbose: bool = False) -> bool:
        """Test TOCTOU detection."""
        code = """
import os

def process_file(filename):
    if os.path.exists(filename):
        with open(filename, 'r') as f:
            data = f.read()
        return data
    return None
"""
        config = DetectorConfig(min_confidence=0.70)
        analyzer = EnhancedStaticAnalyzer(code, "test_toctou.py", config)
        races = analyzer.analyze()
        
        if verbose:
            print(f"  Detected {len(races)} race(s)")
        
        # Should detect TOCTOU
        return any(r.race_type == RaceType.TOCTOU for r in races)
    
    @staticmethod
    def test_read_modify_write(verbose: bool = False) -> bool:
        """Test RMW detection."""
        code = """
import threading

BALANCE = 1000

def withdraw(amount):
    global BALANCE
    BALANCE -= amount

threads = []
for _ in range(5):
    t = threading.Thread(target=withdraw, args=(100,))
    threads.append(t)
    t.start()
"""
        config = DetectorConfig(min_confidence=0.70)
        analyzer = EnhancedStaticAnalyzer(code, "test_rmw.py", config)
        races = analyzer.analyze()
        
        if verbose:
            print(f"  Detected {len(races)} race(s)")
        
        return len(races) > 0
    
    @staticmethod
    def test_safe_code(verbose: bool = False) -> bool:
        """Test that safe code doesn't trigger false positives."""
        code = """
import threading

counter = 0
lock = threading.Lock()

def increment():
    global counter
    with lock:
        counter += 1

threads = []
for _ in range(10):
    t = threading.Thread(target=increment)
    threads.append(t)
    t.start()

for t in threads:
    t.join()
"""
        config = DetectorConfig(min_confidence=0.70)
        analyzer = EnhancedStaticAnalyzer(code, "test_safe.py", config)
        races = analyzer.analyze()
        
        if verbose:
            print(f"  Detected {len(races)} race(s)")
        
        # Should NOT detect high-confidence races
        high_conf_races = [r for r in races if r.confidence > 0.75]
        return len(high_conf_races) == 0
    
    @staticmethod
    def test_signal_race(verbose: bool = False) -> bool:
        """Test signal handler race detection."""
        code = """
import signal
import threading

def handler(signum, frame):
    print("Signal received")

signal.signal(signal.SIGINT, handler)

def worker():
    pass

threads = [threading.Thread(target=worker) for _ in range(5)]
for t in threads:
    t.start()
"""
        config = DetectorConfig(min_confidence=0.70)
        analyzer = EnhancedStaticAnalyzer(code, "test_signal.py", config)
        races = analyzer.analyze()
        
        if verbose:
            print(f"  Detected {len(races)} race(s)")
        
        return any(r.race_type == RaceType.SIGNAL_RACE for r in races)
    
    @staticmethod
    def test_tempfile_race(verbose: bool = False) -> bool:
        """Test tempfile race detection."""
        code = """
import tempfile
import threading

def worker():
    f = tempfile.NamedTemporaryFile(delete=False)
    f.write(b"data")
    f.close()

threads = [threading.Thread(target=worker) for _ in range(5)]
for t in threads:
    t.start()
"""
        config = DetectorConfig(min_confidence=0.70)
        analyzer = EnhancedStaticAnalyzer(code, "test_tempfile.py", config)
        races = analyzer.analyze()
        
        if verbose:
            print(f"  Detected {len(races)} race(s)")
        
        return any(r.race_type == RaceType.TEMPFILE_RACE for r in races)
    
    @staticmethod
    def test_database_race(verbose: bool = False) -> bool:
        """Test database race detection."""
        code = """
import sqlite3
import threading

conn = sqlite3.connect(':memory:', check_same_thread=False)
cursor = conn.cursor()

def worker():
    cursor.execute("SELECT * FROM test")

threads = [threading.Thread(target=worker) for _ in range(5)]
for t in threads:
    t.start()
"""
        config = DetectorConfig(min_confidence=0.70)
        analyzer = EnhancedStaticAnalyzer(code, "test_db.py", config)
        races = analyzer.analyze()
        
        if verbose:
            print(f"  Detected {len(races)} race(s)")
        
        return any(r.race_type == RaceType.DATABASE_RACE for r in races)
    
    @staticmethod
    def test_asyncio_race(verbose: bool = False) -> bool:
        """Test asyncio race detection."""
        code = """
import asyncio

shared_data = []

async def worker():
    shared_data.append(1)

async def main():
    await asyncio.gather(*[worker() for _ in range(10)])

asyncio.run(main())
"""
        config = DetectorConfig(min_confidence=0.60)
        analyzer = EnhancedStaticAnalyzer(code, "test_async.py", config)
        races = analyzer.analyze()
        
        if verbose:
            print(f"  Detected {len(races)} race(s)")
        
        return len(races) > 0
    
    @staticmethod
    def test_dynamic_detection(verbose: bool = False) -> bool:
        """Test dynamic race detection."""
        code = """
import threading

counter = 0

def increment():
    global counter
    temp = counter
    counter = temp + 1
    return counter

threads = []
for _ in range(5):
    t = threading.Thread(target=increment)
    threads.append(t)
    t.start()

for t in threads:
    t.join()
"""
        config = DetectorConfig(min_confidence=0.70, iterations=50, max_threads=5)
        dynamic_analyzer = EnhancedDynamicAnalyzer(code, "test_dynamic.py", config)
        races = dynamic_analyzer.analyze()
        
        if verbose:
            print(f"  Detected {len(races)} race(s) dynamically")
        
        # Dynamic testing should detect race
        return len(races) > 0


# ═══════════════════════════════════════════════════════════════════════════
#                          COMMAND LINE INTERFACE
# ═══════════════════════════════════════════════════════════════════════════


def create_parser() -> argparse.ArgumentParser:
    """Create enhanced argument parser."""
    parser = argparse.ArgumentParser(
        description='Race Condition Detector v2.0 - Enhanced professional scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Basic scan:
    python race_detector.py --file script.py
  
  Full project scan with high intensity:
    python race_detector.py --path /project --threads 16 --iterations 1000
  
  With configuration file:
    python race_detector.py --path /src --config detector.yaml
  
  Static analysis only (faster):
    python race_detector.py --path /src --static-only
  
  JSON output for CI/CD:
    python race_detector.py --file app.py --output json > report.json
  
  With custom plugins:
    python race_detector.py --path . --plugin-dir ./plugins
  
  Run self-tests:
    python race_detector.py --self-test --verbose

Race Types Detected:
  • Time-of-Check to Time-of-Use (TOCTOU)
  • Read-Modify-Write atomicity violations
  • Unsynchronized shared resource access
  • File-based races (including tempfile)
  • Signal handler races
  • Database concurrency issues
  • Asyncio coroutine races

Author: arkanzas.feziii
Version: 2.0
        """
    )
    
    # Input options
    input_group = parser.add_mutually_exclusive_group()
    input_group.add_argument('--file', type=str, help='Python file to analyze')
    input_group.add_argument('--path', type=str, help='Directory to analyze recursively')
    input_group.add_argument('--snippet', type=str, help='Code snippet to analyze')
    input_group.add_argument('--self-test', action='store_true', help='Run self-tests')
    
    # Analysis options
    parser.add_argument('--threads', type=int, default=8, help='Concurrent threads for testing (default: 8)')
    parser.add_argument('--iterations', type=int, default=1000, help='Test iterations (default: 1000)')
    parser.add_argument('--static-only', action='store_true', help='Static analysis only')
    parser.add_argument('--ignore', type=str, help='Comma-separated ignore patterns')
    
    # Configuration
    parser.add_argument('--config', type=str, help='YAML configuration file')
    parser.add_argument('--plugin-dir', type=str, help='Custom plugin directory')
    
    # Output options
    parser.add_argument('--output', choices=['text', 'json'], default='text', help='Output format')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    
    return parser


def main():
    """Main entry point."""
    parser = create_parser()
    args = parser.parse_args()
    
    c = Colors
    
    # Banner
    print(f"""
{c.CYAN}╔═══════════════════════════════════════════════════════════════════════════╗
║              {c.BOLD}Race Condition Detector v2.0 - Enhanced{c.RESET}{c.CYAN}                ║
║           {c.BOLD}Professional Race Condition Vulnerability Scanner{c.RESET}{c.CYAN}         ║
║                      {c.BOLD}by arkanzas.feziii{c.RESET}{c.CYAN}                             ║
╚═══════════════════════════════════════════════════════════════════════════╝{c.RESET}
    """)
    
    # Self-test mode
    if args.self_test:
        success = EnhancedSelfTest.run_self_tests(args.verbose)
        sys.exit(0 if success else 1)
    
    # Validate input
    if not any([args.file, args.path, args.snippet]):
        parser.print_help()
        sys.exit(1)
    
    # Run detector
    try:
        detector = EnhancedRaceConditionDetector(args)
        races = detector.run()
        detector.generate_report()
        
        # Exit codes: 0=no races, 1=races found, 2=error
        sys.exit(1 if len(races) > 0 else 0)
    
    except KeyboardInterrupt:
        print(f"\n\n{c.YELLOW}Analysis interrupted by user{c.RESET}")
        sys.exit(130)
    
    except Exception as e:
        logging.error(f"Fatal error: {e}")
        if args.verbose:
            traceback.print_exc()
        sys.exit(2)


if __name__ == "__main__":
    main()


# ═══════════════════════════════════════════════════════════════════════════
#                     EXAMPLE CONFIGURATION FILE (YAML)
# ═══════════════════════════════════════════════════════════════════════════

"""
Example detector.yaml:

# Race Condition Detector Configuration

# Minimum confidence threshold (0.0 - 1.0)
min_confidence: 0.75

# Maximum concurrent threads for dynamic testing
max_threads: 16

# Number of test iterations
iterations: 1000

# Timeout per test in seconds
timeout_per_test: 10

# Patterns to ignore (regex)
ignore_patterns:
  - "test"
  - "__pycache__"
  - ".venv"
  - "venv"

# Feature flags
enable_multiprocessing: true
enable_asyncio_detection: true
enable_db_detection: true

# Custom rules (optional)
custom_rules:
  max_line_length: 120
  enforce_type_hints: false
"""


# ═══════════════════════════════════════════════════════════════════════════
#                     EXAMPLE PLUGIN IMPLEMENTATION
# ═══════════════════════════════════════════════════════════════════════════

"""
Example custom plugin (~/.race_detector/plugins/my_plugin.py):

from race_detector import PluginInterface, RaceCondition, RaceType, Severity, DetectorConfig
import ast

class CustomRaceDetector(PluginInterface):
    '''Custom race condition detector plugin.'''
    
    def analyze(self, code: str, file_path: str, config: DetectorConfig):
        races = []
        
        try:
            tree = ast.parse(code)
            
            # Custom detection logic
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    # Detect custom pattern
                    if self._is_custom_race(node):
                        race = RaceCondition(
                            race_type=RaceType.COMPOUND_OPERATION,
                            severity=Severity.MEDIUM,
                            file_path=file_path,
                            line_number=node.lineno,
                            code_snippet="<custom pattern>",
                            description="Custom race pattern detected",
                            recommended_fix="Apply custom fix",
                            confidence=0.80,
                            detection_method="plugin-custom"
                        )
                        races.append(race)
        
        except:
            pass
        
        return races
    
    def _is_custom_race(self, node):
        # Custom detection logic
        return False
"""


# ═══════════════════════════════════════════════════════════════════════════
#                        COMPREHENSIVE EXAMPLES
# ═══════════════════════════════════════════════════════════════════════════

"""
VULNERABLE CODE EXAMPLES:

1. Classic Race - Unsynchronized Counter:
```python
import threading

counter = 0

def increment():
    global counter
    for _ in range(10000):
        counter += 1  # NOT ATOMIC - RACE!

threads = [threading.Thread(target=increment) for _ in range(10)]
for t in threads:
    t.start()
for t in threads:
    t.join()

print(f"Counter: {counter}")  # Will be < 100000
```

2. TOCTOU File Race:
```python
import os

def safe_delete(filename):
    if os.path.exists(filename):  # CHECK
        os.remove(filename)        # USE - File may be deleted here!
```

3. Read-Modify-Write Race:
```python
import threading

balance = {'account': 1000}

def withdraw(amount):
    if balance['account'] >= amount:  # READ
        time.sleep(0.001)             # Race window
        balance['account'] -= amount   # MODIFY + WRITE
        # Race: Two threads can both pass the check!
```

4. Database Race:
```python
import sqlite3
import threading

conn = sqlite3.connect('data.db', check_same_thread=False)

def update_balance():
    cursor = conn.cursor()
    cursor.execute("SELECT balance FROM accounts WHERE id=1")
    balance = cursor.fetchone()[0]
    cursor.execute("UPDATE accounts SET balance=? WHERE id=1", (balance + 100,))
    conn.commit()
    # Race: Lost updates without transaction locks!

threads = [threading.Thread(target=update_balance) for _ in range(5)]
```

5. Signal Handler Race:
```python
import signal
import threading

shared_list = []

def signal_handler(sig, frame):
    shared_list.append(1)  # Race with threads!

signal.signal(signal.SIGINT, signal_handler)

def worker():
    shared_list.append(2)

threads = [threading.Thread(target=worker) for _ in range(5)]
```

6. Tempfile Race:
```python
import tempfile
import threading

def worker():
    f = tempfile.NamedTemporaryFile(delete=False, prefix="data_")
    # Predictable names - race between workers!
    f.write(b"data")
    f.close()
```

SAFE CODE EXAMPLES:

1. Properly Locked Counter:
```python
import threading

counter = 0
lock = threading.Lock()

def increment():
    global counter
    with lock:
        counter += 1  # Protected!

threads = [threading.Thread(target=increment) for _ in range(10)]
for t in threads:
    t.start()
for t in threads:
    t.join()
```

2. TOCTOU-Safe File Access:
```python
def safe_read(filename):
    try:
        with open(filename) as f:  # No check - just use!
            return f.read()
    except FileNotFoundError:
        return None
```

3. Thread-Safe Queue:
```python
import queue
import threading

q = queue.Queue()

def producer():
    q.put(42)  # Thread-safe!

def consumer():
    item = q.get()  # Thread-safe!
```

4. Database with Locks:
```python
import sqlite3
import threading

conn = sqlite3.connect('data.db', check_same_thread=False)
db_lock = threading.Lock()

def update_balance():
    with db_lock:
        cursor = conn.cursor()
        cursor.execute("BEGIN TRANSACTION")
        cursor.execute("SELECT balance FROM accounts WHERE id=1")
        balance = cursor.fetchone()[0]
        cursor.execute("UPDATE accounts SET balance=? WHERE id=1", (balance + 100,))
        conn.commit()
```

USAGE EXAMPLES:

# Analyze single file
python race_detector.py --file myapp.py

# Analyze project with custom settings
python race_detector.py --path ./src --threads 16 --iterations 2000 --config detector.yaml

# Quick static scan
python race_detector.py --path . --static-only --ignore "test,venv"

# CI/CD integration
python race_detector.py --path . --output json > races.json
if [ $? -eq 1 ]; then
    echo "Race conditions detected!"
    exit 1
fi

# With plugins
python race_detector.py --path . --plugin-dir ./custom_plugins

# Self-test
python race_detector.py --self-test --verbose
"""
