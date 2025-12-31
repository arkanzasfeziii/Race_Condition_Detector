# Race Condition Detector (v2.0)

> 🔍 **Professional Static & Dynamic Race Condition Vulnerability Scanner for Python**

Detect concurrency bugs like **Time-of-Check to Time-of-Use (TOCTOU)**, **Read-Modify-Write violations**, **Unsynchronized Shared State**, **Signal Handler Races**, **Database Concurrency Issues**, and more — **before they hit production**.

Built for security researchers, code auditors, and developers who care about **thread-safe**, **race-free** Python applications.

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python)
![License](https://img.shields.io/badge/License-MIT-green)
…
```
git clone https://github.com/your-username/race-condition-detector.git
cd race-condition-detector
pip install -r requirements.txt
```

✅ Works on Linux, macOS, and Windows with Python 3.8+.

▶️ Quick Start

Scan a single file:
```
python race_detector.py --file vulnerable_app.py
```
Scan a whole project:
```
python race_detector.py --path ./my_project --threads 16 --iterations 1000
```
Use config file:
```
python race_detector.py --path ./src --config detector.yaml
```
JSON output (for CI/CD):
```
python race_detector.py --file app.py --output json > report.json
```
Run built-in self-tests:
```
python race_detector.py --self-test --verbose
```

🧾 Supported Race Types
```
+--------------------------------------+----------------------------------------------------------+
| Race Type                            | Description                                              |
+--------------------------------------+----------------------------------------------------------+
| Time-of-Check to Time-of-Use (TOCTOU)| File check followed by use — state may change in between |
| Read-Modify-Write Atomicity Violation| Non-atomic operations like `x += 1` on shared variables  |
| Unsynchronized Shared Resource Access | Shared state accessed without locks                     |
| File-Based Race Condition            | Unsafe concurrent file operations                       |
| Signal Handler Race                  | Signal handlers interacting with threads                 |
| Non-Atomic Compound Operation        | Multi-step logic without atomicity                      |
| Concurrent Global Variable Access    | Global vars used across threads without protection      |
| Database Concurrency Issue           | SQLite or DB ops without proper thread safety           |
| Asyncio Coroutine Race Condition     | Shared state in async coroutines without `asyncio.Lock` |
| Temporary File Race                  | Predictable temp files (`delete=False`) in concurrency  |
+--------------------------------------+----------------------------------------------------------+
```

🛠️ Configuration (detector.yaml)
Example config:
```
min_confidence: 0.75
max_threads: 16
iterations: 1000
timeout_per_test: 10
ignore_patterns:
  - "test"
  - "__pycache__"
  - "venv"
enable_multiprocessing: true
enable_asyncio_detection: true
enable_db_detection: true
```
Pass it with --config detector.yaml.

🧩 Plugins
Extend functionality with custom plugins:
```
# ~/.race_detector/plugins/custom_rule.py
from race_detector import PluginInterface, RaceCondition, RaceType, Severity

class MyCustomDetector(PluginInterface):
    def analyze(self, code, file_path, config):
        # Your logic here
        return [RaceCondition(...)]
```
Enable plugin directory:
```
python race_detector.py --path . --plugin-dir ./plugins
```

🧪 Example Output
```
[1] 🟠 HIGH - Time-of-Check to Time-of-Use
File:       app.py
Line:       12
Method:     STATIC
Confidence: 88%
Description: File check at line 12 followed by operation at line 14...
Code Snippet:
  if os.path.exists(filename):
      with open(filename) as f:

Visualization:
Thread A                    Thread B
|                           |
| Check file (line 12)      |
|                           |
|                           | Delete file
|                           |
| Use file (line 14)        | ← RACE WINDOW
```
📚 Best Practices
Always protect shared mutable state with threading.Lock()
Avoid global variables in threaded code
Use queue.Queue for safe inter-thread communication
Prefer try: open() over os.path.exists()
Use connection-per-thread for SQLite
Never mix signals + threads
⚠️ Note: Due to the halting problem, no tool can guarantee 100% race-free code. Always combine with manual review.

📜 License
MIT License — see LICENSE for details.

Author: arkanzas.feziii

💡 Contributing
Contributions welcome!
Please open an issue or PR for:

New race patterns
Plugin examples
Performance improvements
False-positive reductions

✨ Happy race hunting!
