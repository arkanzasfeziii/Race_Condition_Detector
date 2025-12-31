# Custom Plugins

Place your `.py` plugin files here.

Each plugin must:
- Inherit from `PluginInterface`
- Implement `analyze(code, file_path, config) -> List[RaceCondition]`

Example:

```python
from race_detector import PluginInterface, RaceCondition, RaceType, Severity, DetectorConfig

class MyPlugin(PluginInterface):
    def analyze(self, code, file_path, config):
        # Your custom logic
        return []
```
Run with:
```
python race_detector.py --path . --plugin-dir ./plugins
```
