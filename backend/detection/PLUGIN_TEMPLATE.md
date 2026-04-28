# Detector Plugin Template

Create a detector by adding a Python class that inherits `BaseDetector`, then register it in `backend/detection/detectors.json`.

```python
from backend.detection.base_detector import BaseDetector, Finding


class ExampleDetector(BaseDetector):
    name = "example"

    async def detect(self, target_url, site_map, request_handler):
        return []
```

Registry entry:

```json
{
  "name": "example",
  "module": "backend.detection.example_detector",
  "class": "ExampleDetector",
  "enabled": true,
  "category": "custom",
  "description": "Describe what this detector validates.",
  "supports": ["query", "form", "api"]
}
```

Plugin safety requirements:

- Only scan authorized targets.
- Respect rate limits and scan profiles.
- Return evidence, confidence, and remediation guidance for every finding.
- Avoid destructive payloads and denial-of-service behavior.
