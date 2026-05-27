import asyncio

from backend.detection.advanced_surface_detector import AdvancedSurfaceDetector


def test_advanced_surface_detector_flags_reviewable_surfaces():
    detector = AdvancedSurfaceDetector()
    findings = asyncio.run(
        detector.detect(
            "https://example.com",
            {
                "endpoints": [
                    {"url": "https://example.com/graphql", "type": "graphql"},
                    {"url": "https://example.com/openapi.json", "type": "schema"},
                    {"url": "https://example.com/admin", "type": "page"},
                    {"url": "https://example.com/upload", "type": "api"},
                ],
                "forms": [{"action": "https://example.com/login", "fields": ["email", "password"]}],
            },
            request_handler=None,
        )
    )

    categories = {finding.category for finding in findings}
    assert {"api", "authorization", "server-side", "auth"}.issubset(categories)
    assert all(finding.validation_state == "requires-review" for finding in findings)
