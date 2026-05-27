from backend.core.product_capabilities import list_product_capabilities


def test_product_capabilities_track_all_fourteen_product_areas():
    payload = list_product_capabilities()
    capabilities = payload["capabilities"]

    assert payload["summary"]["total"] == 14
    assert len(capabilities) == 14
    assert {item["id"] for item in capabilities} >= {
        "recon-engine",
        "web-vulnerability-coverage",
        "validation-engine",
        "ai-assisted-features",
    }
    assert all(item["next_tasks"] for item in capabilities)
