from scripts.benchmark_detectors import BENCHMARK_TARGETS


def test_benchmark_targets_define_profiles_and_urls():
    assert "juice-shop" in BENCHMARK_TARGETS
    for target in BENCHMARK_TARGETS.values():
        assert target["url"].startswith("http")
        assert target["profile"] in {"quick", "deep", "api", "passive", "stealth", "authenticated"}
