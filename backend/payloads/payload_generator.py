from pathlib import Path


PAYLOAD_DIR = Path(__file__).resolve().parent


class PayloadGenerator:
    def sqli_payloads(self) -> list[str]:
        return self._read_payloads("sqli_payloads.txt")

    def xss_payloads(self) -> list[str]:
        return self._read_payloads("xss_payloads.txt")

    def xss_probe_payloads(self, marker: str) -> list[str]:
        return [
            marker,
            f'"{marker}"',
            f"<script>{marker}</script>",
            f'"><svg data-xss="{marker}"></svg>',
            f"<img src=x alt='{marker}'>",
        ]

    def xss_contextual_payloads(self, marker: str) -> dict[str, list[str]]:
        return {
            "html": [
                marker,
                f"<div>{marker}</div>",
                f"<script>window.__awvs='{marker}'</script>",
            ],
            "attribute": [
                f'" data-xss="{marker}"',
                f"' data-xss='{marker}'",
                f'" autofocus onfocus="window.__awvs=\'{marker}\'"',
            ],
            "json": [
                marker,
                f'{{"awvs":"{marker}"}}',
                f'["{marker}"]',
            ],
            "script": [
                f"';window.__awvs='{marker}';//",
                f'";window.__awvs="{marker}";//',
            ],
        }

    def graphql_probe_bodies(self, marker: str) -> list[dict[str, str]]:
        return [
            {"query": f'query AWVS {{ __typename search(q: "{marker}") }}'},
            {"query": f'mutation AWVS {{ __typename }}', "variables": f'{{"marker":"{marker}"}}'},
        ]

    def _read_payloads(self, filename: str) -> list[str]:
        path = PAYLOAD_DIR / filename
        return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
