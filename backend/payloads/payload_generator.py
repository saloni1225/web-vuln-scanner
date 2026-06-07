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
                f"<img src=x onerror=\"window.__awvs='{marker}'\">",
            ],
            "attribute": [
                f'" data-xss="{marker}"',
                f"' data-xss='{marker}'",
                f'" autofocus onfocus="window.__awvs=\'{marker}\'"',
                f"' autofocus onfocus='window.__awvs=\"{marker}\"'",
            ],
            "json": [
                marker,
                f'{{"awvs":"{marker}"}}',
                f'["{marker}"]',
            ],
            "script": [
                f"';window.__awvs='{marker}';//",
                f'";window.__awvs="{marker}";//',
                f"\\x3cscript\\x3ewindow.__awvs='{marker}'\\x3c/script\\x3e",
            ],
            "template_literal": [
                f"${{window.__awvs='{marker}'}}",
            ],
            "href_javascript": [
                f"javascript:window.__awvs='{marker}'",
            ],
            "csp_bypass": [
                f"<base href=\"javascript:window.__awvs='{marker}'//\">",
            ]
        }

    def graphql_probe_bodies(self, marker: str) -> list[dict[str, str]]:
        return [
            {"query": f'query AWVS {{ __typename search(q: "{marker}") }}'},
            {"query": f'mutation AWVS {{ __typename }}', "variables": f'{{"marker":"{marker}"}}'},
        ]

    def nosql_payloads(self) -> list[str]:
        return self._read_payloads("nosql_payloads.txt")

    def ssti_payloads(self) -> list[str]:
        return self._read_payloads("ssti_payloads.txt")

    def xxe_payloads(self) -> list[str]:
        return self._read_payloads("xxe_payloads.txt")

    def rce_payloads(self) -> list[str]:
        return self._read_payloads("rce_payloads.txt")

    def ssrf_payloads(self) -> list[str]:
        return self._read_payloads("ssrf_payloads.txt")

    def _read_payloads(self, filename: str) -> list[str]:
        path = PAYLOAD_DIR / filename
        return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
