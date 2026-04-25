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

    def _read_payloads(self, filename: str) -> list[str]:
        path = PAYLOAD_DIR / filename
        return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
