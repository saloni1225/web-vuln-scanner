"""Advanced Cloud Exposure Detector — Cloud infra misconfiguration scanning.

CWE-200/CWE-16 · OWASP A05:2021
"""
from __future__ import annotations
from urllib.parse import urlparse
from backend.core.request_handler import RequestHandler
from backend.core.response_analyzer import ResponseAnalyzer
from backend.detection.base_detector import BaseDetector, Finding

_CLOUD_META_ENDPOINTS = [
    ("http://169.254.169.254/latest/meta-data/", "ami-id", "AWS IMDS"),
    ("http://169.254.169.254/latest/meta-data/iam/security-credentials/", "access", "AWS IAM Creds"),
    ("http://metadata.google.internal/computeMetadata/v1/", "attributes", "GCP Metadata"),
    ("http://169.254.169.254/metadata/instance?api-version=2021-02-01", "compute", "Azure IMDS"),
]

_SENSITIVE_PATHS = [
    ("/.env", ["DB_PASSWORD", "SECRET_KEY", "API_KEY", "AWS_", "DATABASE_URL"], ".env file"),
    ("/.git/config", ["[core]", "[remote", "url ="], "Git config"),
    ("/wp-config.php", ["DB_NAME", "DB_USER", "DB_PASSWORD"], "WordPress config"),
    ("/application.yml", ["spring:", "datasource:", "password:"], "Spring config"),
    ("/config.json", ['"password"', '"secret"', '"apiKey"'], "Config JSON"),
    ("/.aws/credentials", ["aws_access_key_id", "aws_secret_access_key"], "AWS credentials"),
    ("/server-status", ["Apache Server Status", "Server Version"], "Apache status"),
    ("/debug", ["DEBUG", "Traceback", "settings"], "Debug endpoint"),
    ("/.dockerenv", [], "Docker environment"),
    ("/api/v1/configmaps", ["apiVersion", "kind"], "K8s configmaps"),
]

_ENV_LEAK_PATTERNS = [
    "AKIA",  # AWS Access Key
    "aws_secret_access_key",
    "AZURE_CLIENT_SECRET",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "DATABASE_URL=",
    "REDIS_URL=",
    "SECRET_KEY=",
    "private_key",
]

_CLOUD_STORAGE_PATTERNS = [
    (".s3.amazonaws.com", "AWS S3"),
    (".s3-", "AWS S3 Regional"),
    ("storage.googleapis.com", "Google Cloud Storage"),
    (".blob.core.windows.net", "Azure Blob"),
    (".r2.cloudflarestorage.com", "Cloudflare R2"),
]


class CloudExposureDetector(BaseDetector):
    name = "cloud_exposure"

    async def detect(self, target_url: str, site_map: dict[str, object], request_handler: RequestHandler) -> list[Finding]:
        analyzer = ResponseAnalyzer()
        findings: list[Finding] = []
        parsed = urlparse(target_url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        max_params = int(site_map.get("max_detector_params", 6) or 6)
        tested = 0

        # Test 1: Sensitive file exposure
        for path, sigs, label in _SENSITIVE_PATHS:
            if tested >= max_params:
                break
            tested += 1
            f = await self._probe_path(request_handler, analyzer, base, path, sigs, label)
            if f:
                findings.append(f)

        # Test 2: Scan crawled pages for env variable leaks
        for page in list(site_map.get("pages", []))[:5]:
            try:
                resp = await request_handler.get(str(page))
                leaked = [p for p in _ENV_LEAK_PATTERNS if p in resp.text]
                if leaked:
                    v = analyzer.classify_confidence(error_signature=True, anomaly_score=0.7)
                    findings.append(Finding(
                        detector=self.name, severity="high", url=str(page),
                        evidence=f"Environment variable leak detected: {', '.join(leaked[:5])}",
                        recommendation="Remove sensitive data from responses. Use env injection at runtime, not hardcoded values.",
                        confidence=str(v["confidence"]), confidence_score=float(v["confidence_score"]),
                        validation_signals=list(v["signals"]), parameter=None, payload="env-leak",
                        method="get", category="cloud-env-leak", baseline_status=200,
                        mutated_status=resp.status_code, baseline_length=0, mutated_length=len(resp.text),
                        request_snapshot=f"GET {page}",
                        response_snapshot=analyzer.snapshot_response(resp),
                        reason="Sensitive env patterns found in response.", validation_state=str(v["validation_state"]),
                    ))
            except Exception:
                continue

        # Test 3: Cloud storage references in crawled content
        all_text = " ".join(str(p) for p in site_map.get("pages", []))
        for pattern, provider in _CLOUD_STORAGE_PATTERNS:
            if pattern in all_text.lower():
                findings.append(Finding(
                    detector=self.name, severity="low", url=target_url,
                    evidence=f"Cloud storage reference ({provider}) found in crawled URLs.",
                    recommendation="Ensure cloud storage buckets have proper access controls. Disable public listing.",
                    confidence="medium", parameter=None, payload=provider,
                    method="get", category="cloud-storage-reference",
                    baseline_status=200, mutated_status=200, baseline_length=0, mutated_length=0,
                    request_snapshot="Passive analysis of crawled URLs",
                    response_snapshot="", reason=f"{provider} URL pattern detected.", validation_state="requires-review",
                ))

        return self._dedupe(findings)

    async def _probe_path(self, rh, analyzer, base, path, sigs, label):
        url = f"{base}{path}"
        try:
            resp = await rh.get(url)
        except Exception:
            return None

        if resp.status_code != 200:
            return None

        body = resp.text
        if sigs:
            matched = [s for s in sigs if s.lower() in body.lower()]
            if not matched:
                return None
        elif len(body.strip()) < 5:
            return None

        v = analyzer.classify_confidence(error_signature=True, anomaly_score=0.75)
        return Finding(
            detector=self.name, severity="high", url=url,
            evidence=f"Sensitive file exposed: {label} at {path}." + (f" Matched: {', '.join(sigs[:3])}" if sigs else ""),
            recommendation=f"Block access to {path} via web server config. Remove sensitive files from document root.",
            confidence=str(v["confidence"]), confidence_score=float(v["confidence_score"]),
            validation_signals=list(v["signals"]), parameter=None, payload=path,
            method="get", category="cloud-sensitive-file", baseline_status=200,
            mutated_status=resp.status_code, baseline_length=0, mutated_length=len(body),
            request_snapshot=f"GET {url}",
            response_snapshot=analyzer.snapshot_response(resp),
            reason=f"Sensitive file '{label}' publicly accessible.", validation_state=str(v["validation_state"]),
        )

    @staticmethod
    def _dedupe(findings):
        seen, out = set(), []
        for f in findings:
            k = (f.url, f.category)
            if k not in seen:
                seen.add(k)
                out.append(f)
        return out
