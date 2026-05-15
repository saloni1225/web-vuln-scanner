const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? "http://127.0.0.1:8000/api";

export async function startScan(targetUrl, options = {}) {
  let response;
  try {
    response = await fetch(`${API_BASE_URL}/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        target_url: targetUrl,
        auth_headers: options.headers ?? {},
        auth_cookies: options.cookies ?? {},
        jwt_token: options.jwtToken ?? "",
        login_url: options.loginUrl || null,
        login_method: options.loginMethod ?? "post",
        username_field: options.usernameField ?? "email",
        password_field: options.passwordField ?? "password",
        username: options.username ?? "",
        password: options.password ?? "",
        role_name: options.roleName ?? "default",
        login_extra_fields: options.loginExtraFields ?? {},
        rate_limit_per_second: options.rateLimitPerSecond ?? null,
        retry_attempts: options.retryAttempts ?? null,
        retry_backoff_ms: options.retryBackoffMs ?? null,
        authorization_confirmed: options.authorizationConfirmed ?? false,
        domain_allowlist: options.domainAllowlist ?? [],
        detector_names: options.detectorNames ?? [],
        scan_profile: options.scanProfile ?? "deep",
        enable_api_fuzzing: options.enableApiFuzzing ?? true,
        enable_graphql_checks: options.enableGraphqlChecks ?? true,
        enable_finding_validator: options.enableFindingValidator ?? true,
        enable_openapi_discovery: options.enableOpenapiDiscovery ?? true,
        enable_directory_fuzzing: options.enableDirectoryFuzzing ?? null,
        enable_unsafe_state_changing_fuzz: options.enableUnsafeStateChangingFuzz ?? false,
        enable_safe_port_scan: options.enableSafePortScan ?? null,
        enable_subdomain_recon: options.enableSubdomainRecon ?? null,
        enable_screenshot_recon: options.enableScreenshotRecon ?? null,
        fail_on_high: options.failOnHigh ?? true,
        max_high_severity: options.maxHighSeverity ?? 0,
        max_medium_severity: options.maxMediumSeverity ?? null,
        max_total_findings: options.maxTotalFindings ?? null,
        slack_webhook_url: options.slackWebhookUrl || null,
        discord_webhook_url: options.discordWebhookUrl || null,
      }),
    });
  } catch (error) {
    throw new Error(`Backend API is unreachable at ${API_BASE_URL}. Start FastAPI, then retry the scan.`);
  }
  if (!response.ok) {
    let message = `API returned ${response.status}`;
    try {
      const body = await response.json();
      message = body.detail?.[0]?.msg ?? body.detail ?? message;
    } catch {
      // fall back to status text
    }
    throw new Error(message);
  }
  return response.json();
}

export async function fetchReports() {
  const response = await fetch(`${API_BASE_URL}/reports`);
  if (!response.ok) {
    throw new Error(`API returned ${response.status}`);
  }
  return response.json();
}

export async function fetchReportDetail(scanId) {
  const response = await fetch(`${API_BASE_URL}/reports/${scanId}`);
  if (!response.ok) {
    throw new Error(`API returned ${response.status}`);
  }
  return response.json();
}

export async function fetchScanHistory(limit = 25) {
  const response = await fetch(`${API_BASE_URL}/scans/history?limit=${limit}`);
  if (!response.ok) {
    throw new Error(`API returned ${response.status}`);
  }
  return response.json();
}

export async function fetchReportComparison(leftScanId, rightScanId) {
  const response = await fetch(`${API_BASE_URL}/reports/compare/${leftScanId}/${rightScanId}`);
  if (!response.ok) {
    throw new Error(`API returned ${response.status}`);
  }
  return response.json();
}

export async function fetchActiveScans() {
  const response = await fetch(`${API_BASE_URL}/scans/active`);
  if (!response.ok) {
    throw new Error(`API returned ${response.status}`);
  }
  return response.json();
}

export async function fetchDetectors() {
  const response = await fetch(`${API_BASE_URL}/detectors`);
  if (!response.ok) {
    throw new Error(`API returned ${response.status}`);
  }
  return response.json();
}

export async function fetchScanProfiles() {
  const response = await fetch(`${API_BASE_URL}/scan-profiles`);
  if (!response.ok) {
    throw new Error(`API returned ${response.status}`);
  }
  return response.json();
}

export async function fetchReplayPlan(scanId, findingIndex) {
  const response = await fetch(`${API_BASE_URL}/replay/${scanId}/${findingIndex}`);
  if (!response.ok) {
    throw new Error(`API returned ${response.status}`);
  }
  return response.json();
}

export async function fetchPluginMarketplace() {
  const response = await fetch(`${API_BASE_URL}/plugins/marketplace`);
  if (!response.ok) {
    throw new Error(`API returned ${response.status}`);
  }
  return response.json();
}

export async function fetchRoleComparison(leftScanId, rightScanId) {
  const response = await fetch(`${API_BASE_URL}/roles/compare/${leftScanId}/${rightScanId}`);
  if (!response.ok) {
    throw new Error(`API returned ${response.status}`);
  }
  return response.json();
}

export async function resumeScan(scanId) {
  const response = await fetch(`${API_BASE_URL}/scans/${scanId}/resume`, { method: "POST" });
  if (!response.ok) {
    throw new Error(`API returned ${response.status}`);
  }
  return response.json();
}
