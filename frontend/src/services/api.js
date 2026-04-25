const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? "http://127.0.0.1:8000/api";

export async function startScan(targetUrl, options = {}) {
  const response = await fetch(`${API_BASE_URL}/scan`, {
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
      login_extra_fields: options.loginExtraFields ?? {},
      rate_limit_per_second: options.rateLimitPerSecond ?? null,
      retry_attempts: options.retryAttempts ?? null,
      retry_backoff_ms: options.retryBackoffMs ?? null,
      authorization_confirmed: options.authorizationConfirmed ?? false,
      domain_allowlist: options.domainAllowlist ?? [],
      detector_names: options.detectorNames ?? [],
      enable_api_fuzzing: options.enableApiFuzzing ?? true,
      enable_graphql_checks: options.enableGraphqlChecks ?? true,
    }),
  });
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
