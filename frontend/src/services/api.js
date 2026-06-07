const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? "/api";

// ---------------------------------------------------------------------------
// Shared fetch helper — all API calls go through this to ensure:
//   1. credentials: "include" (sends httpOnly JWT cookie on every request)
//   2. Consistent 401/403 handling (redirect to login on session expiry)
// ---------------------------------------------------------------------------
async function apiFetch(path, options = {}) {
  const response = await fetch(`${API_BASE_URL}${path}`, {
    ...options,
    credentials: "include",
    headers: {
      "Content-Type": "application/json",
      ...options.headers,
    },
  });

  if (response.status === 401) {
    // Session expired — clear local state and reload to trigger auth redirect
    window.localStorage.removeItem("adaptiveScan.accessToken");
    window.localStorage.removeItem("adaptiveScan.refreshToken");
    window.localStorage.removeItem("adaptiveScan.pendingEmail");
    // Dispatch event so AuthContext can handle the redirect
    window.dispatchEvent(new CustomEvent("adaptivescan:session-expired"));
    throw new Error("Session expired. Please log in again.");
  }

  if (!response.ok) {
    let message = `API returned ${response.status}`;
    try {
      const body = await response.json();
      message = body.detail?.[0]?.msg ?? body.detail?.message ?? body.detail ?? body.reason ?? message;
    } catch {
      // fall back to status text
    }
    throw new Error(message);
  }

  // Return null for 204 No Content
  if (response.status === 204) return null;

  return response.json();
}

export async function startScan(targetUrl, options = {}) {
  return apiFetch("/scan", {
    method: "POST",
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
      enable_dns_analysis: options.enableDnsAnalysis ?? null,
      enable_cloud_asset_recon: options.enableCloudAssetRecon ?? null,
      enable_screenshot_recon: options.enableScreenshotRecon ?? null,
      fail_on_high: options.failOnHigh ?? true,
      max_high_severity: options.maxHighSeverity ?? 0,
      max_medium_severity: options.maxMediumSeverity ?? null,
      max_total_findings: options.maxTotalFindings ?? null,
      slack_webhook_url: options.slackWebhookUrl || null,
      discord_webhook_url: options.discordWebhookUrl || null,
    }),
  });
}

export async function fetchReports() {
  return apiFetch("/reports");
}

export async function fetchReportDetail(scanId) {
  return apiFetch(`/reports/${scanId}`);
}

export async function fetchScanHistory(limit = 25) {
  return apiFetch(`/scans/history?limit=${limit}`);
}

export async function fetchReportComparison(leftScanId, rightScanId) {
  return apiFetch(`/reports/compare/${leftScanId}/${rightScanId}`);
}

export async function fetchActiveScans() {
  return apiFetch("/scans/active");
}

export async function fetchDetectors() {
  return apiFetch("/detectors");
}

export async function fetchScanProfiles() {
  return apiFetch("/scan-profiles");
}

export async function fetchReplayPlan(scanId, findingIndex) {
  return apiFetch(`/replay/${scanId}/${findingIndex}`);
}

export async function fetchPluginMarketplace() {
  return apiFetch("/plugins/marketplace");
}

export async function fetchFindingLifecycle(scanId, findingIndex) {
  return apiFetch(`/findings/${scanId}/${findingIndex}/lifecycle`);
}

export async function updateFindingLifecycle(scanId, findingIndex, payload) {
  return apiFetch(`/findings/${scanId}/${findingIndex}/lifecycle`, {
    method: "PUT",
    body: JSON.stringify(payload),
  });
}

export async function addFindingComment(scanId, findingIndex, payload) {
  return apiFetch(`/findings/${scanId}/${findingIndex}/comments`, {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function fetchAuditLogs(limit = 100) {
  return apiFetch(`/audit-logs?limit=${limit}`);
}

export async function fetchTenancyOverview() {
  return apiFetch("/tenancy/overview");
}

export async function createOrganization(payload) {
  return apiFetch("/organizations", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function createWorkspace(payload) {
  return apiFetch("/workspaces", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function createApiKey(payload) {
  return apiFetch("/api-keys", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function fetchProductCapabilities() {
  return apiFetch("/product/capabilities");
}

export async function fetchEnterpriseFoundation() {
  return apiFetch("/product/enterprise-foundation");
}

export async function fetchPlatformOverview() {
  return apiFetch("/platform/overview");
}

export async function fetchOperationsIntelligence() {
  return apiFetch("/platform/operations");
}

export async function fetchPlatformQueue() {
  return apiFetch("/platform/queue");
}

export async function fetchPlatformDatabase() {
  return apiFetch("/platform/database");
}

export async function fetchPlatformObservability() {
  return apiFetch("/platform/observability");
}

export async function fetchAttackSurfaceGraph() {
  return apiFetch("/attack-surface/graph");
}

export async function fetchAttackSurfaceDrift() {
  return apiFetch("/attack-surface/drift");
}

export async function fetchAttackPaths() {
  return apiFetch("/attack-paths");
}

export async function fetchExposureOverview() {
  return apiFetch("/exposure/overview");
}

export async function fetchRoleComparison(leftScanId, rightScanId) {
  return apiFetch(`/roles/compare/${leftScanId}/${rightScanId}`);
}

export async function resumeScan(scanId) {
  return apiFetch(`/scans/${scanId}/resume`, { method: "POST" });
}

export async function fetchAuthArchitecture() {
  return apiFetch("/auth/architecture");
}

export async function registerAccount(payload) {
  return apiFetch("/auth/register", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function loginAccount(payload) {
  return apiFetch("/auth/login", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function verifyOtp(payload) {
  return apiFetch("/auth/otp/verify", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function requestPasswordReset(payload) {
  return apiFetch("/auth/forgot-password", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function fetchOnboarding() {
  return apiFetch("/onboarding");
}

export async function fetchBillingCatalog() {
  return apiFetch("/billing/catalog");
}

export async function fetchSubscriptionStatus() {
  return apiFetch("/billing/subscription");
}

export async function fetchTeamDirectory() {
  return apiFetch("/team");
}

export async function fetchNotificationCenter() {
  return apiFetch("/notifications");
}

export async function fetchMonitoringWorkflows() {
  return apiFetch("/monitoring/workflows");
}

export async function fetchTrustCenter() {
  return apiFetch("/trust");
}
