const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? "http://127.0.0.1:8000/api";

export async function startScan(targetUrl) {
  const response = await fetch(`${API_BASE_URL}/scan`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ target_url: targetUrl }),
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
