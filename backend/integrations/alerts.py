import logging

import httpx


logger = logging.getLogger(__name__)


async def send_scan_alerts(
    scan: dict[str, object],
    *,
    slack_webhook_url: str | None = None,
    discord_webhook_url: str | None = None,
) -> dict[str, object]:
    summary = scan.get("summary", {})
    if not isinstance(summary, dict):
        summary = {}
    high_count = int(summary.get("high_severity_count", 0) or 0)
    risk_gate = scan.get("risk_gate", {})
    should_alert = high_count > 0 or (isinstance(risk_gate, dict) and risk_gate.get("status") == "failed")
    results: list[dict[str, object]] = []

    if not should_alert:
        return {"sent": False, "reason": "no high severity findings or failed risk gate", "results": results}

    message = (
        f"High severity vulnerability detected on {scan.get('target_url')}. "
        f"High: {high_count}, Total: {summary.get('finding_count', 0)}, "
        f"Risk gate: {risk_gate.get('status', 'unknown') if isinstance(risk_gate, dict) else 'unknown'}."
    )
    async with httpx.AsyncClient(timeout=8.0) as client:
        if slack_webhook_url:
            results.append(await _post_alert(client, "slack", slack_webhook_url, {"text": message}))
        if discord_webhook_url:
            results.append(await _post_alert(client, "discord", discord_webhook_url, {"content": message}))

    return {"sent": any(item.get("sent") for item in results), "results": results}


async def _post_alert(
    client: httpx.AsyncClient,
    channel: str,
    webhook_url: str,
    payload: dict[str, object],
) -> dict[str, object]:
    try:
        response = await client.post(webhook_url, json=payload)
        return {
            "channel": channel,
            "sent": 200 <= response.status_code < 300,
            "status_code": response.status_code,
        }
    except Exception as exc:
        logger.warning("Failed to send %s scan alert: %s", channel, exc)
        return {"channel": channel, "sent": False, "error": str(exc)}
