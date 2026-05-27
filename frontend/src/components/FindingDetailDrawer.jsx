import React, { useEffect, useState } from "react";
import { ArrowUpRight, CircleAlert, MessageSquarePlus, X } from "lucide-react";
import { addFindingComment, fetchFindingLifecycle, updateFindingLifecycle } from "../services/api.js";

const lifecycleStates = ["open", "triaged", "assigned", "retesting", "resolved", "closed"];

export function FindingDetailDrawer({ finding, open, onClose }) {
  const [lifecycle, setLifecycle] = useState(null);
  const [workflowState, setWorkflowState] = useState("open");
  const [owner, setOwner] = useState("");
  const [slaDueAt, setSlaDueAt] = useState("");
  const [commentBody, setCommentBody] = useState("");
  const [workflowMessage, setWorkflowMessage] = useState("");

  useEffect(() => {
    if (!open || !finding?.scan_id || finding?.finding_index === undefined) {
      setLifecycle(null);
      return;
    }
    fetchFindingLifecycle(finding.scan_id, finding.finding_index)
      .then((item) => {
        setLifecycle(item);
        setWorkflowState(item.state || "open");
        setOwner(item.owner || "");
        setSlaDueAt(item.sla_due_at || "");
      })
      .catch(() => setWorkflowMessage("Lifecycle metadata is not available for this finding yet."));
  }, [finding, open]);

  if (!open || !finding) {
    return null;
  }

  async function saveLifecycle() {
    if (!finding.scan_id || finding.finding_index === undefined) {
      return;
    }
    setWorkflowMessage("Saving workflow...");
    try {
      const item = await updateFindingLifecycle(finding.scan_id, finding.finding_index, {
        state: workflowState,
        owner,
        sla_due_at: slaDueAt,
        actor: "local-user",
      });
      setLifecycle(item);
      setWorkflowMessage("Workflow saved.");
    } catch (error) {
      setWorkflowMessage(String(error.message || "Could not save workflow"));
    }
  }

  async function saveComment() {
    if (!finding.scan_id || finding.finding_index === undefined || !commentBody.trim()) {
      return;
    }
    setWorkflowMessage("Adding comment...");
    try {
      const item = await addFindingComment(finding.scan_id, finding.finding_index, {
        body: commentBody.trim(),
        actor: "local-user",
      });
      setLifecycle(item);
      setCommentBody("");
      setWorkflowMessage("Comment added.");
    } catch (error) {
      setWorkflowMessage(String(error.message || "Could not add comment"));
    }
  }

  const evidenceRows = [
    ["Detector", String(finding.detector ?? "generic").toUpperCase()],
    ["Severity", finding.severity ?? "unknown"],
    ["Confidence", finding.confidence ?? "medium"],
    ["Score", finding.confidence_score ?? "-"],
    ["Priority", finding.remediation_priority ?? "-"],
    ["CWE", finding.cwe_id ?? "-"],
    ["Method", String(finding.method ?? "get").toUpperCase()],
    ["Parameter", finding.parameter ?? "-"],
    ["Input", finding.input_location ?? "-"],
    ["Context", finding.reflection_context ?? "-"],
    ["DOM", finding.dom_observation ?? "-"],
    ["Validation", finding.validation_state ?? "-"],
  ];

  return (
    <div className="drawer-backdrop" onClick={onClose} role="presentation">
      <aside className="finding-drawer" onClick={(event) => event.stopPropagation()}>
        <header className="drawer-header">
          <div>
            <span className={`drawer-severity severity-pill severity-${finding.severity}`}>{finding.severity}</span>
            <h3>{String(finding.detector ?? "finding").toUpperCase()} Finding</h3>
          </div>
          <button type="button" className="icon-button" onClick={onClose} aria-label="Close finding drawer">
            <X size={18} />
          </button>
        </header>

        <section className="drawer-block drawer-highlight">
          <div className="drawer-title">
            <CircleAlert size={18} />
            <strong>Evidence Summary</strong>
          </div>
          <p>{finding.evidence}</p>
          <small>{finding.reason ?? "No additional reasoning captured for this finding."}</small>
        </section>

        <section className="drawer-grid">
          {evidenceRows.map(([label, value]) => (
            <article key={label} className="drawer-stat">
              <span>{label}</span>
              <strong>{value}</strong>
            </article>
          ))}
        </section>

        <section className="drawer-block">
          <div className="drawer-title">
            <ArrowUpRight size={18} />
            <strong>Technical Detail</strong>
          </div>
          <div className="drawer-kv">
            <div><span>URL</span><strong>{finding.url}</strong></div>
            <div><span>Status delta</span><strong>{finding.baseline_status ?? "-"} {"->"} {finding.mutated_status ?? "-"}</strong></div>
            <div><span>Length delta</span><strong>{finding.baseline_length ?? "-"} {"->"} {finding.mutated_length ?? "-"}</strong></div>
            <div><span>CVSS</span><strong>{finding.cvss_score ?? "-"}</strong></div>
          </div>
          {finding.validation_signals?.length ? (
            <div className="drawer-chip-row">
              {finding.validation_signals.map((signal) => (
                <span key={signal} className="drawer-chip">{signal}</span>
              ))}
            </div>
          ) : null}
          {finding.poc ? <code className="drawer-code">{finding.poc}</code> : null}
          {finding.payload ? <code className="drawer-code">{finding.payload}</code> : null}
          {finding.replay_plan?.curl ? (
            <>
              <strong>Replay Plan</strong>
              <code className="drawer-code">{finding.replay_plan.curl}</code>
              <small>{finding.replay_plan.note}</small>
            </>
          ) : null}
          {finding.request_snapshot ? <code className="drawer-code">{finding.request_snapshot}</code> : null}
          {finding.response_snapshot ? <code className="drawer-code">{finding.response_snapshot}</code> : null}
        </section>

        <section className="drawer-block">
          <div className="drawer-title">
            <MessageSquarePlus size={18} />
            <strong>Lifecycle Workflow</strong>
          </div>
          <div className="lifecycle-form">
            <label>
              <span>State</span>
              <select value={workflowState} onChange={(event) => setWorkflowState(event.target.value)}>
                {lifecycleStates.map((state) => (
                  <option key={state} value={state}>{state}</option>
                ))}
              </select>
            </label>
            <label>
              <span>Owner</span>
              <input value={owner} placeholder="security@company.com" onChange={(event) => setOwner(event.target.value)} />
            </label>
            <label>
              <span>SLA Due</span>
              <input value={slaDueAt} placeholder="2026-05-30" onChange={(event) => setSlaDueAt(event.target.value)} />
            </label>
            <button type="button" className="report-link" onClick={saveLifecycle}>Save workflow</button>
          </div>
          <div className="comment-box">
            <textarea value={commentBody} placeholder="Add triage notes, remediation context, or retest evidence..." onChange={(event) => setCommentBody(event.target.value)} />
            <button type="button" className="report-link secondary" onClick={saveComment}>Add comment</button>
          </div>
          {workflowMessage ? <small>{workflowMessage}</small> : null}
          {(lifecycle?.comments ?? []).length ? (
            <div className="comment-list">
              {lifecycle.comments.map((comment, index) => (
                <article key={`${comment.created_at}-${index}`}>
                  <strong>{comment.actor}</strong>
                  <small>{comment.created_at}</small>
                  <p>{comment.body}</p>
                </article>
              ))}
            </div>
          ) : null}
        </section>

        <section className="drawer-block">
          <div className="drawer-title">
            <strong>Recommended Action</strong>
          </div>
          {finding.owasp_category ? (
            <div className="drawer-chip-row" style={{marginBottom: "8px"}}>
              <span className="drawer-chip severity-high">{finding.owasp_category}</span>
            </div>
          ) : null}
          {finding.cwe_title ? <small>{finding.cwe_title}</small> : null}
          <p>{finding.recommendation}</p>
          {finding.code_snippet ? (
            <div style={{marginTop: "12px"}}>
              <strong>Remediation Example:</strong>
              <code className="drawer-code" style={{marginTop: "4px"}}>{finding.code_snippet}</code>
            </div>
          ) : null}
        </section>
      </aside>
    </div>
  );
}
