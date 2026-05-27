import React, { useMemo, useState } from "react";
import { ArrowUpDown, Columns3, Download, Filter, Search } from "lucide-react";

export function PageHeader({ eyebrow, title, subtitle, actions }) {
  return (
    <section className="page-header">
      <div>
        {eyebrow ? <span className="eyebrow">{eyebrow}</span> : null}
        <h1>{title}</h1>
        {subtitle ? <p>{subtitle}</p> : null}
      </div>
      {actions ? <div className="page-actions">{actions}</div> : null}
    </section>
  );
}

export function Card({ children, className = "" }) {
  return <article className={`as-card ${className}`}>{children}</article>;
}

export function CardHeader({ icon: Icon, title, meta }) {
  return (
    <header className="card-header">
      <div>{Icon ? <Icon size={17} /> : null}<strong>{title}</strong></div>
      {meta ? <span>{meta}</span> : null}
    </header>
  );
}

export function StatCard({ icon: Icon, label, value, delta, tone = "neutral" }) {
  return (
    <article className={`stat-card tone-${tone}`}>
      <div>{Icon ? <Icon size={18} /> : null}<span>{label}</span></div>
      <strong>{value}</strong>
      {delta ? <small>{delta}</small> : null}
    </article>
  );
}

export function KpiStrip({ items }) {
  return (
    <section className="kpi-strip">
      {items.map((item) => (
        <div key={item.label} className={`kpi-item tone-${item.tone ?? "neutral"}`}>
          <span>{item.label}</span>
          <strong>{item.value}</strong>
          {item.meta ? <small>{item.meta}</small> : null}
        </div>
      ))}
    </section>
  );
}

export function SeverityBadge({ value = "info" }) {
  return <span className={`severity-badge severity-${String(value).toLowerCase()}`}>{value}</span>;
}

export function StatusPill({ children, tone = "neutral" }) {
  return <span className={`status-pill tone-${tone}`}>{children}</span>;
}

export function DataTable({ columns, rows, getKey, empty = "No data available" }) {
  const [query, setQuery] = useState("");
  const [sortKey, setSortKey] = useState(columns[0]?.key ?? "");
  const [direction, setDirection] = useState("asc");

  const filtered = useMemo(() => {
    const text = query.trim().toLowerCase();
    const base = text
      ? rows.filter((row) => JSON.stringify(row).toLowerCase().includes(text))
      : rows;
    return [...base].sort((left, right) => {
      const a = String(left[sortKey] ?? "").toLowerCase();
      const b = String(right[sortKey] ?? "").toLowerCase();
      return direction === "asc" ? a.localeCompare(b) : b.localeCompare(a);
    });
  }, [columns, direction, query, rows, sortKey]);

  function onSort(key) {
    if (sortKey === key) {
      setDirection((current) => (current === "asc" ? "desc" : "asc"));
      return;
    }
    setSortKey(key);
    setDirection("asc");
  }

  return (
    <div className="table-shell">
      <div className="table-toolbar">
        <label className="table-search">
          <Search size={14} />
          <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search rows" />
        </label>
        <div className="table-actions">
          <button type="button" title="Filters"><Filter size={14} /></button>
          <button type="button" title="Columns"><Columns3 size={14} /></button>
          <button type="button" title="Export"><Download size={14} /></button>
          <span>{filtered.length} rows</span>
        </div>
      </div>
      <div className="table-scroll">
        <table className="data-table">
          <thead>
            <tr>
              {columns.map((column) => (
                <th key={column.key}>
                  <button type="button" onClick={() => onSort(column.key)}>
                    {column.label}<ArrowUpDown size={12} />
                  </button>
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {filtered.length ? filtered.map((row, index) => (
              <tr key={getKey ? getKey(row, index) : index}>
                {columns.map((column) => (
                  <td key={column.key}>{column.render ? column.render(row) : row[column.key]}</td>
                ))}
              </tr>
            )) : (
              <tr><td colSpan={columns.length} className="empty-cell">{empty}</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
