import React from "react";
import { TerminalSquare } from "lucide-react";

export function LogsViewer({ logs }) {
  return (
    <section className="logs-shell">
      <header className="panel-header">
        <div>
          <TerminalSquare size={18} />
          <strong>Runtime Console</strong>
        </div>
        <span>{logs.length} events</span>
      </header>
      <section className="logs">
        {logs.map((line, index) => (
          <div key={`${line}-${index}`}>{line}</div>
        ))}
      </section>
    </section>
  );
}
