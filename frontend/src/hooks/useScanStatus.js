import { useState } from "react";

export function useScanStatus() {
  const [status, setStatus] = useState("idle");
  return { status, setStatus, isRunning: status === "running" };
}

