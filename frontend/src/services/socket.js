export function createScanSocket(onMessage, onOpen, onClose) {
  const protocol = window.location.protocol === "https:" ? "wss" : "ws";
  // Dynamically resolve target host/port, routing through Vite proxy in dev or same host in prod
  const host = window.location.host;
  const socket = new WebSocket(`${protocol}://${host}/api/ws/scans`);
  
  if (onOpen) {
    socket.addEventListener("open", onOpen);
  }
  if (onClose) {
    socket.addEventListener("close", onClose);
  }
  
  socket.addEventListener("message", (event) => {
    try {
      onMessage(JSON.parse(event.data));
    } catch {
      // Ignore malformed payloads
    }
  });
  
  return socket;
}
