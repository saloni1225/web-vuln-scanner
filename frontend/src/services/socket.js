export function createScanSocket(onMessage) {
  const protocol = window.location.protocol === "https:" ? "wss" : "ws";
  const socket = new WebSocket(`${protocol}://127.0.0.1:8000/api/ws/scans`);
  socket.addEventListener("message", (event) => onMessage(JSON.parse(event.data)));
  return socket;
}
