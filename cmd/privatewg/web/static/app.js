document.addEventListener("submit", (event) => {
  const message = event.target.dataset.confirm;
  if (message && !window.confirm(message)) event.preventDefault();
});

document.addEventListener("click", async (event) => {
  const openButton = event.target.closest("[data-dialog-open]");
  if (openButton) {
    const dialog = document.getElementById(openButton.dataset.dialogOpen);
    if (dialog) {
      dialog.showModal();
      dialog.querySelector("input:not([type=hidden]), select")?.focus();
    }
    return;
  }

  const closeButton = event.target.closest("[data-dialog-close]");
  if (closeButton) {
    closeButton.closest("dialog")?.close();
    return;
  }

  const button = event.target.closest("[data-copy-target]");
  if (!button) return;

  const target = document.getElementById(button.dataset.copyTarget);
  if (!target) return;

  try {
    await navigator.clipboard.writeText(target.value);
    const original = button.textContent;
    button.textContent = "Config copied";
    window.setTimeout(() => { button.textContent = original; }, 1800);
  } catch {
    target.select();
    document.execCommand("copy");
  }
});

document.querySelectorAll("dialog").forEach((dialog) => {
  dialog.addEventListener("click", (event) => {
    if (event.target === dialog) dialog.close();
  });
});

document.querySelector("dialog[data-open-on-error]")?.showModal();

const peerRows = [...document.querySelectorAll("[data-peer-id]")];
const relativeTime = new Intl.RelativeTimeFormat("en", { numeric: "auto" });

function formatRelative(timestamp) {
  if (!timestamp) return "never";
  const seconds = Math.round(timestamp - Date.now() / 1000);
  const ranges = [[86400, "day"], [3600, "hour"], [60, "minute"]];
  for (const [size, unit] of ranges) {
    if (Math.abs(seconds) >= size) return relativeTime.format(Math.round(seconds / size), unit);
  }
  return "just now";
}

function formatBytes(value) {
  const units = ["B", "KB", "MB", "GB", "TB"];
  let unit = 0;
  let size = value;
  while (size >= 1024 && unit < units.length - 1) {
    size /= 1024;
    unit += 1;
  }
  return `${size.toFixed(1)} ${units[unit]}`;
}

function refreshRelativeTimes() {
  document.querySelectorAll("[data-timestamp]").forEach((element) => {
    element.textContent = formatRelative(Number(element.dataset.timestamp));
  });
}

function renderPeerStatus(root, peer) {
  const state = root.querySelector("[data-peer-state]");
  const stateText = root.querySelector("[data-peer-state-text]");
  state?.classList.toggle("online", peer.enabled && peer.active);
  if (stateText) stateText.textContent = !peer.enabled ? (root.classList.contains("peer-detail") ? "Access paused" : "Paused") : peer.active ? "Connected" : "Disconnected";

  const handshake = root.querySelector("[data-peer-handshake]");
  if (handshake) {
    handshake.dataset.timestamp = peer.lastHandshake;
    handshake.textContent = formatRelative(peer.lastHandshake);
  }
  const received = root.querySelector("[data-peer-rx]");
  const transmitted = root.querySelector("[data-peer-tx]");
  if (received) received.textContent = formatBytes(peer.received);
  if (transmitted) transmitted.textContent = formatBytes(peer.transmitted);
}

async function refreshPeerStatuses() {
  if (!peerRows.length) return;
  try {
    const response = await fetch("/__privatewg/api/peers/status");
    if (!response.ok) return;
    const statuses = new Map((await response.json()).map((peer) => [String(peer.id), peer]));
    peerRows.forEach((root) => {
      const peer = statuses.get(root.dataset.peerId);
      if (peer) renderPeerStatus(root, peer);
    });
  } catch {}
}

refreshRelativeTimes();
refreshPeerStatuses();
window.setInterval(refreshRelativeTimes, 30000);
window.setInterval(refreshPeerStatuses, 15000);
