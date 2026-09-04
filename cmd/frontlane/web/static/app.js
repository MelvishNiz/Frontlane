let pendingForm;
let lastDialogTrigger;

function openDialog(dialog, trigger) {
  if (!dialog) return;
  lastDialogTrigger = trigger || document.activeElement;
  dialog.showModal();
  dialog.querySelector("input:not([type=hidden]), select, [data-confirm-submit], [data-dialog-close]")?.focus();
}

function closeDialog(dialog) {
  if (!dialog) return;
  dialog.close();
  lastDialogTrigger?.focus();
}

function showToast(message, type = "success", title = "Done") {
  const stack = document.querySelector(".toast-stack");
  if (!stack) return;
  const toast = document.createElement("div");
  toast.className = `toast is-${type}`;
  toast.dataset.toast = "";
  toast.setAttribute("role", type === "error" ? "alert" : "status");
  toast.innerHTML = `<svg aria-hidden="true"><use href="#icon-${type === "error" ? "warning" : "check"}"></use></svg><span><b></b><small></small></span><button type="button" data-toast-close aria-label="Dismiss notification"><svg aria-hidden="true"><use href="#icon-close"></use></svg></button>`;
  toast.querySelector("b").textContent = title;
  toast.querySelector("small").textContent = message;
  stack.append(toast);
  if (type !== "error") window.setTimeout(() => dismissToast(toast), 4200);
}

function dismissToast(toast) {
  if (!toast || toast.classList.contains("is-leaving")) return;
  toast.classList.add("is-leaving");
  window.setTimeout(() => toast.remove(), 180);
}

document.addEventListener("submit", (event) => {
  const form = event.target;
  if (form.dataset.submitting === "true") {
    event.preventDefault();
    return;
  }
  const message = form.dataset.confirm;
  if (!message || form.dataset.confirmed === "true") {
    form.dataset.submitting = "true";
    event.submitter?.setAttribute("disabled", "");
    return;
  }
  event.preventDefault();
  pendingForm = form;
  form.closest(".account-menu")?.removeAttribute("open");
  const dialog = document.getElementById("confirm-dialog");
  dialog.querySelector("#confirm-title").textContent = form.dataset.confirmTitle || "Confirm this change?";
  dialog.querySelector("#confirm-message").textContent = message;
  dialog.querySelector("[data-confirm-submit]").textContent = form.dataset.confirmAction || "Continue";
  openDialog(dialog, event.submitter);
});

document.addEventListener("click", async (event) => {
  const openButton = event.target.closest("[data-dialog-open]");
  if (openButton) {
    openDialog(document.getElementById(openButton.dataset.dialogOpen), openButton);
    return;
  }

  const closeButton = event.target.closest("[data-dialog-close]");
  if (closeButton) {
    if (closeButton.closest("#confirm-dialog")) pendingForm = undefined;
    closeDialog(closeButton.closest("dialog"));
    return;
  }

  const confirmButton = event.target.closest("[data-confirm-submit]");
  if (confirmButton && pendingForm) {
    const form = pendingForm;
    pendingForm = undefined;
    form.dataset.confirmed = "true";
    closeDialog(confirmButton.closest("dialog"));
    form.requestSubmit();
    return;
  }

  const toastClose = event.target.closest("[data-toast-close]");
  if (toastClose) {
    dismissToast(toastClose.closest("[data-toast]"));
    return;
  }

  const accountMenu = document.querySelector(".account-menu[open]");
  if (accountMenu && !accountMenu.contains(event.target)) accountMenu.removeAttribute("open");

  const button = event.target.closest("[data-copy-target]");
  if (!button) return;
  const target = document.getElementById(button.dataset.copyTarget);
  if (!target) return;

  try {
    await navigator.clipboard.writeText(target.value);
    showToast("Gateway credential copied to clipboard.", "success", "Credential copied");
  } catch {
    target.select();
    if (document.execCommand("copy")) showToast("Gateway credential copied to clipboard.", "success", "Credential copied");
    else showToast("Clipboard access was blocked. Select and copy the credential manually.", "error", "Copy failed");
  }
});

document.querySelectorAll("dialog").forEach((dialog) => {
  dialog.addEventListener("click", (event) => {
    if (event.target !== dialog) return;
    if (dialog.id === "confirm-dialog") pendingForm = undefined;
    closeDialog(dialog);
  });
  dialog.addEventListener("cancel", () => {
    if (dialog.id === "confirm-dialog") pendingForm = undefined;
  });
});

const errorDialog = document.querySelector("dialog[data-open-on-error]");
if (errorDialog) openDialog(errorDialog);

document.querySelectorAll("[data-toast]:not(.is-error)").forEach((toast) => {
  window.setTimeout(() => dismissToast(toast), 5000);
});

document.querySelectorAll("[data-select-group]").forEach((group) => {
  const all = group.querySelector("[data-select-all]");
  const items = [...group.querySelectorAll('input[type="checkbox"]:not([data-select-all])')];
  const sync = () => {
    all.checked = items.length > 0 && items.every((item) => item.checked);
    all.indeterminate = items.some((item) => item.checked) && !all.checked;
  };
  all?.addEventListener("change", () => { items.forEach((item) => { item.checked = all.checked; }); });
  items.forEach((item) => { item.addEventListener("change", sync); });
  sync();
});

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
  if (stateText) stateText.textContent = !peer.enabled ? (root.classList.contains("peer-detail") ? "Access paused" : "Paused") : peer.active ? "Connected" : "Idle";

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
    const response = await fetch("/__frontlane/api/vpn/status");
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
