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
    button.textContent = "Config disalin";
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
