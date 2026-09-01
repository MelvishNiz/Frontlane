document.addEventListener("submit", (event) => {
  const message = event.target.dataset.confirm;
  if (message && !window.confirm(message)) event.preventDefault();
});

document.addEventListener("click", async (event) => {
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
