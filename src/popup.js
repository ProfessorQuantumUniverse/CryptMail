/**
 * CryptMail – Popup UI logic
 */

(() => {
  "use strict";

  const emailInput = document.getElementById("email");
  const passphraseInput = document.getElementById("passphrase");
  const saveBtn = document.getElementById("saveBtn");
  const statusEl = document.getElementById("status");
  const keyListEl = document.getElementById("keyList");

  function showStatus(msg, isError) {
    statusEl.textContent = msg;
    statusEl.className = isError ? "error" : "";
    setTimeout(() => {
      statusEl.textContent = "";
      statusEl.className = "";
    }, 3000);
  }

  async function renderKeys() {
    const keys = await KeyStore.listKeys();
    const emails = Object.keys(keys);

    if (emails.length === 0) {
      keyListEl.innerHTML = '<div class="empty-state">No keys stored yet.</div>';
      return;
    }

    keyListEl.innerHTML = "";
    emails.forEach((email) => {
      const item = document.createElement("div");
      item.className = "key-item";

      const span = document.createElement("span");
      span.className = "email";
      span.textContent = email;

      const removeBtn = document.createElement("button");
      removeBtn.className = "remove-btn";
      removeBtn.textContent = "✕";
      removeBtn.title = "Remove key";
      removeBtn.addEventListener("click", async () => {
        await KeyStore.removeKey(email);
        showStatus(`Key for ${email} removed.`);
        renderKeys();
      });

      item.appendChild(span);
      item.appendChild(removeBtn);
      keyListEl.appendChild(item);
    });
  }

  saveBtn.addEventListener("click", async () => {
    const email = emailInput.value.trim();
    const passphrase = passphraseInput.value;

    if (!email) {
      showStatus("Please enter an email address.", true);
      return;
    }
    if (!passphrase) {
      showStatus("Please enter a passphrase.", true);
      return;
    }

    await KeyStore.setKey(email, passphrase);
    showStatus(`Key saved for ${email}.`);
    emailInput.value = "";
    passphraseInput.value = "";
    renderKeys();
  });

  renderKeys();
})();
