document.addEventListener("DOMContentLoaded", () => {

  const btn = document.getElementById("unlock-btn");
  if (!btn) return;

  document.getElementById("password-input")?.focus();

  document.getElementById("password-input")
    .addEventListener("keypress", function (e) {
      if (e.key === "Enter") {
        btn.click();
      }
    });

  btn.addEventListener("click", async () => {

    let input = document.getElementById("password-input").value.trim();
    const error = document.getElementById("error-msg");

    error.style.display = "none";

    if (!/^[a-f0-9]{32}$/i.test(input)) {
      error.innerText = "Invalid flag format (32 hex required)";
      error.style.display = "block";
      return;
    }

    const password = input.toLowerCase();

    try {
      const res = await fetch(`/assets/protected/${POST_ID}.txt`);
      if (!res.ok) throw new Error();

      const encrypted = await res.text();

      const bytes = CryptoJS.AES.decrypt(encrypted, password);
      const decrypted = bytes.toString(CryptoJS.enc.Utf8);

      if (!decrypted) throw new Error();

      const content = document.getElementById("post-content");

      content.innerHTML = `
        <article class="px-1">
          <div class="content">
            ${decrypted}
          </div>
        </article>
      `;

      content.style.display = "block";

      // apply syntax highlighting (robust)
      document.querySelectorAll('#post-content pre code').forEach((block) => {
      block.classList.add("hljs");
      hljs.highlightElement(block);
      });

      // smooth remove overlay
      const overlay = document.getElementById("lock-wrapper");
      overlay.style.transition = "opacity 0.3s ease";
      overlay.style.opacity = "0";
      setTimeout(() => overlay.remove(), 300);

    } catch (e) {
      error.innerText = "Invalid root flag";
      error.style.display = "block";
    }

  });

});