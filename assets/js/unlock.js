document.addEventListener("DOMContentLoaded", () => {

    const btn = document.getElementById("unlock-btn");
    if (!btn) return;
  
    btn.addEventListener("click", async () => {
  
      let input = document.getElementById("password-input").value.trim();
      const error = document.getElementById("error-msg");
  
      // reset error
      error.style.display = "none";
  
      // 🔒 validate 32 hex
      if (!/^[a-f0-9]{32}$/i.test(input)) {
        error.innerText = "Invalid flag format (32 hex required)";
        error.style.display = "block";
        return;
      }
  
      const password = input.toLowerCase();
  
      try {
        const res = await fetch(`/assets/protected/${POST_ID}.txt`);
  
        if (!res.ok) throw new Error("Encrypted file not found");
  
        const encrypted = await res.text();
  
        const bytes = CryptoJS.AES.decrypt(encrypted, password);
        const decrypted = bytes.toString(CryptoJS.enc.Utf8);
  
        if (!decrypted) throw new Error("Wrong password");
  
        document.getElementById("post-content").innerHTML = decrypted;
        document.getElementById("post-content").style.display = "block";
        document.getElementById("lock-wrapper").style.display = "none";
  
      } catch (e) {
        error.innerText = "Invalid root flag";
        error.style.display = "block";
      }
  
    });
  
  });