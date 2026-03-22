// Force gate visible on every page load
document.addEventListener('DOMContentLoaded', function() {
  var gate = document.getElementById('flag-gate');
  if (gate) {
    gate.removeAttribute('style');
  }

  var input = document.getElementById('flag-input');
  if (input) {
    input.addEventListener('keydown', function(e) {
      if (e.key === 'Enter') attemptDecrypt();
    });
  }
});

function attemptDecrypt() {
  var flag    = document.getElementById('flag-input').value.trim();
  var errorEl = document.getElementById('flag-error');
  if (!flag) return;

  try {
    if (typeof ENCRYPTED_BLOB === 'undefined') throw new Error('Blob not loaded');

    var decrypted = CryptoJS.AES.decrypt(ENCRYPTED_BLOB, flag);
    var words     = decrypted.words;
    var sigBytes  = decrypted.sigBytes;

    if (!sigBytes || sigBytes < 10) throw new Error('wrong flag');

    var u8arr = new Uint8Array(sigBytes);
    for (var i = 0; i < sigBytes; i++) {
      u8arr[i] = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
    }

    var plaintext = new TextDecoder('utf-8').decode(u8arr);
    if (!plaintext || plaintext.length < 10) throw new Error('wrong flag');

    // Hide teaser and gate
    var teaser = document.getElementById('public-teaser');
    if (teaser) teaser.style.display = 'none';
    document.getElementById('flag-gate').style.display = 'none';
    errorEl.style.display = 'none';

    // Strip <script> tags before injecting — prevents 404 errors from
    // scripts that reference paths only valid in Jekyll's full page context
    var clean = plaintext.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '');

    var contentEl = document.getElementById('writeup-content');
    contentEl.innerHTML = clean;
    contentEl.style.display = 'block';

    if (typeof Prism !== 'undefined') Prism.highlightAllUnder(contentEl);

  } catch(e) {
    errorEl.style.display = 'block';
    document.getElementById('flag-input').select();
  }
}