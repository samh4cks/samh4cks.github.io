require 'base64'
require 'digest'
require 'openssl'
require 'nokogiri'
require 'json'
require 'yaml'

def aes256_encrypt(password, cleardata)
  digest = Digest::SHA256.new
  digest.update(password)
  key = digest.digest

  cipher = OpenSSL::Cipher::AES256.new(:CBC)
  cipher.encrypt
  cipher.key = key
  cipher.iv = iv = cipher.random_iv

  encrypted = cipher.update(cleardata) + cipher.final
  encoded_msg = Base64.encode64(encrypted).gsub(/\n/, '')
  encoded_iv  = Base64.encode64(iv).gsub(/\n/, '')

  hmac = Base64.encode64(OpenSSL::HMAC.digest('sha256', key, encoded_msg)).strip
  "#{encoded_iv}|#{hmac}|#{encoded_msg}"
end

# Read flag_secret from a post's original front matter in _posts/
def get_post_flag(post_slug)
  # Find the matching _posts/*.md file by slug
  Dir.glob('_posts/*.md').each do |md_path|
    filename = File.basename(md_path, '.md')
    # Strip date prefix (YYYY-MM-DD-) to get slug
    slug = filename.sub(/^\d{4}-\d{2}-\d{2}-/, '')
    next unless slug == post_slug

    content = File.read(md_path, encoding: 'utf-8') rescue next

    # Check if it starts with ciphertext: (encrypted markdown)
    # In that case read flag_secret differently — skip, no flag available
    return nil if content.strip.start_with?('ciphertext:')

    # Parse front matter
    parts = content.split('---', 3)
    next unless parts.length >= 3

    begin
      fm = YAML.safe_load(parts[1])
      secret_name = fm['flag_secret']
      next unless secret_name

      # Look up the actual flag from environment variable
      flag = ENV[secret_name]
      if flag.nil? || flag.empty?
        puts "  WARNING: env var '#{secret_name}' not set for post '#{slug}'"
        return nil
      end

      return flag
    rescue => e
      puts "  WARNING: could not parse front matter for #{md_path}: #{e.message}"
      next
    end
  end

  nil
end

Dir.glob('_site/posts/*/index.html').each do |post_path|
  html = File.read(post_path)

  # Only process posts with Protect category
  next unless html.include?('<a href="/categories/Protect/">Protect</a>')

  # Get post slug from path: _site/posts/SLUG/index.html
  post_slug = File.basename(File.dirname(post_path))

  # Get per-post flag from environment via flag_secret in front matter
  password = get_post_flag(post_slug)

  if password.nil?
    puts "Skipping #{post_slug} — no flag found (flag_secret not set or env var missing)"
    next
  end

  puts "Protecting: #{post_slug}"

  doc          = Nokogiri::HTML(html)
  content_node = doc.at_css('div.content')
  next unless content_node

  content_to_encrypt = content_node.inner_html
  encrypted          = aes256_encrypt(password, content_to_encrypt)
  encrypted_js       = encrypted.to_json

  protected_block = <<~HTML
    <div class="content">
      <div id="protected"></div>

      <div id="decryptModal" class="modal">
        <div class="modal-content">
          <div class="lock-icon">🔒</div>
          <h2 class="modal-title">This post is locked</h2>
          <p class="explain-text">
            This machine is currently <strong>live</strong>.<br>
            Submit the <code>root.txt</code> flag to unlock the full walkthrough.
          </p>
          <input id="password" type="text" placeholder="Enter root flag (e.g. a1b2c3d4...)">
          <button id="decryptButton" class="decrypt-btn">Unlock</button>
          <p id="errmsg" style="color: red; margin-top: 10px;"></p>
        </div>
      </div>

      <script>
        const protectedContent = #{encrypted_js};

        function base64ToBytes(b64) {
          const bin = atob(b64);
          return new Uint8Array([...bin].map(c => c.charCodeAt(0)));
        }
        function bytesToBase64(bytes) {
          return btoa(String.fromCharCode(...new Uint8Array(bytes)));
        }

        async function decrypt() {
          const [ivB64, hmacB64, cipherB64] = protectedContent.split("|");
          const password = document.getElementById('password').value.trim();
          if (!password) return;

          const pwKey = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(password));

          const keyForHmac = await crypto.subtle.importKey("raw", pwKey, {name:"HMAC", hash:"SHA-256"}, false, ["sign"]);
          const computedHmac = await crypto.subtle.sign("HMAC", keyForHmac, new TextEncoder().encode(cipherB64));
          if (bytesToBase64(computedHmac).trim() !== hmacB64.trim()) {
            const errmsg = document.getElementById('errmsg');
            errmsg.innerText = "Incorrect flag — try again.";
            errmsg.classList.remove("shake");
            void errmsg.offsetWidth;
            errmsg.classList.add("shake");
            return;
          }

          const aesKey = await crypto.subtle.importKey("raw", pwKey, {name:"AES-CBC"}, false, ["decrypt"]);

          const decrypted = await crypto.subtle.decrypt(
            {name: "AES-CBC", iv: base64ToBytes(ivB64)},
            aesKey,
            base64ToBytes(cipherB64)
          );

          const content = new TextDecoder().decode(decrypted);
          document.getElementById('protected').innerHTML = content;

          document.querySelectorAll('#protected .shimmer').forEach(el => el.classList.remove('shimmer'));

          const modal = document.getElementById('decryptModal');
          modal.classList.add("hide");
          setTimeout(() => { modal.style.display = "none"; }, 800);

          if (window.tocbot) {
            tocbot.refresh();
            tocbot.collapseAll();
          }
        }

        document.getElementById("decryptButton").onclick = decrypt;
        document.getElementById("password").addEventListener("keyup", e => {
          if (e.key === "Enter") decrypt();
        });
      </script>
    </div>
  HTML

  fragment = Nokogiri::HTML::DocumentFragment.parse(protected_block)
  content_node.replace(fragment)

  File.write(post_path, doc.to_html)
  puts "  ✓ Protected with flag from env var"
end