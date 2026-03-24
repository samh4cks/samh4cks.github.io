const fs = require("fs");
const path = require("path");
const CryptoJS = require("crypto-js");
const { marked } = require("marked");
const readline = require("readline");

const inputDir = "protected";
const outputDir = "assets/protected";

if (!fs.existsSync(outputDir)) {
  fs.mkdirSync(outputDir, { recursive: true });
}

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

const files = fs.readdirSync(inputDir).filter(f => f.endsWith(".md"));

async function encryptAll() {
  for (const file of files) {

    const postId = path.basename(file, ".md");

    let password = await new Promise(resolve => {
      rl.question(`Enter ROOT hash (32 hex) for ${postId}: `, resolve);
    });

    password = password.trim().toLowerCase();

    // 🔒 enforce format
    if (!/^[a-f0-9]{32}$/.test(password)) {
      console.log(`❌ Invalid hash for ${postId}`);
      continue;
    }

    const md = fs.readFileSync(`${inputDir}/${file}`, "utf-8");
    const html = marked.parse(md);

    const encrypted = CryptoJS.AES.encrypt(html, password).toString();

    fs.writeFileSync(`${outputDir}/${postId}.txt`, encrypted);

    console.log(`✔ Encrypted ${postId}`);
  }

  rl.close();
}

encryptAll();