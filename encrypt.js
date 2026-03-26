import { marked } from "marked";
import fs from "fs";
import path from "path";
import CryptoJS from "crypto-js";
import readline from "readline";

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

    if (!/^[a-f0-9]{32}$/.test(password)) {
      console.log(`❌ Invalid hash for ${postId}`);
      continue;
    }

    const mdRaw = fs.readFileSync(`${inputDir}/${file}`, "utf-8");

    // 🔥 remove front matter
    let md = mdRaw.replace(/^---[\s\S]*?---/, "").trim();

    // 🔥 remove Jekyll link attributes {:...}
    md = md.replace(/\{\:.*?\}/g, "");

    // 🔥 parse markdown properly
    const html = marked.parse(md, {
      gfm: true,
      breaks: true
    });

    const encrypted = CryptoJS.AES.encrypt(html, password).toString();

    fs.writeFileSync(`${outputDir}/${postId}.txt`, encrypted);

    console.log(`✔ Encrypted ${postId}`);
  }

  rl.close();
}

encryptAll();