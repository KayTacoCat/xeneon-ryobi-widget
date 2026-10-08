import { createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';

const file = new URL('../index.html', import.meta.url);
const html = (await readFile(file, 'utf8')).replace(/\r\n?/g, '\n');
const hashBlock = tag => {
  const blocks = [...html.matchAll(new RegExp(`<${tag}>([\\s\\S]*?)<\\/${tag}>`, 'g'))];
  if (blocks.length !== 1) throw new Error(`Expected one inline ${tag} block`);
  return `'sha256-${createHash('sha256').update(blocks[0][1]).digest('base64')}'`;
};
const policy = [
  "default-src 'none'",
  "base-uri 'none'",
  "object-src 'none'",
  "form-action 'none'",
  `script-src ${hashBlock('script')}`,
  `style-src ${hashBlock('style')}`,
  'connect-src https://rss.app/feeds/NbvgRJvMlmSIRBEe.xml',
  'frame-src https://rss.app/embed/v1/wall/NbvgRJvMlmSIRBEe'
].join('; ');
const updated = html.replace(
  /(<meta http-equiv="Content-Security-Policy" content=")[^"]*(" \/>)/,
  (_, before, after) => before + policy + after
);
if (updated === html && !html.includes(policy)) throw new Error('CSP meta tag not found');
await writeFile(file, updated, 'utf8');
console.log('Updated CSP hashes in index.html');
