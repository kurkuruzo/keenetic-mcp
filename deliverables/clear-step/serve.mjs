import http from 'node:http';
import { readFile } from 'node:fs/promises';
const files = new Map([
  ['/', ['actions.html', 'text/html; charset=utf-8']],
  ['/actions.html', ['actions.html', 'text/html; charset=utf-8']],
  ['/project.html', ['project.html', 'text/html; charset=utf-8']],
  ['/screen.css', ['screen.css', 'text/css; charset=utf-8']],
  ['/screen.js', ['screen.js', 'text/javascript; charset=utf-8']]
]);
const server = http.createServer(async (req, res) => {
  const path = new URL(req.url, 'http://127.0.0.1').pathname;
  const file = files.get(path);
  if (!file || !['GET', 'HEAD'].includes(req.method)) { res.writeHead(404); res.end(); return; }
  try {
    const body = await readFile(new URL(file[0], import.meta.url));
    res.writeHead(200, { 'Content-Type': file[1], 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' });
    res.end(req.method === 'HEAD' ? undefined : body);
  } catch { res.writeHead(500); res.end('Could not read prototype file.'); }
});
server.on('error', error => { console.error(error.message); process.exitCode = 1; });
server.listen(4177, '127.0.0.1', () => console.log('Actions: http://127.0.0.1:4177/actions.html\nProject: http://127.0.0.1:4177/project.html\nCtrl+C to stop.'));
