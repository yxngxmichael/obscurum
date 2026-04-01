/**
 * Obscurum — Backend Server
 * Node.js / Express — runs real nmap, whois, dig, openssl, ping, curl, ssh
 *
 * Requirements:
 *   npm install express cors
 *   System tools: nmap, whois, dnsutils (dig), openssl, iputils-ping, curl, traceroute
 *
 * Usage:
 *   node server.js
 *   Server runs on http://localhost:3000
 *
 * WARNING: Only run on networks and systems you own or have explicit permission to test.
 */

'use strict';

const express  = require('express');
const cors     = require('cors');
const { spawn } = require('child_process');
const https    = require('https');
const http     = require('http');
const { URL }  = require('url');

const app  = express();
const PORT = 3000;

// ── Middleware ──────────────────────────────────────────────────────────────
app.use(cors({ origin: '*' }));
app.use(express.json());

// ── Helpers ─────────────────────────────────────────────────────────────────

/** Send an SSE line to the response */
function send(res, line, type = 'out', loot = false) {
  res.write(`data:${JSON.stringify({ line, type, loot })}\n\n`);
}

/** Start SSE response */
function startSSE(res) {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders();
}

/** Validate that a target looks like a hostname, IP, or CIDR — basic sanitisation */
function safeTarget(t) {
  if (!t) return null;
  // Allow: alphanumeric, dots, hyphens, colons (IPv6), forward slash (CIDR), underscore
  if (!/^[a-zA-Z0-9.\-:/_ ]+$/.test(t)) return null;
  // Block shell metacharacters
  if (/[;&|`$<>!'"\\]/.test(t)) return null;
  return t.trim();
}

/** Validate URL */
function safeUrl(u) {
  try {
    const parsed = new URL(u);
    if (!['http:', 'https:'].includes(parsed.protocol)) return null;
    return u;
  } catch { return null; }
}

/** Validate port number */
function safePort(p) {
  const n = parseInt(p, 10);
  return (n > 0 && n < 65536) ? n : null;
}

/** Run a command and stream output line-by-line via SSE */
function streamCommand(res, cmd, args, opts = {}) {
  return new Promise((resolve) => {
    const proc = spawn(cmd, args, {
      timeout: opts.timeout || 60000,
      env: { ...process.env }
    });

    proc.stdout.on('data', (data) => {
      data.toString().split('\n').forEach(line => {
        if (line.trim()) send(res, line, opts.successType || 'out', opts.lootAll || false);
      });
    });

    proc.stderr.on('data', (data) => {
      data.toString().split('\n').forEach(line => {
        if (line.trim()) send(res, line, 'warn');
      });
    });

    proc.on('close', (code) => resolve(code));
    proc.on('error', (err) => {
      send(res, `✗ Command error: ${err.message}`, 'err');
      resolve(1);
    });
  });
}

// ── Health check ─────────────────────────────────────────────────────────────
app.get('/health', (req, res) => res.json({ status: 'ok', version: '1.0.0' }));

// ── NMAP ─────────────────────────────────────────────────────────────────────
app.post('/run/nmap', async (req, res) => {
  startSSE(res);
  const target = safeTarget(req.body.target);
  const type   = ['-sS','-sT','-sV','-A','-sn','-O'].includes(req.body.type) ? req.body.type : '-sS';
  const timing = ['-T1','-T2','-T3','-T4','-T5'].includes(req.body.timing) ? req.body.timing : '-T3';

  if (!target) { send(res, '✗ Invalid target', 'err'); return res.end(); }

  send(res, `$ nmap ${type} ${timing} ${target}`, 'info');
  send(res, '');

  const args = [type, timing, target];
  // Add -oG for grep-able output parsing is optional; we stream raw
  await streamCommand(res, 'nmap', args, { timeout: 120000, lootAll: true });

  res.end();
});

// ── WHOIS ─────────────────────────────────────────────────────────────────────
app.post('/run/whois', async (req, res) => {
  startSSE(res);
  const target = safeTarget(req.body.target);
  if (!target) { send(res, '✗ Invalid target', 'err'); return res.end(); }

  send(res, `$ whois ${target}`, 'info');
  send(res, '');

  await streamCommand(res, 'whois', [target], { timeout: 30000, lootAll: true });
  res.end();
});

// ── DNS ───────────────────────────────────────────────────────────────────────
app.post('/run/dns', async (req, res) => {
  startSSE(res);
  const domain = safeTarget(req.body.domain);
  const validTypes = ['A','MX','NS','TXT','CNAME','ANY'];
  const type   = validTypes.includes(req.body.type) ? req.body.type : 'A';

  if (!domain) { send(res, '✗ Invalid domain', 'err'); return res.end(); }

  send(res, `$ dig ${type} ${domain} +noall +answer`, 'info');
  send(res, '');

  if (type === 'ALL') {
    for (const t of ['A','MX','NS','TXT']) {
      send(res, `\n;; === ${t} Records ===`, 'info');
      await streamCommand(res, 'dig', [t, domain, '+noall', '+answer'], { timeout: 15000, lootAll: true });
    }
  } else {
    await streamCommand(res, 'dig', [type, domain, '+noall', '+answer'], { timeout: 15000, lootAll: true });
  }

  res.end();
});

// ── SSL ───────────────────────────────────────────────────────────────────────
app.post('/run/ssl', async (req, res) => {
  startSSE(res);
  const host = safeTarget(req.body.host);
  const port = safePort(req.body.port) || 443;
  if (!host) { send(res, '✗ Invalid host', 'err'); return res.end(); }

  send(res, `$ openssl s_client -connect ${host}:${port} -brief`, 'info');
  send(res, '');

  // Run openssl s_client — pipe empty input to trigger handshake then close
  const proc = spawn('openssl', ['s_client', '-connect', `${host}:${port}`, '-brief'], {
    timeout: 20000,
    env: { ...process.env }
  });

  // Send empty input so openssl proceeds
  proc.stdin.end();

  proc.stdout.on('data', d => {
    d.toString().split('\n').forEach(line => {
      if (line.trim()) {
        const type = line.includes('Verification error') || line.includes('self signed') ? 'warn'
                   : line.includes('Verify return code: 0') ? 'success' : 'out';
        send(res, line, type, true);
      }
    });
  });

  proc.stderr.on('data', d => {
    d.toString().split('\n').forEach(line => {
      if (line.trim()) {
        const type = line.includes('error') ? 'err' : 'out';
        send(res, line, type, line.includes('Protocol') || line.includes('Cipher') || line.includes('Certificate'));
      }
    });
  });

  await new Promise(resolve => proc.on('close', resolve));

  // Also get certificate details
  send(res, '', 'out');
  send(res, ';; Certificate details:', 'info');

  const certProc = spawn('openssl', [
    's_client', '-connect', `${host}:${port}`,
    '-showcerts', '-servername', host
  ], { timeout: 15000 });

  certProc.stdin.end();

  let certOutput = '';
  certProc.stdout.on('data', d => { certOutput += d.toString(); });
  certProc.stderr.on('data', () => {});
  await new Promise(resolve => certProc.on('close', resolve));

  // Extract cert and parse it
  const certMatch = certOutput.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/);
  if (certMatch) {
    const parseProc = spawn('openssl', ['x509', '-noout', '-text', '-subject', '-issuer', '-dates', '-fingerprint'], {
      timeout: 10000
    });
    parseProc.stdin.write(certMatch[0]);
    parseProc.stdin.end();
    parseProc.stdout.on('data', d => {
      d.toString().split('\n').forEach(line => {
        if (line.trim() && (
          line.includes('Subject:') || line.includes('Issuer:') ||
          line.includes('Not Before') || line.includes('Not After') ||
          line.includes('DNS:') || line.includes('Fingerprint') ||
          line.includes('Public-Key')
        )) {
          send(res, line.trim(), 'out', true);
        }
      });
    });
    parseProc.stderr.on('data', () => {});
    await new Promise(resolve => parseProc.on('close', resolve));
  }

  res.end();
});

// ── PING / TRACEROUTE ─────────────────────────────────────────────────────────
app.post('/run/ping', async (req, res) => {
  startSSE(res);
  const target = safeTarget(req.body.target);
  const mode   = req.body.mode === 'trace' ? 'trace' : 'ping';
  if (!target) { send(res, '✗ Invalid target', 'err'); return res.end(); }

  if (mode === 'ping') {
    send(res, `$ ping -c 5 ${target}`, 'info');
    send(res, '');
    await streamCommand(res, 'ping', ['-c', '5', target], { timeout: 30000, lootAll: true });
  } else {
    send(res, `$ traceroute ${target}`, 'info');
    send(res, '');
    // Try traceroute, fall back to tracepath
    const code = await streamCommand(res, 'traceroute', ['-m', '20', target], { timeout: 60000, lootAll: true });
    if (code !== 0) {
      await streamCommand(res, 'tracepath', [target], { timeout: 60000, lootAll: true });
    }
  }

  res.end();
});

// ── HTTP HEADERS ──────────────────────────────────────────────────────────────
app.post('/run/headers', async (req, res) => {
  startSSE(res);
  const url    = safeUrl(req.body.url);
  const method = ['HEAD','GET','OPTIONS'].includes(req.body.method) ? req.body.method : 'HEAD';
  if (!url) { send(res, '✗ Invalid URL', 'err'); return res.end(); }

  send(res, `$ curl -v -I -X ${method} --max-time 15 "${url}"`, 'info');
  send(res, '');

  const args = [
    '-v', '-I', '-X', method,
    '--max-time', '15',
    '--user-agent', 'Obscurum-Scanner/1.0',
    url
  ];

  const proc = spawn('curl', args, { timeout: 20000 });
  proc.stdin.end();

  const secHeaders = ['strict-transport-security','x-frame-options','x-content-type-options','content-security-policy','x-xss-protection','referrer-policy','permissions-policy'];

  proc.stdout.on('data', d => {
    d.toString().split('\n').forEach(line => {
      if (line.trim()) send(res, line, 'out', true);
    });
  });

  proc.stderr.on('data', d => {
    d.toString().split('\n').forEach(line => {
      if (!line.trim()) return;
      // curl sends headers to stderr with -v
      const lower = line.toLowerCase();
      const isSec = secHeaders.some(h => lower.includes(h));
      const isHeader = line.startsWith('<') || line.startsWith('>') || line.startsWith('*');
      if (isHeader) {
        const type = isSec ? 'success' : lower.includes('error') ? 'err' : 'out';
        send(res, line, type, isSec || lower.includes('http/'));
      }
    });
  });

  // After headers, check for missing security headers
  await new Promise(resolve => proc.on('close', resolve));

  send(res, '', 'out');
  send(res, ';; Security header audit:', 'info');

  // Fetch just headers in a parseable way
  const auditProc = spawn('curl', ['-s', '-I', '-X', method, '--max-time', '10', url], { timeout: 15000 });
  auditProc.stdin.end();
  let headerOutput = '';
  auditProc.stdout.on('data', d => { headerOutput += d.toString(); });
  auditProc.stderr.on('data', () => {});
  await new Promise(resolve => auditProc.on('close', resolve));

  const lower = headerOutput.toLowerCase();
  secHeaders.forEach(h => {
    const present = lower.includes(h + ':');
    send(res, `  ${present ? '✓' : '⚠'} ${h}: ${present ? 'present' : 'MISSING'}`, present ? 'success' : 'warn', true);
  });

  res.end();
});

// ── UNIFI ─────────────────────────────────────────────────────────────────────
app.post('/run/unifi', async (req, res) => {
  startSSE(res);
  const host = safeTarget(req.body.host);
  const port = safePort(req.body.port) || 8443;
  const op   = req.body.op;

  if (!host) { send(res, '✗ Invalid host', 'err'); return res.end(); }

  const baseUrl = `https://${host}:${port}`;

  if (op === 'discover') {
    send(res, `$ nmap -sV -p 8443,8080,8880,8843,3478,6789 ${host}`, 'info');
    send(res, '');
    await streamCommand(res, 'nmap', ['-sV', '-p', '8443,8080,8880,8843,3478,6789', host], { timeout: 60000, lootAll: true });

  } else if (op === 'portcheck') {
    send(res, `$ nmap -p 8443,8080,22,443,80 ${host}`, 'info');
    send(res, '');
    await streamCommand(res, 'nmap', ['-p', '8443,8080,22,443,80', host], { timeout: 60000, lootAll: true });

  } else if (op === 'sysinfo') {
    send(res, `$ curl -sk ${baseUrl}/status`, 'info');
    send(res, '');
    await streamCommand(res, 'curl', ['-sk', '--max-time', '10', `${baseUrl}/status`], { timeout: 15000, lootAll: true });

  } else if (op === 'devlist') {
    send(res, `$ curl -sk ${baseUrl}/api/s/default/stat/device`, 'info');
    send(res, '');
    await streamCommand(res, 'curl', ['-sk', '--max-time', '10', `${baseUrl}/api/s/default/stat/device`], { timeout: 15000, lootAll: true });

  } else if (op === 'firmware') {
    send(res, `$ curl -sk ${baseUrl}/api/s/default/stat/device | python3 -m json.tool`, 'info');
    send(res, '');
    const proc = spawn('bash', ['-c', `curl -sk --max-time 10 "${baseUrl}/api/s/default/stat/device" | python3 -m json.tool 2>/dev/null || echo "Could not parse JSON response"`], { timeout: 20000 });
    proc.stdin.end();
    proc.stdout.on('data', d => d.toString().split('\n').forEach(l => { if(l.trim()) send(res, l, 'out', l.includes('version')); }));
    proc.stderr.on('data', () => {});
    await new Promise(resolve => proc.on('close', resolve));

  } else if (op === 'sslcheck') {
    send(res, `$ openssl s_client -connect ${host}:${port} -brief`, 'info');
    send(res, '');
    const proc = spawn('openssl', ['s_client', '-connect', `${host}:${port}`, '-brief'], { timeout: 15000 });
    proc.stdin.end();
    proc.stdout.on('data', d => d.toString().split('\n').forEach(l => { if(l.trim()) send(res, l, l.includes('error') ? 'warn' : 'out', true); }));
    proc.stderr.on('data', d => d.toString().split('\n').forEach(l => { if(l.trim()) send(res, l, 'out', l.includes('Protocol') || l.includes('Cipher')); }));
    await new Promise(resolve => proc.on('close', resolve));

    // TLS version check
    send(res, '', 'out');
    send(res, ';; TLS version audit:', 'info');
    for (const tlsVer of ['tls1', 'tls1_1']) {
      const p2 = spawn('openssl', ['s_client', '-connect', `${host}:${port}`, `-${tlsVer}`], { timeout: 10000 });
      p2.stdin.end();
      let out = '';
      p2.stdout.on('data', d => { out += d.toString(); });
      p2.stderr.on('data', d => { out += d.toString(); });
      await new Promise(resolve => p2.on('close', resolve));
      const accepted = out.includes('CONNECTED') && !out.includes('alert');
      send(res, `  ${accepted ? '⚠' : '✓'} ${tlsVer.replace('_','.')}: ${accepted ? 'ACCEPTED (weak!)' : 'rejected'}`, accepted ? 'warn' : 'success', true);
    }

  } else if (op === 'sshcheck') {
    send(res, `$ ssh -vn -o ConnectTimeout=5 ${host} 2>&1 | head -30`, 'info');
    send(res, '');
    const proc = spawn('ssh', ['-vn', '-o', 'ConnectTimeout=5', '-o', 'StrictHostKeyChecking=no', '-o', 'BatchMode=yes', host], { timeout: 15000 });
    proc.stdin.end();
    const handleSSH = d => {
      d.toString().split('\n').forEach(l => {
        if (!l.trim()) return;
        const isKey = l.includes('kex') || l.includes('cipher') || l.includes('mac') || l.includes('host key') || l.includes('banner') || l.includes('SSH-');
        send(res, l, 'out', isKey);
      });
    };
    proc.stdout.on('data', handleSSH);
    proc.stderr.on('data', handleSSH);
    await new Promise(resolve => proc.on('close', resolve));

  } else if (op === 'apicheck') {
    const endpoints = [
      '/status',
      '/api/self',
      '/api/s/default/stat/health',
      '/api/s/default/stat/device',
      '/api/s/default/stat/sta',
      '/api/s/default/rest/user',
      '/manage/account/login',
    ];

    send(res, `;; Probing ${baseUrl} API endpoints`, 'info');
    send(res, '');

    for (const ep of endpoints) {
      const proc = spawn('curl', ['-sk', '-o', '/dev/null', '-w', '%{http_code}', '--max-time', '5', `${baseUrl}${ep}`], { timeout: 10000 });
      proc.stdin.end();
      let code = '';
      proc.stdout.on('data', d => { code += d.toString().trim(); });
      proc.stderr.on('data', () => {});
      await new Promise(resolve => proc.on('close', resolve));
      const status = code || 'timeout';
      const type = status === '200' ? 'success' : status === '401' ? 'warn' : status === '404' ? 'out' : 'err';
      send(res, `  ${status}  ${ep}${status === '401' ? ' (auth required)' : status === '200' ? ' (accessible)' : ''}`, type, true);
    }
  } else {
    send(res, '✗ Unknown operation: ' + op, 'err');
  }

  res.end();
});

// ── Start ─────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n  ✦ Obscurum Backend ✦`);
  console.log(`  Listening on http://localhost:${PORT}`);
  console.log(`  WARNING: Only use on systems you own or have permission to test.\n`);
});
