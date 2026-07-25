import { connect } from "cloudflare:sockets";

// This is the plain-text password clients enter / see in their share link.
// Changing this is the ONLY thing you need to do to rotate the password —
// the wire-format hash below is derived from it automatically, so the two
// values can never drift out of sync again.
let plainPassword = 'ygsyafgGGFud123';

function rrot(x, n) { return (x >>> n) | (x << (32 - n)); }

// Standard SHA-224 (FIPS 180-4). The Trojan protocol requires the
// connection header to carry SHA224(password) as a 56-char hex string.
function sha224Hex(message) {
    const K = [
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
    ];
    let H = [0xc1059ed8,0x367cd507,0x3070dd17,0xf70e5939,0xffc00b31,0x68581511,0x64f98fa7,0xbefa4fa4];
    const msgBytes = new TextEncoder().encode(message);
    const bitLen = BigInt(msgBytes.length) * 8n;
    let withOne = new Uint8Array(msgBytes.length + 1);
    withOne.set(msgBytes);
    withOne[msgBytes.length] = 0x80;
    let totalLen = withOne.length;
    while (totalLen % 64 !== 56) totalLen++;
    const padded = new Uint8Array(totalLen + 8);
    padded.set(withOne);
    for (let i = 0; i < 8; i++) {
        padded[padded.length - 1 - i] = Number((bitLen >> BigInt(8 * i)) & 0xffn);
    }
    const view = new DataView(padded.buffer);
    for (let start = 0; start < padded.length; start += 64) {
        const w = new Uint32Array(64);
        for (let i = 0; i < 16; i++) w[i] = view.getUint32(start + i * 4, false);
        for (let i = 16; i < 64; i++) {
            const s0 = rrot(w[i-15],7) ^ rrot(w[i-15],18) ^ (w[i-15] >>> 3);
            const s1 = rrot(w[i-2],17) ^ rrot(w[i-2],19) ^ (w[i-2] >>> 10);
            w[i] = (w[i-16] + s0 + w[i-7] + s1) >>> 0;
        }
        let [a,b,c,d,e,f,g,h] = H;
        for (let i = 0; i < 64; i++) {
            const S1 = rrot(e,6) ^ rrot(e,11) ^ rrot(e,25);
            const ch = (e & f) ^ (~e & g);
            const t1 = (h + S1 + ch + K[i] + w[i]) >>> 0;
            const S0 = rrot(a,2) ^ rrot(a,13) ^ rrot(a,22);
            const maj = (a & b) ^ (a & c) ^ (b & c);
            const t2 = (S0 + maj) >>> 0;
            h=g; g=f; f=e; e=(d+t1)>>>0; d=c; c=b; b=a; a=(t1+t2)>>>0;
        }
        H[0]=(H[0]+a)>>>0; H[1]=(H[1]+b)>>>0; H[2]=(H[2]+c)>>>0; H[3]=(H[3]+d)>>>0;
        H[4]=(H[4]+e)>>>0; H[5]=(H[5]+f)>>>0; H[6]=(H[6]+g)>>>0; H[7]=(H[7]+h)>>>0;
    }
    return H.slice(0,7).map(x => x.toString(16).padStart(8,'0')).join('');
}

// Wire-format password used for header validation — derived, never edited directly.
let k1 = sha224Hex(plainPassword);

const h2 = [
    "workers.cloudflare.cyou",
    "cdn-all.xn--b6gac.eu.org",
    "cdn.xn--b6gac.eu.org",
    "cdn-b100.xn--b6gac.eu.org",
    "edgetunnel.anycast.eu.org",
    "cdn.anycast.eu.org",
];

const T1 = 5000;

function sanitizeHost(h) {
    return (h || "").replace(/[^a-zA-Z0-9.-]/g, "");
}

function buildConfigUri(host) {
    const qs = [
        "security=tls",
        `sni=${host}`,
        "fp=chrome",
        "type=ws",
        `host=${host}`,
        "path=/",
        "max_early_data=2560",
        "early_data_header_name=Sec-WebSocket-Protocol"
    ].join("&");
    return `trojan://${plainPassword}@${host}:443?${qs}#main`;
}

function renderPanel(uri) {
    return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Config</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<style>
  :root {
    --bg:#0c0d12; --surface:#15161f; --border:#2a2d3d; --text:#eceef5;
    --text-dim:#9497ab; --accent:#9b8cff; --accent-2:#57d9c6;
  }
  * { box-sizing:border-box; }
  html,body { margin:0; padding:0; background:var(--bg); color:var(--text); font-family:'Inter',sans-serif; -webkit-font-smoothing:antialiased; }
  body {
    min-height:100vh; display:flex; align-items:center; justify-content:center; padding:24px;
    background:
      radial-gradient(1200px 500px at 15% -10%, #2a1f4a33, transparent),
      radial-gradient(900px 500px at 110% 10%, #10352e33, transparent),
      var(--bg);
  }
  .card {
    width:100%; max-width:380px; background:var(--surface); border:1px solid var(--border);
    border-radius:18px; padding:28px 24px; text-align:center;
  }
  .eyebrow { font-size:12px; color:var(--accent-2); letter-spacing:.05em; font-weight:600; text-transform:uppercase; }
  h1 { font-size:20px; font-weight:700; margin:6px 0 20px; }
  #qrHost { display:flex; justify-content:center; padding:16px; background:#fff; border-radius:14px; margin-bottom:18px; }
  .link-box {
    background:#0e0f16; border:1px solid #1f2130; border-radius:10px; padding:12px 13px;
    font-family:'JetBrains Mono',monospace; font-size:11.5px; line-height:1.6; color:#c9cbe0;
    word-break:break-all; text-align:left; direction:ltr; margin-bottom:14px;
  }
  button {
    font-family:inherit; font-size:13px; font-weight:700; border-radius:10px; padding:11px 18px;
    cursor:pointer; border:1px solid transparent; background:var(--accent); color:#14101f; width:100%;
    transition:background .15s;
  }
  button:hover { background:#ab9eff; }
  .toast {
    position:fixed; bottom:22px; left:50%; transform:translateX(-50%) translateY(20px);
    background:var(--surface); border:1px solid var(--border); color:var(--text);
    padding:10px 18px; border-radius:999px; font-size:12.5px; font-weight:600;
    opacity:0; pointer-events:none; transition:all .25s ease;
  }
  .toast.show { opacity:1; transform:translateX(-50%) translateY(0); }
</style>
</head>
<body>
  <div class="card">
    <span class="eyebrow">Connection</span>
    <h1>Scan to configure</h1>
    <div id="qrHost"></div>
    <div class="link-box" id="uriBox">${uri}</div>
    <button id="copyBtn">Copy link</button>
  </div>
  <div class="toast" id="toast">Copied</div>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js"></script>
  <script>
    new QRCode(document.getElementById('qrHost'), {
      text: ${JSON.stringify(uri)},
      width: 220, height: 220,
      correctLevel: QRCode.CorrectLevel.M
    });
    document.getElementById('copyBtn').addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(${JSON.stringify(uri)});
        const t = document.getElementById('toast');
        t.classList.add('show');
        setTimeout(() => t.classList.remove('show'), 1800);
      } catch (e) {}
    });
  </script>
</body>
</html>`;
}

const worker_default = {
    async fetch(request, env, ctx) {
        try {
            const e1 = env.PROXYIP;
            const u1 = request.headers.get("Upgrade");
            if (!u1 || u1 !== "websocket") {
                const url = new URL(request.url);
                const host = sanitizeHost(request.headers.get('Host'));
                switch (url.pathname) {
                    case "/panel":
                        return new Response(renderPanel(buildConfigUri(host)), {
                            status: 200,
                            headers: { "Content-Type": "text/html;charset=utf-8" }
                        });
                    case "/links":
                        return new Response(buildConfigUri(host), {
                            status: 200,
                            headers: { "Content-Type": "text/plain;charset=utf-8" }
                        });
                    default:
                        return new Response("200 OK", { status: 200 });
                }
            } else {
                return await f1(request, e1);
            }
        } catch (err) {
            return new Response(err.toString(), { status: 500 });
        }
    }
};

async function f1(request, e1) {
    const wp = new WebSocketPair();
    const [c1, s1] = Object.values(wp);
    s1.accept();

    let a1 = "";
    let a2 = "";
    const lg = (m1, m2) => {
        console.log(`[${a1}:${a2}] ${m1}`, m2 || "");
    };

    const eh = request.headers.get("sec-websocket-protocol") || "";
    const rs = m1(s1, eh, lg);

    let so = { value: null };
    let cp = null;

    rs.pipeTo(new WritableStream({
        async write(chunk, controller) {
            if (so.value) {
                const w = so.value.writable.getWriter();
                try {
                    await w.write(chunk);
                } finally {
                    w.releaseLock();
                }
                return;
            }

            if (cp) {
                await cp;
                if (so.value) {
                    const w = so.value.writable.getWriter();
                    try {
                        await w.write(chunk);
                    } finally {
                        w.releaseLock();
                    }
                }
                return;
            }

            const {
                hasError,
                message,
                portRemote = 443,
                addressRemote = "",
                rawClientData
            } = await p1(chunk);

            a1 = addressRemote;
            a2 = `${portRemote}--${Math.random()}`;

            if (hasError) {
                throw new Error(message);
            }

            cp = h1(so, addressRemote, portRemote, rawClientData, s1, lg, e1);
            await cp;
        },
        close() {
            lg(`closed`);
        },
        abort(reason) {
            lg(`aborted`, JSON.stringify(reason));
        }
    })).catch((err) => {
        lg("pipe error", err);
        c2(s1);
    });

    return new Response(null, {
        status: 101,
        // @ts-ignore
        webSocket: c1
    });
}

async function p1(buffer) {
    if (buffer.byteLength < 56) {
        return { hasError: true, message: "invalid data" };
    }
    let idx = 56;
    if (new Uint8Array(buffer.slice(56, 57))[0] !== 0x0d || new Uint8Array(buffer.slice(57, 58))[0] !== 0x0a) {
        return { hasError: true, message: "invalid header format (missing CR LF)" };
    }
    const pw = new TextDecoder().decode(buffer.slice(0, idx));
    if (pw !== k1) {
        return { hasError: true, message: "invalid password" };
    }

    const db = buffer.slice(idx + 2);
    if (db.byteLength < 6) {
        return { hasError: true, message: "invalid request data" };
    }

    const view = new DataView(db);
    const cmd = view.getUint8(0);
    if (cmd !== 1) {
        return { hasError: true, message: "unsupported command" };
    }

    const atype = view.getUint8(1);
    let al = 0;
    let ai = 2;
    let addr = "";
    switch (atype) {
        case 1:
            al = 4;
            addr = new Uint8Array(db.slice(ai, ai + al)).join(".");
            break;
        case 3:
            al = new Uint8Array(db.slice(ai, ai + 1))[0];
            ai += 1;
            addr = new TextDecoder().decode(db.slice(ai, ai + al));
            break;
        case 4: {
            al = 16;
            const dv = new DataView(db.slice(ai, ai + al));
            const parts = [];
            for (let i = 0; i < 8; i++) {
                parts.push(dv.getUint16(i * 2).toString(16));
            }
            addr = parts.join(":");
            break;
        }
        default:
            return { hasError: true, message: `invalid addressType is ${atype}` };
    }

    if (!addr) {
        return { hasError: true, message: `address is empty, addressType is ${atype}` };
    }

    const pi = ai + al;
    const pb = db.slice(pi, pi + 2);
    const port = new DataView(pb).getUint16(0);
    return {
        hasError: false,
        addressRemote: addr,
        portRemote: port,
        rawClientData: db.slice(pi + 4)
    };
}

function c3(hostname, port, timeoutMs) {
    return new Promise((resolve, reject) => {
        let done = false;
        const timer = setTimeout(() => {
            if (!done) {
                done = true;
                reject(new Error(`timeout ${hostname}:${port}`));
            }
        }, timeoutMs);
        try {
            const sock = connect({ hostname, port });
            done = true;
            clearTimeout(timer);
            resolve(sock);
        } catch (err) {
            if (!done) {
                done = true;
                clearTimeout(timer);
                reject(err);
            }
        }
    });
}

async function h1(so, addressRemote, portRemote, rawClientData, s1, lg, e1) {
    async function w1(hostname, port) {
        const sock = await c3(hostname, port, T1);
        so.value = sock;
        lg(`open ${hostname}:${port}`);
        const w = sock.writable.getWriter();
        try {
            await w.write(rawClientData);
        } finally {
            w.releaseLock();
        }
        return sock;
    }

    const list = [];
    if (e1) list.push(e1);
    const shuffled = [...h2];
    for (let i = shuffled.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
    }
    for (const p of shuffled) {
        if (!list.includes(p)) list.push(p);
    }

    async function n1(hosts, i) {
        if (i >= hosts.length) {
            lg(`exhausted for ${addressRemote}:${portRemote}`);
            c2(s1);
            return;
        }
        const host = hosts[i];
        try {
            const sock = await w1(host, portRemote);
            sock.closed
                .catch((error) => lg("closed error", error))
                .finally(() => c2(s1));
            r1(sock, s1, () => n1(hosts, i + 1), lg);
        } catch (err) {
            lg(`attempt via ${host} failed`, err);
            await n1(hosts, i + 1);
        }
    }

    try {
        const sock = await w1(addressRemote, portRemote);
        r1(sock, s1, () => n1(list, 0), lg);
    } catch (err) {
        lg(`direct failed for ${addressRemote}:${portRemote}`, err);
        await n1(list, 0);
    }
}

function m1(server, eh, lg) {
    let cancelled = false;
    const stream = new ReadableStream({
        start(controller) {
            server.addEventListener("message", (event) => {
                if (cancelled) return;
                controller.enqueue(event.data);
            });
            server.addEventListener("close", () => {
                c2(server);
                if (cancelled) return;
                controller.close();
            });
            server.addEventListener("error", (err) => {
                lg("server error");
                controller.error(err);
            });
            const { earlyData, error } = b1(eh);
            if (error) {
                controller.error(error);
            } else if (earlyData) {
                controller.enqueue(earlyData);
            }
        },
        pull(controller) {},
        cancel(reason) {
            if (cancelled) return;
            lg(`cancelled: ${reason}`);
            cancelled = true;
            c2(server);
        }
    });
    return stream;
}

async function r1(sock, s1, retry, lg) {
    let got = false;
    await sock.readable.pipeTo(
        new WritableStream({
            start() {},
            async write(chunk, controller) {
                got = true;
                if (s1.readyState !== WS_OPEN) {
                    controller.error("socket not open");
                    return;
                }
                s1.send(chunk);
            },
            close() {
                lg(`closed, got: ${got}`);
            },
            abort(reason) {
                lg("abort", reason);
            }
        })
    ).catch((error) => {
        lg(`pipe error:`, error.stack || error);
        if (got === false && retry) {
            retry();
            return;
        }
        c2(s1);
    });

    if (got === false && retry) {
        lg(`no data, retrying`);
        retry();
    }
}

function b1(str) {
    if (!str) {
        return { error: null };
    }
    try {
        str = str.replace(/-/g, "+").replace(/_/g, "/");
        const decoded = atob(str);
        const buf = Uint8Array.from(decoded, (c) => c.charCodeAt(0));
        return { earlyData: buf.buffer, error: null };
    } catch (error) {
        return { error };
    }
}

const WS_OPEN = 1;
const WS_CLOSING = 2;

function c2(socket) {
    try {
        if (socket.readyState === WS_OPEN || socket.readyState === WS_CLOSING) {
            socket.close();
        }
    } catch (error) {
        console.error("close error", error);
    }
}

export { worker_default as default };
