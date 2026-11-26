// Turns a text sample into a real capture file (Ethernet / IPv4 / UDP), with
// optional RTP streams, so the pcap reader can be tested and demoed without
// using anyone's real traffic.
//
//   node tools/make-pcap.js              -> writes samples/one-way-audio.pcap
//
// Also used by the tests to build pcap and pcapng files in memory.
const fs = require('fs');
const path = require('path');
const P = require('../src/parser.js');

function ipBytes(ip) { return ip.split('.').map(Number); }

function checksum(buf) {
  let sum = 0;
  for (let i = 0; i < buf.length; i += 2) sum += (buf[i] << 8) + (buf[i + 1] || 0);
  while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
  return (~sum) & 0xffff;
}

function frame(src, sport, dst, dport, payload) {
  const udp = Buffer.alloc(8 + payload.length);
  udp.writeUInt16BE(sport, 0); udp.writeUInt16BE(dport, 2); udp.writeUInt16BE(udp.length, 4);
  payload.copy(udp, 8);
  const ip = Buffer.alloc(20);
  ip[0] = 0x45; ip.writeUInt16BE(20 + udp.length, 2); ip.writeUInt16BE(Math.floor(Math.random() * 65535), 4);
  ip[8] = 64; ip[9] = 17;
  Buffer.from(ipBytes(src)).copy(ip, 12); Buffer.from(ipBytes(dst)).copy(ip, 16);
  ip.writeUInt16BE(checksum(ip), 10);
  const eth = Buffer.from([0x02, 0, 0, 0, 0, 2, 0x02, 0, 0, 0, 0, 1, 0x08, 0x00]);
  return Buffer.concat([eth, ip, udp]);
}

function rtpPacket(pt, seq, ts, ssrc) {
  const b = Buffer.alloc(12 + 160, 0xd5); // 20 ms of G.711 a-law silence
  b[0] = 0x80; b[1] = pt; b.writeUInt16BE(seq & 0xffff, 2); b.writeUInt32BE(ts >>> 0, 4); b.writeUInt32BE(ssrc >>> 0, 8);
  return b;
}

/**
 * text: a sample trace with address lines. opts.rtp: [{ from:'ip:port', to:'ip:port', start, end, pt }]
 * opts.shift: { after, by } moves messages later than `after` seconds earlier by `by` seconds.
 * Returns a list of { ts, data } with absolute timestamps.
 */
function packets(text, opts = {}) {
  const parsed = P.parseTrace(text);
  const base = Date.UTC(2026, 10, 26, 10, 15, 2) / 1000;
  const out = [];
  parsed.messages.forEach((m) => {
    let t = m.time;
    if (opts.shift && t > opts.shift.after) t -= opts.shift.by;
    const body = m.lines.join('\r\n').replace(/(\r\n)+$/, '') + '\r\n' + (m.sdp ? '' : '\r\n');
    const sipText = m.sdp ? m.lines.slice(0, m.lines.indexOf('') + 1).join('\r\n') + '\r\n' + m.body.split('\n').join('\r\n') + '\r\n' : body;
    out.push({ ts: base + t, data: frame(m.meta.src.ip, m.meta.src.port, m.meta.dst.ip, m.meta.dst.port, Buffer.from(sipText, 'utf8')) });
  });
  (opts.rtp || []).forEach((s, i) => {
    const [fip, fport] = s.from.split(':'); const [tip, tport] = s.to.split(':');
    let seq = 1000 * (i + 1), ts = 160000 * (i + 1);
    for (let t = s.start; t <= s.end; t += 0.02) {
      out.push({ ts: base + t, data: frame(fip, +fport, tip, +tport, rtpPacket(s.pt || 8, seq++, ts, 0x5ac0de00 + i)) });
      ts += 160;
    }
  });
  return out.sort((a, b) => a.ts - b.ts);
}

function toPcap(list) {
  const head = Buffer.alloc(24);
  head.writeUInt32LE(0xa1b2c3d4, 0); head.writeUInt16LE(2, 4); head.writeUInt16LE(4, 6);
  head.writeUInt32LE(65535, 16); head.writeUInt32LE(1, 20);
  const recs = list.map((p) => {
    const h = Buffer.alloc(16);
    const sec = Math.floor(p.ts);
    h.writeUInt32LE(sec, 0); h.writeUInt32LE(Math.round((p.ts - sec) * 1e6), 4);
    h.writeUInt32LE(p.data.length, 8); h.writeUInt32LE(p.data.length, 12);
    return Buffer.concat([h, p.data]);
  });
  return Buffer.concat([head].concat(recs));
}

function toPcapng(list) {
  const block = (type, body) => {
    const padded = Buffer.concat([body, Buffer.alloc((4 - (body.length % 4)) % 4)]);
    const b = Buffer.alloc(12 + padded.length);
    b.writeUInt32LE(type, 0); b.writeUInt32LE(b.length, 4); padded.copy(b, 8); b.writeUInt32LE(b.length, b.length - 4);
    return b;
  };
  const shb = Buffer.alloc(16); shb.writeUInt32LE(0x1a2b3c4d, 0); shb.writeUInt16LE(1, 4); shb.writeInt32LE(-1, 8); shb.writeInt32LE(-1, 12);
  // Interface with nanosecond timestamps (if_tsresol = 9) to exercise that path.
  const idb = Buffer.alloc(8 + 8 + 4); idb.writeUInt16LE(1, 0); idb.writeUInt32LE(65535, 4);
  idb.writeUInt16LE(9, 8); idb.writeUInt16LE(1, 10); idb[12] = 9; // option if_tsresol
  const parts = [block(0x0a0d0d0a, shb), block(1, idb)];
  list.forEach((p) => {
    const ns = BigInt(Math.round(p.ts * 1e6)) * 1000n;
    const h = Buffer.alloc(20);
    h.writeUInt32LE(0, 0); h.writeUInt32LE(Number(ns >> 32n), 4); h.writeUInt32LE(Number(ns & 0xffffffffn), 8);
    h.writeUInt32LE(p.data.length, 12); h.writeUInt32LE(p.data.length, 16);
    parts.push(block(6, Buffer.concat([h, p.data])));
  });
  return Buffer.concat(parts);
}

// The one-way audio call, shortened so the file stays small, captured on the
// SBC's access side: audio from the phone arrives, audio back is sent to the
// private address in the phone's SDP and never makes it.
const ONE_WAY = {
  shift: { after: 10, by: 32 },
  rtp: [
    { from: '203.0.113.24:41010', to: '198.51.100.10:30002', start: 3.95, end: 9.15 },
    { from: '198.51.100.10:30002', to: '192.168.1.45:12000', start: 3.96, end: 9.15 }
  ]
};

module.exports = { packets, toPcap, toPcapng, ONE_WAY };

if (require.main === module) {
  const dir = path.join(__dirname, '..', 'samples');
  const text = fs.readFileSync(path.join(dir, 'one-way-audio.txt'), 'utf8');
  const file = path.join(dir, 'one-way-audio.pcap');
  fs.writeFileSync(file, toPcap(packets(text, ONE_WAY)));
  console.log('Wrote ' + path.relative(process.cwd(), file) + ' (' + fs.statSync(file).size + ' bytes)');
}
