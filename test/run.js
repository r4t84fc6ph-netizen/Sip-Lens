// Run with: node test/run.js
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const P = require('../src/parser.js');
const R = require('../src/rules.js');

const dir = path.join(__dirname, '..', 'samples');
const load = (f) => P.parseTrace(fs.readFileSync(path.join(dir, f), 'utf8'));

let passed = 0;
function test(name, fn) {
  try { fn(); passed++; console.log('  ok   ' + name); }
  catch (e) { console.log('  FAIL ' + name + '\n       ' + e.message); process.exitCode = 1; }
}

console.log('Parser');
test('splits a trace into messages', () => {
  const p = load('one-way-audio.txt');
  assert.strictEqual(p.messages.length, 13);
  assert.strictEqual(p.messages[0].method, 'INVITE');
  assert.strictEqual(p.messages[1].status, 100);
});
test('reads network addresses and relative times', () => {
  const m = load('one-way-audio.txt').messages;
  assert.strictEqual(m[0].meta.src.ip, '203.0.113.24');
  assert.strictEqual(m[0].time, 0);
  assert.strictEqual(m[9].time, 41.206);
});
test('parses SDP connection and media', () => {
  const sdp = load('one-way-audio.txt').messages[0].sdp;
  assert.strictEqual(sdp.connection.address, '192.168.1.45');
  assert.deepStrictEqual(sdp.media[0].payloads, [0, 8, 101]);
});
test('understands compact header names', () => {
  const p = P.parseTrace('OPTIONS sip:a@b SIP/2.0\ni: abc\nv: SIP/2.0/UDP 10.0.0.1\n\n');
  assert.strictEqual(p.messages[0].callId, 'abc');
  assert.strictEqual(P.header(p.messages[0], 'via'), 'SIP/2.0/UDP 10.0.0.1');
});
test('works on pasted messages without network lines', () => {
  const text = fs.readFileSync(path.join(dir, 'one-way-audio.txt'), 'utf8').replace(/^U .*$/gm, '');
  const p = P.parseTrace(text);
  assert.strictEqual(p.messages.length, 13);
  assert.strictEqual(p.messages[0].time, null);
});
test('private address detection', () => {
  assert.ok(P.isPrivateIp('192.168.1.45'));
  assert.ok(P.isPrivateIp('172.20.0.1'));
  assert.ok(P.isPrivateIp('100.64.1.1'));
  assert.ok(!P.isPrivateIp('172.32.0.1'));
  assert.ok(!P.isPrivateIp('203.0.113.24'));
});
test('anonymiser masks numbers and keeps private IPs', () => {
  const a = P.makeAnonymiser();
  assert.strictEqual(a('sip:+351212345142@x'), 'sip:+3512•••••142@x');
  assert.strictEqual(a('sip:201@x'), 'sip:201@x');
  assert.strictEqual(a('c=IN IP4 192.168.1.45'), 'c=IN IP4 192.168.1.45');
  const first = a('8.8.8.8');
  assert.notStrictEqual(first, '8.8.8.8');
  assert.strictEqual(a('again 8.8.8.8'), 'again ' + first); // consistent
});

console.log('Diagnosis');
const expect = {
  'one-way-audio.txt': 'nat-audio',
  'codec-488.txt': 'codec',
  'auth-loop-407.txt': 'auth',
  'missing-ack.txt': 'missing-ack',
  'rejected-404.txt': 'rejected'
};
Object.keys(expect).forEach((file) => {
  test(file + ' -> ' + expect[file], () => {
    const d = R.diagnose(load(file));
    assert.ok(d.findings.length, 'no findings');
    assert.strictEqual(d.findings[0].rule, expect[file]);
    assert.strictEqual(d.findings[0].confidence, 'high');
    assert.ok(d.findings[0].evidence.length >= 2, 'needs at least 2 pieces of evidence');
  });
});
test('a healthy call has no findings', () => {
  const ok = [
    'INVITE sip:+351212345142@sbc.example.net SIP/2.0', 'Call-ID: good1', 'CSeq: 1 INVITE', 'Content-Type: application/sdp', '',
    'v=0', 'c=IN IP4 198.51.100.77', 'm=audio 4000 RTP/AVP 8', '',
    'SIP/2.0 200 OK', 'Call-ID: good1', 'CSeq: 1 INVITE', '',
    'ACK sip:+351212345142@sbc.example.net SIP/2.0', 'Call-ID: good1', 'CSeq: 1 ACK', ''
  ].join('\n');
  assert.strictEqual(R.diagnose(P.parseTrace(ok)).findings.length, 0);
});
test('codec names come from the SDP', () => {
  const d = R.diagnose(load('codec-488.txt'));
  assert.ok(/G\.729/.test(d.findings[0].summary));
  assert.strictEqual(d.findings[0].legs, 2);
});

console.log('Captures');
const C = require('../src/pcap.js');
const M = require('../tools/make-pcap.js');
const asAB = (buf) => buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.length);
const oneWayText = fs.readFileSync(path.join(dir, 'one-way-audio.txt'), 'utf8');

test('reads the sample .pcap: SIP and RTP', () => {
  const p = C.parseCapture(asAB(fs.readFileSync(path.join(dir, 'one-way-audio.pcap'))));
  assert.strictEqual(p.source.format, 'pcap');
  assert.strictEqual(p.messages.length, 13);
  assert.strictEqual(p.messages[0].meta.src.ip, '203.0.113.24');
  assert.strictEqual(p.rtp.length, 2);
  assert.ok(p.rtp.every((s) => s.packets > 200 && s.lost === 0));
});
test('reads the same call as .pcapng with nanosecond timestamps', () => {
  const p = C.parseCapture(asAB(M.toPcapng(M.packets(oneWayText, M.ONE_WAY))));
  assert.strictEqual(p.source.format, 'pcapng');
  assert.strictEqual(p.messages.length, 13);
  assert.strictEqual(p.messages[6].time, 3.808);
  assert.strictEqual(p.rtp[0].start, 3.95);
});
test('RTP confirms one-way audio', () => {
  const p = C.parseCapture(asAB(fs.readFileSync(path.join(dir, 'one-way-audio.pcap'))));
  const f = R.diagnose(p).findings[0];
  assert.strictEqual(f.rule, 'nat-audio');
  assert.strictEqual(f.kind, 'error');
  assert.strictEqual(f.caveat, null);
  assert.ok(f.media.stream && f.media.stream.dst === '192.168.1.45');
  assert.ok(f.evidence.some((e) => e.kind === 'rtp' && /260 audio packets were sent/.test(e.note)));
});
test('no false alarm when the server already handles NAT', () => {
  const opts = { shift: M.ONE_WAY.shift, rtp: [
    { from: '203.0.113.24:41010', to: '198.51.100.10:30002', start: 3.95, end: 6 },
    { from: '198.51.100.10:30002', to: '203.0.113.24:41010', start: 3.96, end: 6 }
  ] };
  const p = C.parseCapture(asAB(M.toPcap(M.packets(oneWayText, opts))));
  const f = R.diagnose(p).findings[0];
  assert.strictEqual(f.kind, 'info');
  assert.strictEqual(f.badge, 'Handled');
});
test('reassembles a SIP message split into IPv4 fragments', () => {
  const pk = M.packets(oneWayText, { shift: M.ONE_WAY.shift })[0];
  const frame = pk.data;                 // Ethernet + IPv4 + UDP + INVITE
  const ip = frame.subarray(14);
  const ihl = (ip[0] & 15) * 4;
  const l4 = ip.subarray(ihl);
  const cut = 200;                       // must be a multiple of 8
  const mk = (part, offset, more) => {
    const h = Buffer.from(ip.subarray(0, ihl));
    h.writeUInt16BE(ihl + part.length, 2);
    h.writeUInt16BE((more ? 0x2000 : 0) | (offset / 8), 6);
    return Buffer.concat([frame.subarray(0, 14), h, part]);
  };
  const list = [{ ts: pk.ts, data: mk(l4.subarray(cut), cut, false) }, { ts: pk.ts, data: mk(l4.subarray(0, cut), 0, true) }];
  const p = C.parseCapture(asAB(M.toPcap(list)));
  assert.strictEqual(p.messages.length, 1);
  assert.strictEqual(p.messages[0].sdp.connection.address, '192.168.1.45');
});
test('understands VLAN tags', () => {
  const pk = M.packets(oneWayText, {})[1];
  const tagged = Buffer.concat([pk.data.subarray(0, 12), Buffer.from([0x81, 0, 0, 10]), pk.data.subarray(12)]);
  const p = C.parseCapture(asAB(M.toPcap([{ ts: pk.ts, data: tagged }])));
  assert.strictEqual(p.messages.length, 1);
  assert.strictEqual(p.messages[0].status, 100);
});
test('rejects files that are not captures', () => {
  assert.ok(!C.isCapture(asAB(Buffer.from('INVITE sip:a@b SIP/2.0\r\n\r\n'.repeat(3)))));
  assert.throws(() => C.readCapture(asAB(Buffer.alloc(64))));
});

console.log('\n' + passed + ' passed' + (process.exitCode ? ', some failed' : ''));
