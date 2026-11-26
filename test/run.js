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

console.log('\n' + passed + ' passed' + (process.exitCode ? ', some failed' : ''));
