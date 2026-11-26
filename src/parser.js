/*
 * SIP Lens - parser
 * Turns a SIP trace in text form into a list of messages.
 * Runs in the browser (window.SIPLens) and in Node (module.exports).
 *
 * Supported input:
 *  - ngrep / sngrep style:   "U 2026/11/26 10:15:02.123456 192.168.1.45:5060 -> 198.51.100.10:5060"
 *  - Wireshark-like lines:   "10:15:02.123 192.168.1.45:5060 -> 198.51.100.10:5060"
 *  - plain SIP messages pasted one after another (no network info)
 */
(function (root) {
  'use strict';

  var METHODS = 'INVITE|ACK|BYE|CANCEL|REGISTER|OPTIONS|PRACK|UPDATE|INFO|REFER|NOTIFY|SUBSCRIBE|MESSAGE|PUBLISH';
  var REQUEST_LINE = new RegExp('^(' + METHODS + ')\\s+(\\S+)\\s+SIP\\/2\\.0\\s*$', 'i');
  var STATUS_LINE = /^SIP\/2\.0\s+(\d{3})\s*(.*)$/i;
  var ENDPOINTS = /(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})\s*-+>\s*(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})/;
  var TIME = /(\d{1,2}):(\d{2}):(\d{2}(?:\.\d+)?)/;

  // RFC 3261 compact header forms
  var COMPACT = { v: 'via', f: 'from', t: 'to', i: 'call-id', m: 'contact', l: 'content-length', c: 'content-type', k: 'supported', s: 'subject', e: 'content-encoding' };

  function isStartLine(line) {
    return REQUEST_LINE.test(line) || STATUS_LINE.test(line);
  }

  function parseMeta(line) {
    var meta = {};
    var e = ENDPOINTS.exec(line);
    if (e) {
      meta.src = { ip: e[1], port: Number(e[2]) };
      meta.dst = { ip: e[3], port: Number(e[4]) };
    }
    var t = TIME.exec(line);
    if (t) meta.clock = Number(t[1]) * 3600 + Number(t[2]) * 60 + Number(t[3]);
    return meta;
  }

  function parseSdp(lines, firstLineNo) {
    var sdp = { media: [], attributes: [], lines: [] };
    lines.forEach(function (raw, i) {
      var line = raw.trim();
      var m = /^([a-z])=(.*)$/.exec(line);
      if (!m) return;
      var entry = { type: m[1], value: m[2], lineNo: firstLineNo + i };
      sdp.lines.push(entry);
      if (m[1] === 'c') {
        var c = /^IN\s+IP[46]\s+(\S+)/.exec(m[2]);
        var conn = { address: c ? c[1] : m[2], lineNo: entry.lineNo };
        if (sdp.media.length) sdp.media[sdp.media.length - 1].connection = conn;
        else sdp.connection = conn;
      } else if (m[1] === 'o') {
        sdp.origin = { value: m[2], lineNo: entry.lineNo };
      } else if (m[1] === 'm') {
        var parts = m[2].split(/\s+/);
        sdp.media.push({ kind: parts[0], port: Number(parts[1]), proto: parts[2], payloads: parts.slice(3).map(Number), lineNo: entry.lineNo, rtpmap: {} });
      } else if (m[1] === 'a') {
        var rtp = /^rtpmap:(\d+)\s+([^\/\s]+)/.exec(m[2]);
        if (rtp && sdp.media.length) sdp.media[sdp.media.length - 1].rtpmap[rtp[1]] = rtp[2];
        if (/^(sendrecv|sendonly|recvonly|inactive)$/.test(m[2])) {
          if (sdp.media.length) sdp.media[sdp.media.length - 1].direction = m[2];
          else sdp.direction = m[2];
        }
        sdp.attributes.push(entry);
      }
    });
    return sdp;
  }

  function parseMessage(block) {
    // block: { lines: [string], meta }
    var lines = block.lines;
    var start = lines[0].trim();
    var msg = { raw: lines.join('\n'), lines: lines.slice(), headers: [], meta: block.meta || {} };
    var req = REQUEST_LINE.exec(start);
    var res = STATUS_LINE.exec(start);
    if (req) {
      msg.isRequest = true;
      msg.method = req[1].toUpperCase();
      msg.uri = req[2];
      msg.label = msg.method;
    } else {
      msg.isRequest = false;
      msg.status = Number(res[1]);
      msg.reason = res[2].trim();
      msg.label = msg.status + ' ' + msg.reason;
    }

    var i = 1;
    for (; i < lines.length; i++) {
      var line = lines[i];
      if (line.trim() === '') { i++; break; }
      if (/^[ \t]/.test(line) && msg.headers.length) { // folded header
        msg.headers[msg.headers.length - 1].value += ' ' + line.trim();
        continue;
      }
      var h = /^([A-Za-z0-9\-_.!%*+`'~]+)\s*:\s*(.*)$/.exec(line);
      if (!h) continue;
      var name = h[1].toLowerCase();
      if (COMPACT[name]) name = COMPACT[name];
      msg.headers.push({ name: name, display: h[1], value: h[2].trim(), lineNo: i });
    }

    var bodyLines = lines.slice(i);
    while (bodyLines.length && bodyLines[bodyLines.length - 1].trim() === '') bodyLines.pop();
    msg.body = bodyLines.join('\n');
    var ctype = header(msg, 'content-type');
    if (bodyLines.length && (!ctype || /sdp/i.test(ctype)) && bodyLines.some(function (l) { return /^v=0/.test(l.trim()); })) {
      msg.sdp = parseSdp(bodyLines, i);
    }

    msg.callId = header(msg, 'call-id') || '';
    var cseq = /^(\d+)\s+(\S+)/.exec(header(msg, 'cseq') || '');
    msg.cseq = cseq ? { num: Number(cseq[1]), method: cseq[2].toUpperCase() } : null;
    return msg;
  }

  function headers(msg, name) {
    return msg.headers.filter(function (h) { return h.name === name; });
  }

  function header(msg, name) {
    var h = headers(msg, name)[0];
    return h ? h.value : null;
  }

  /** Split raw trace text into SIP messages. */
  function parseTrace(text) {
    var all = String(text || '').replace(/\r\n?/g, '\n').split('\n');
    var blocks = [];
    var current = null;
    var pendingMeta = null;

    for (var n = 0; n < all.length; n++) {
      var line = all[n].replace(/\s+$/, '');
      var trimmed = line.trim();
      if (isStartLine(trimmed)) {
        if (current) blocks.push(current);
        current = { lines: [trimmed], meta: pendingMeta || {} };
        pendingMeta = null;
        continue;
      }
      // A metadata line (addresses ->) belongs to the next message.
      if (ENDPOINTS.test(trimmed) && !/^[A-Za-z\-]+\s*:/.test(trimmed)) {
        if (current) { blocks.push(current); current = null; }
        pendingMeta = parseMeta(trimmed);
        continue;
      }
      // Separators used by some tools
      if (/^(-{3,}|={3,}|#\s*$)/.test(trimmed)) {
        if (current) { blocks.push(current); current = null; }
        continue;
      }
      if (current) current.lines.push(line);
    }
    if (current) blocks.push(current);

    var messages = blocks.map(parseMessage);

    // Relative times
    var firstClock = null;
    messages.forEach(function (m, idx) {
      m.index = idx + 1;
      if (typeof m.meta.clock === 'number') {
        if (firstClock === null) firstClock = m.meta.clock;
        var t = m.meta.clock - firstClock;
        if (t < 0) t += 86400; // crossed midnight
        m.time = Math.round(t * 1000) / 1000;
      } else {
        m.time = null;
      }
    });

    return { messages: messages, participants: participants(messages) };
  }

  /** Distinct hosts in order of first appearance, used as ladder lanes. */
  function participants(messages) {
    var list = [];
    var seen = {};
    function add(ep) {
      if (!ep) return;
      var key = ep.ip;
      if (!seen[key]) { seen[key] = { id: key, ip: ep.ip, ports: [] }; list.push(seen[key]); }
      if (seen[key].ports.indexOf(ep.port) < 0) seen[key].ports.push(ep.port);
    }
    messages.forEach(function (m) { add(m.meta.src); add(m.meta.dst); });
    return list;
  }

  /* ---------- Address helpers ---------- */

  function ipToInt(ip) {
    var p = ip.split('.').map(Number);
    if (p.length !== 4 || p.some(function (x) { return isNaN(x) || x < 0 || x > 255; })) return null;
    return ((p[0] << 24) >>> 0) + (p[1] << 16) + (p[2] << 8) + p[3];
  }

  function inRange(ip, base, bits) {
    var a = ipToInt(ip), b = ipToInt(base);
    if (a === null || b === null) return false;
    var mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
    return ((a & mask) >>> 0) === ((b & mask) >>> 0);
  }

  /** RFC 1918 private ranges plus carrier-grade NAT (RFC 6598). */
  function isPrivateIp(ip) {
    return inRange(ip, '10.0.0.0', 8) || inRange(ip, '172.16.0.0', 12) || inRange(ip, '192.168.0.0', 16) || inRange(ip, '100.64.0.0', 10);
  }

  function isIpv4(s) { return ipToInt(s) !== null; }

  function isPublicIp(ip) {
    return isIpv4(ip) && !isPrivateIp(ip) && !inRange(ip, '127.0.0.0', 8) && !inRange(ip, '169.254.0.0', 16) && ip !== '0.0.0.0';
  }

  /* ---------- Anonymiser ---------- */

  /**
   * Masks phone numbers in SIP/tel URIs (keeps the last 3 digits) and replaces
   * public IPs consistently. Private ranges are kept: they often explain the fault.
   * Documentation ranges (RFC 5737) are already fictional and are left as they are.
   */
  function isDocRange(ip) {
    return inRange(ip, '192.0.2.0', 24) || inRange(ip, '198.51.100.0', 24) || inRange(ip, '203.0.113.0', 24);
  }

  /** Returns a function that anonymises strings, with the same replacements across calls. */
  function makeAnonymiser() {
    var ipMap = {};
    var next = 101;
    return function (text) {
      var out = String(text == null ? '' : text).replace(/\b(\d{1,3}(?:\.\d{1,3}){3})\b/g, function (ip) {
        if (!isPublicIp(ip) || isDocRange(ip)) return ip;
        if (!ipMap[ip]) ipMap[ip] = '203.0.113.' + Math.min(next++, 254);
        return ipMap[ip];
      });
      // Phone numbers in SIP/tel URIs: keep the first 4 and last 3 digits.
      return out.replace(/((?:sips?|tel):)(\+?)(\d{7,})(?=[@;>\s"]|$)/g, function (all, scheme, plus, digits) {
        return scheme + plus + digits.slice(0, 4) + digits.slice(4, -3).replace(/\d/g, '•') + digits.slice(-3);
      });
    };
  }

  function anonymise(text) { return makeAnonymiser()(text); }

  var api = {
    parseTrace: parseTrace,
    header: header,
    headers: headers,
    isPrivateIp: isPrivateIp,
    isPublicIp: isPublicIp,
    isIpv4: isIpv4,
    anonymise: anonymise,
    makeAnonymiser: makeAnonymiser
  };

  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else { root.SIPLens = root.SIPLens || {}; Object.keys(api).forEach(function (k) { root.SIPLens[k] = api[k]; }); }
})(this);
