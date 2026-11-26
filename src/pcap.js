/*
 * SIP Lens - capture reader
 * Reads .pcap and .pcapng files in the browser, pulls out the SIP messages and
 * counts the RTP audio streams. The SIP part is turned into the same text format
 * the parser already understands, so the rest of the app doesn't care where a
 * trace came from.
 *
 * Supported: pcap (micro and nanosecond), pcapng; Ethernet (with VLAN tags),
 * Linux cooked capture v1/v2, raw IP and BSD loopback; IPv4 (with fragment
 * reassembly) and IPv6; SIP over UDP and TCP (one segment at a time).
 */
(function (root) {
  'use strict';

  /* ---------------- Capture file formats ---------------- */

  function readPcap(view) {
    var magicLE = view.getUint32(0, true);
    var little, nano;
    if (magicLE === 0xa1b2c3d4) { little = true; nano = false; }
    else if (magicLE === 0xa1b23c4d) { little = true; nano = true; }
    else if (view.getUint32(0, false) === 0xa1b2c3d4) { little = false; nano = false; }
    else if (view.getUint32(0, false) === 0xa1b23c4d) { little = false; nano = true; }
    else return null;

    var linkType = view.getUint32(20, little) & 0xffff;
    var packets = [];
    var off = 24;
    while (off + 16 <= view.byteLength) {
      var sec = view.getUint32(off, little);
      var frac = view.getUint32(off + 4, little);
      var len = view.getUint32(off + 8, little);
      off += 16;
      if (off + len > view.byteLength) break; // truncated file
      packets.push({ ts: sec + frac / (nano ? 1e9 : 1e6), data: new Uint8Array(view.buffer, view.byteOffset + off, len), linkType: linkType });
      off += len;
    }
    return { format: 'pcap', packets: packets };
  }

  function readPcapng(view) {
    if (view.getUint32(0, true) !== 0x0a0d0d0a) return null;
    var packets = [];
    var interfaces = [];
    var little = true;
    var off = 0;
    while (off + 12 <= view.byteLength) {
      var type = view.getUint32(off, little);
      if (type === 0x0a0d0d0a) { // Section Header: byte order may change per section
        little = view.getUint32(off + 8, true) === 0x1a2b3c4d;
        interfaces = [];
      }
      var total = view.getUint32(off + 4, little);
      if (total < 12 || off + total > view.byteLength) break;
      var body = off + 8;

      if (type === 1) { // Interface Description
        var iface = { linkType: view.getUint16(body, little), tsres: 1e-6 };
        var opt = body + 8;
        while (opt + 4 <= off + total - 4) {
          var code = view.getUint16(opt, little);
          var olen = view.getUint16(opt + 2, little);
          if (code === 0) break;
          if (code === 9 && olen >= 1) { // if_tsresol
            var r = view.getUint8(opt + 4);
            iface.tsres = (r & 0x80) ? Math.pow(2, -(r & 0x7f)) : Math.pow(10, -r);
          }
          opt += 4 + Math.ceil(olen / 4) * 4;
        }
        interfaces.push(iface);
      } else if (type === 6) { // Enhanced Packet
        var ifc = interfaces[view.getUint32(body, little)] || { linkType: 1, tsres: 1e-6 };
        var ts = (view.getUint32(body + 4, little) * 4294967296 + view.getUint32(body + 8, little)) * ifc.tsres;
        var cap = view.getUint32(body + 12, little);
        packets.push({ ts: ts, data: new Uint8Array(view.buffer, view.byteOffset + body + 20, cap), linkType: ifc.linkType });
      } else if (type === 3) { // Simple Packet (no timestamp)
        var ifs = interfaces[0] || { linkType: 1 };
        var slen = Math.min(view.getUint32(body, little), total - 16);
        packets.push({ ts: null, data: new Uint8Array(view.buffer, view.byteOffset + body + 4, slen), linkType: ifs.linkType });
      }
      off += total;
    }
    return { format: 'pcapng', packets: packets };
  }

  function isCapture(buffer) {
    if (!buffer || buffer.byteLength < 24) return false;
    var v = new DataView(buffer);
    var m = v.getUint32(0, true);
    return m === 0x0a0d0d0a || m === 0xa1b2c3d4 || m === 0xa1b23c4d || v.getUint32(0, false) === 0xa1b2c3d4 || v.getUint32(0, false) === 0xa1b23c4d;
  }

  /* ---------------- Network layers ---------------- */

  function ipv4(b, o) { return b[o] + '.' + b[o + 1] + '.' + b[o + 2] + '.' + b[o + 3]; }

  function ipv6(b, o) {
    var parts = [];
    for (var i = 0; i < 16; i += 2) parts.push(((b[o + i] << 8) | b[o + i + 1]).toString(16));
    return parts.join(':').replace(/(^|:)0(:0)+(:|$)/, '::').replace(/:{3,}/, '::');
  }

  /** Finds the IP header inside a frame. Returns { offset, version } or null. */
  function ipStart(b, linkType) {
    var o, etype;
    switch (linkType) {
      case 1: // Ethernet
        o = 12; etype = (b[o] << 8) | b[o + 1];
        while (etype === 0x8100 || etype === 0x88a8) { o += 4; etype = (b[o] << 8) | b[o + 1]; }
        o += 2;
        break;
      case 113: // Linux cooked v1
        etype = (b[14] << 8) | b[15]; o = 16; break;
      case 276: // Linux cooked v2
        etype = (b[0] << 8) | b[1]; o = 20; break;
      case 0: case 108: // BSD loopback: 4-byte address family
        o = 4; etype = (b[4] >> 4) === 6 ? 0x86dd : 0x0800; break;
      case 101: case 12: case 14: case 228: case 229: // raw IP
        o = 0; etype = (b[0] >> 4) === 6 ? 0x86dd : 0x0800; break;
      default:
        return null;
    }
    if (o >= b.length) return null;
    if (etype === 0x0800) return { offset: o, version: 4 };
    if (etype === 0x86dd) return { offset: o, version: 6 };
    return null;
  }

  function Reassembler() { this.parts = {}; }
  /** Collects IPv4 fragments; returns the full payload once every piece has arrived. */
  Reassembler.prototype.add = function (key, offset, more, data) {
    var e = this.parts[key] || (this.parts[key] = { pieces: [], total: null });
    e.pieces.push({ offset: offset, data: data });
    if (!more) e.total = offset + data.length;
    if (e.total === null) return null;
    var have = 0;
    e.pieces.forEach(function (p) { have += p.data.length; });
    if (have < e.total) return null;
    var out = new Uint8Array(e.total);
    e.pieces.forEach(function (p) { out.set(p.data.subarray(0, Math.max(0, Math.min(p.data.length, e.total - p.offset))), p.offset); });
    delete this.parts[key];
    return out;
  };

  /** Frame -> { src, dst, proto, sport, dport, payload } for UDP and TCP, else null. */
  function decode(pkt, frag) {
    var b = pkt.data;
    var ip = ipStart(b, pkt.linkType);
    if (!ip) return null;
    var o = ip.offset, src, dst, proto, l4;

    if (ip.version === 4) {
      if (o + 20 > b.length) return null;
      var ihl = (b[o] & 0x0f) * 4;
      var totalLen = (b[o + 2] << 8) | b[o + 3];
      var flagsFrag = (b[o + 6] << 8) | b[o + 7];
      proto = b[o + 9];
      src = ipv4(b, o + 12); dst = ipv4(b, o + 16);
      var end = Math.min(b.length, o + (totalLen || (b.length - o)));
      l4 = b.subarray(o + ihl, end);
      var more = (flagsFrag & 0x2000) !== 0, fragOff = (flagsFrag & 0x1fff) * 8;
      if (more || fragOff) {
        var id = (b[o + 4] << 8) | b[o + 5];
        l4 = frag.add(src + '>' + dst + '#' + id + '/' + proto, fragOff, more, l4.slice());
        if (!l4) return null;
      }
    } else {
      if (o + 40 > b.length) return null;
      proto = b[o + 6];
      src = ipv6(b, o + 8); dst = ipv6(b, o + 24);
      var p = o + 40;
      while ((proto === 0 || proto === 43 || proto === 60) && p + 8 <= b.length) { proto = b[p]; p += (b[p + 1] + 1) * 8; }
      l4 = b.subarray(p);
    }

    if (proto === 17 && l4.length >= 8) {
      var ulen = (l4[4] << 8) | l4[5];
      return { src: src, dst: dst, proto: 'UDP', sport: (l4[0] << 8) | l4[1], dport: (l4[2] << 8) | l4[3], payload: l4.subarray(8, ulen >= 8 ? Math.min(ulen, l4.length) : l4.length) };
    }
    if (proto === 6 && l4.length >= 20) {
      var doff = (l4[12] >> 4) * 4;
      return { src: src, dst: dst, proto: 'TCP', sport: (l4[0] << 8) | l4[1], dport: (l4[2] << 8) | l4[3], payload: l4.subarray(doff) };
    }
    return null;
  }

  /* ---------------- Application layer ---------------- */

  var SIP_START = /^(?:(?:INVITE|ACK|BYE|CANCEL|REGISTER|OPTIONS|PRACK|UPDATE|INFO|REFER|NOTIFY|SUBSCRIBE|MESSAGE|PUBLISH) \S+ SIP\/2\.0|SIP\/2\.0 \d{3} )/;

  function latin1(bytes) {
    var s = '';
    for (var i = 0; i < bytes.length; i += 8192) s += String.fromCharCode.apply(null, bytes.subarray(i, i + 8192));
    return s;
  }

  function utf8(bytes) {
    try { return new TextDecoder('utf-8').decode(bytes); } catch (e) { return latin1(bytes); }
  }

  /** RTP version 2, a real payload type (not RTCP 200-204), at least a full header. */
  function looksLikeRtp(p) {
    if (p.length < 12 || (p[0] >> 6) !== 2) return false;
    var pt = p[1] & 0x7f;
    if (pt >= 72 && pt <= 76) return false; // RTCP
    return pt <= 34 || pt >= 96;
  }

  function pad(n, w) { n = String(n); while (n.length < w) n = '0' + n; return n; }

  function stamp(ts) {
    if (ts === null) return '';
    var d = new Date(Math.floor(ts) * 1000);
    var micro = Math.round((ts - Math.floor(ts)) * 1e6);
    if (micro === 1e6) micro = 999999;
    return d.getUTCFullYear() + '/' + pad(d.getUTCMonth() + 1, 2) + '/' + pad(d.getUTCDate(), 2) + ' ' +
      pad(d.getUTCHours(), 2) + ':' + pad(d.getUTCMinutes(), 2) + ':' + pad(d.getUTCSeconds(), 2) + '.' + pad(micro, 6);
  }

  /**
   * Reads a capture. Returns:
   *  { format, packetCount, sipText, firstSipTs, rtp: [stream], skipped }
   * where each RTP stream is { src, sport, dst, dport, ssrc, payloadType, packets, first, last, lost }.
   */
  function readCapture(buffer) {
    var view = new DataView(buffer);
    var cap = readPcapng(view) || readPcap(view);
    if (!cap) throw new Error('This file doesn’t look like a pcap or pcapng capture.');

    var frag = new Reassembler();
    var sip = [];
    var streams = {};
    var order = [];
    var skipped = 0;

    cap.packets.forEach(function (pkt) {
      var d;
      try { d = decode(pkt, frag); } catch (e) { d = null; }
      if (!d || !d.payload.length) { skipped++; return; }
      var head = latin1(d.payload.subarray(0, 64));
      if (SIP_START.test(head)) {
        sip.push({ ts: pkt.ts, src: d.src, sport: d.sport, dst: d.dst, dport: d.dport, text: utf8(d.payload) });
        return;
      }
      if (d.proto === 'UDP' && looksLikeRtp(d.payload)) {
        var p = d.payload;
        var ssrc = ((p[8] << 24) >>> 0) + (p[9] << 16) + (p[10] << 8) + p[11];
        var key = d.src + ':' + d.sport + '>' + d.dst + ':' + d.dport + '#' + ssrc;
        var s = streams[key];
        var seq = (p[2] << 8) | p[3];
        if (!s) {
          s = streams[key] = { src: d.src, sport: d.sport, dst: d.dst, dport: d.dport, ssrc: ssrc, payloadType: p[1] & 0x7f, packets: 0, first: pkt.ts, last: pkt.ts, firstSeq: seq, maxSeq: seq, cycles: 0 };
          order.push(key);
        }
        s.packets++;
        if (pkt.ts !== null) s.last = pkt.ts;
        if (seq > s.maxSeq || (s.maxSeq - seq) > 30000) { if (seq < s.maxSeq) s.cycles++; s.maxSeq = seq; }
        return;
      }
      skipped++;
    });

    var lines = [];
    sip.forEach(function (m) {
      lines.push('U ' + stamp(m.ts) + ' ' + m.src + ':' + m.sport + ' -> ' + m.dst + ':' + m.dport);
      lines.push(m.text.replace(/\r\n/g, '\n').replace(/\n+$/, ''));
      lines.push('');
    });

    var rtp = order.map(function (k) {
      var s = streams[k];
      var expected = s.cycles * 65536 + s.maxSeq - s.firstSeq + 1;
      return { src: s.src, sport: s.sport, dst: s.dst, dport: s.dport, ssrc: s.ssrc, payloadType: s.payloadType, packets: s.packets, first: s.first, last: s.last, lost: Math.max(0, expected - s.packets) };
    }).filter(function (s) { return s.packets >= 5; }); // a few stray packets aren't a stream

    return { format: cap.format, packetCount: cap.packets.length, sipText: lines.join('\n'), firstSipTs: sip.length ? sip[0].ts : null, rtp: rtp, skipped: skipped };
  }

  /** Capture -> the same shape parseTrace returns, plus rtp streams timed like the messages. */
  function parseCapture(buffer) {
    var P = (typeof module !== 'undefined' && module.exports) ? require('./parser.js') : root.SIPLens;
    var cap = readCapture(buffer);
    var parsed = P.parseTrace(cap.sipText);
    var base = cap.firstSipTs;
    parsed.rtp = cap.rtp.map(function (s) {
      s.start = (base !== null && s.first !== null) ? Math.round((s.first - base) * 1000) / 1000 : null;
      s.end = (base !== null && s.last !== null) ? Math.round((s.last - base) * 1000) / 1000 : null;
      return s;
    });
    parsed.source = { format: cap.format, packets: cap.packetCount, skipped: cap.skipped };
    return parsed;
  }

  var api = { readCapture: readCapture, isCapture: isCapture, parseCapture: parseCapture };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else { root.SIPLens = root.SIPLens || {}; Object.keys(api).forEach(function (k) { root.SIPLens[k] = api[k]; }); }
})(this);
