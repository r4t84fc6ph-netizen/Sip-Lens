/*
 * SIP Lens - diagnosis rules
 * Each rule looks for the signature of one known failure and returns
 * findings with plain-language text, the evidence lines it used and fixes.
 * Rule of the house: no verdict without evidence the user can check.
 */
(function (root) {
  'use strict';

  var P = (typeof module !== 'undefined' && module.exports) ? require('./parser.js') : root.SIPLens;

  var CODECS = { 0: 'G.711 u-law (PCMU)', 3: 'GSM', 4: 'G.723', 8: 'G.711 a-law (PCMA)', 9: 'G.722', 18: 'G.729' };

  function codecNames(media) {
    return media.payloads.map(function (pt) {
      var name = media.rtpmap[pt];
      if (name && /telephone-event/i.test(name)) return null;
      if (pt < 96 && CODECS[pt]) return CODECS[pt]; // static payload types
      return name || ('payload ' + pt);
    }).filter(Boolean);
  }

  function lineOf(msg, name) {
    var h = P.headers(msg, name)[0];
    return h ? h.lineNo : 0;
  }

  function uriUser(uri) {
    var m = /^(?:sips?|tel):([^@;>]+)/i.exec(uri || '');
    return m ? m[1] : '';
  }

  function byCall(messages) {
    var calls = {};
    var order = [];
    messages.forEach(function (m) {
      var id = m.callId || '(no Call-ID)';
      if (!calls[id]) { calls[id] = []; order.push(id); }
      calls[id].push(m);
    });
    return order.map(function (id) { return { callId: id, messages: calls[id] }; });
  }

  function viaReceived(msgs) {
    for (var i = 0; i < msgs.length; i++) {
      var vias = P.headers(msgs[i], 'via');
      for (var j = 0; j < vias.length; j++) {
        var r = /;\s*received=([0-9.]+)/i.exec(vias[j].value);
        if (r && P.isPublicIp(r[1])) return { msg: msgs[i], lineNo: vias[j].lineNo, ip: r[1] };
      }
    }
    return null;
  }

  function isInviteFinal(m) { return !m.isRequest && m.cseq && m.cseq.method === 'INVITE' && m.status >= 200; }

  /* ---------------- Rule: rejected call ---------------- */

  var REJECTIONS = {
    403: { badge: 'Call rejected', title: 'The call was refused: this account isn’t allowed to make it.', summary: 'The other side understood the request and said no. The phone and the network are working.', fixes: [['Check the account can call this destination', 'International, premium or mobile numbers are often blocked by default on the trunk or the PBX.'], ['Check the caller ID being sent', 'Some carriers refuse calls with a caller ID that isn’t registered to the account.']] },
    404: { badge: 'Call rejected', title: 'The number that was dialled can’t be found.', summary: 'The other side answered straight away that it doesn’t know this number. The phone and the network are working: the problem is the number, or the format it was sent in.', fixes: [['Dial the number in full international format', 'For example +351 followed by the national number.'], ['Check the outbound route on the PBX', 'The dial plan may be removing or not adding the country code.']] },
    480: { badge: 'Not answered', title: 'The person isn’t available right now.', summary: 'The destination exists but couldn’t take the call: the phone may be offline, not registered or set to do not disturb.', fixes: [['Check the destination phone is registered', 'If it’s an extension on your PBX, look at its registration status.']] },
    484: { badge: 'Call rejected', title: 'The number is incomplete.', summary: 'The other side says digits are missing from the number.', fixes: [['Dial the full number', 'Include the country and area code.'], ['Check the dial plan', 'The PBX may be sending the call before all digits are dialled.']] },
    486: { badge: 'Busy', title: 'The person is busy.', summary: 'The destination is on another call and refused this one. There is nothing to fix.', fixes: [['Try again later', 'Or enable call waiting on the destination, if it’s yours.']] },
    487: { badge: 'Cancelled', title: 'The caller hung up before the call was answered.', summary: 'The call was cancelled while ringing. This is normal if someone gave up waiting.', fixes: [] },
    500: { badge: 'Server error', title: 'The server had an internal error.', summary: 'The other side failed while handling the call. This is usually not caused by your phone.', fixes: [['Try again', 'If it keeps happening, report it to the provider with this trace.']] },
    502: { badge: 'Server error', title: 'A server further along the path failed.', summary: 'A proxy received a bad answer from the next server.', fixes: [['Report it to the provider', 'Share this trace and the time of the call.']] },
    503: { badge: 'Service unavailable', title: 'The carrier or trunk is down or overloaded.', summary: 'The other side is temporarily unable to take calls.', fixes: [['Try again in a few minutes', 'If the problem stays, check the trunk status or use another route.'], ['Check the trunk registration', 'An expired or failed trunk registration can cause 503 on every call.']] },
    504: { badge: 'Timeout', title: 'A server further along the path didn’t answer in time.', summary: 'The call was lost between servers.', fixes: [['Report it to the provider', 'Share this trace and the time of the call.']] },
    603: { badge: 'Declined', title: 'The person declined the call.', summary: 'The destination rejected the call on purpose.', fixes: [] },
    600: { badge: 'Busy', title: 'The person is busy everywhere.', summary: 'All the destination’s devices refused the call.', fixes: [] }
  };

  function ruleRejected(call) {
    var final = call.messages.filter(isInviteFinal).filter(function (m) {
      return m.status >= 300 && [401, 407, 488, 606].indexOf(m.status) < 0;
    })[0];
    if (!final) return null;
    var info = REJECTIONS[final.status] || { badge: 'Call failed', title: 'The call failed with ' + final.label + '.', summary: 'The other side rejected the call with this code.', fixes: [] };
    var invite = call.messages.filter(function (m) { return m.isRequest && m.method === 'INVITE'; })[0];
    var evidence = [{ msg: final.index, lineNo: 0, text: final.lines[0], note: 'The final answer to the call.' }];
    ['warning', 'reason'].forEach(function (h) {
      var v = P.header(final, h);
      if (v) evidence.push({ msg: final.index, lineNo: lineOf(final, h), text: P.headers(final, h)[0].display + ': ' + v, note: 'Extra detail from the server.' });
    });
    if (invite && (final.status === 404 || final.status === 484)) {
      var user = uriUser(invite.uri);
      if (/^\d{6,}$/.test(user) && user.charAt(0) !== '+') {
        evidence.push({ msg: invite.index, lineNo: 0, text: invite.lines[0], note: 'The number was sent without a + or country code.' });
      }
    }
    return {
      id: 'rejected-' + final.status, rule: 'rejected', kind: final.status === 487 || final.status === 486 ? 'info' : 'error',
      badge: info.badge, code: final.label, title: info.title, summary: info.summary, confidence: 'high',
      failMsg: final.index, evidence: evidence,
      fixes: info.fixes.map(function (f, i) { return { title: f[0], detail: f[1], primary: i === 0 }; })
    };
  }

  /* ---------------- Rule: codec mismatch ---------------- */

  function ruleCodec(call) {
    var final = call.messages.filter(isInviteFinal).filter(function (m) { return m.status === 488 || m.status === 606; })[0];
    if (!final) return null;
    var offer = call.messages.filter(function (m) { return m.isRequest && m.method === 'INVITE' && m.sdp; })[0];
    var evidence = [{ msg: final.index, lineNo: 0, text: final.lines[0], note: 'The other side refused the media offer.' }];
    var offered = [];
    if (offer) {
      var audio = offer.sdp.media.filter(function (md) { return md.kind === 'audio'; })[0];
      if (audio) {
        offered = codecNames(audio);
        evidence.unshift({ msg: offer.index, lineNo: audio.lineNo, text: 'm=audio ' + audio.port + ' ' + audio.proto + ' ' + audio.payloads.join(' '), note: 'Audio formats offered: ' + (offered.join(', ') || 'none') + '.' });
      }
    }
    var warn = P.headers(final, 'warning')[0];
    if (warn) evidence.push({ msg: final.index, lineNo: warn.lineNo, text: warn.display + ': ' + warn.value, note: 'The server says why.' });
    var onlyG729 = offered.length === 1 && offered[0] === 'G.729';
    return {
      id: 'codec', rule: 'codec', kind: 'error', badge: 'Call rejected', code: final.label,
      title: 'The two sides have no audio format in common.',
      summary: (offered.length ? 'The call offered ' + offered.join(', ') + '. ' : '') + (offered.length === 1 ? 'The other side doesn’t accept it' : 'The other side doesn’t accept any of them') + ', so it refused the call before it rang.',
      confidence: offer ? 'high' : 'medium', failMsg: final.index, evidence: evidence,
      fixes: [
        { title: onlyG729 ? 'Enable G.711 (PCMA) on the phone' : 'Add G.711 (PCMA/PCMU) to the phone’s codec list', detail: 'Put it near the top. G.711 is accepted almost everywhere.', primary: true },
        { title: 'Or allow transcoding on the PBX or SBC', detail: 'If the phone must keep its codec, the server can convert between formats.' }
      ]
    };
  }

  /* ---------------- Rule: authentication loop ---------------- */

  function ruleAuth(call) {
    var challenges = call.messages.filter(function (m) { return !m.isRequest && (m.status === 401 || m.status === 407); });
    if (challenges.length < 2) return null;
    var method = challenges[0].cseq ? challenges[0].cseq.method : '';
    var succeeded = call.messages.some(function (m) { return !m.isRequest && m.status >= 200 && m.status < 300 && m.cseq && m.cseq.method === method; });
    if (succeeded) return null;
    var withCreds = call.messages.filter(function (m) { return m.isRequest && (P.header(m, 'authorization') || P.header(m, 'proxy-authorization')); });
    var evidence = [{ msg: challenges[challenges.length - 1].index, lineNo: 0, text: challenges[challenges.length - 1].lines[0], note: 'Challenged ' + challenges.length + ' times. A new challenge after every answer means the answer is wrong.' }];
    var user = '', realm = '';
    if (withCreds.length) {
      var m = withCreds[withCreds.length - 1];
      var name = P.header(m, 'proxy-authorization') ? 'proxy-authorization' : 'authorization';
      var v = P.header(m, name);
      user = (/username="([^"]*)"/i.exec(v) || [])[1] || '';
      realm = (/realm="([^"]*)"/i.exec(v) || [])[1] || '';
      evidence.unshift({ msg: m.index, lineNo: lineOf(m, name), text: 'username="' + user + '", realm="' + realm + '"', note: 'The credentials the phone used. Check these match the account.' });
    }
    return {
      id: 'auth', rule: 'auth', kind: 'error', badge: 'Authentication failed', code: challenges[0].status + ' repeated',
      title: 'The server keeps rejecting the ' + (method === 'REGISTER' ? 'registration' : 'phone’s credentials') + '.',
      summary: withCreds.length ? 'The phone answers every challenge, but the server refuses it each time. If the username is right, the password is the most likely problem.' : 'The server asks for credentials, but the phone never sends them. The account may not be set up on the phone.',
      confidence: withCreds.length ? 'high' : 'medium', failMsg: challenges[challenges.length - 1].index, evidence: evidence,
      fixes: [
        { title: 'Re-enter the SIP password on the phone', detail: 'Copy it from the PBX or provider portal. Watch for spaces at the start or end.', primary: true },
        { title: 'Check the auth ID', detail: 'Some providers use an authentication username that differs from the extension number' + (user ? ' (the phone sent "' + user + '")' : '') + '.' },
        { title: 'Check the realm and outbound proxy', detail: realm ? 'The phone answered for realm "' + realm + '". It should match the provider’s domain.' : 'They should match the provider’s settings.' }
      ]
    };
  }

  /* ---------------- Rule: 2xx never acknowledged ---------------- */

  function ruleMissingAck(call) {
    var oks = call.messages.filter(function (m) { return !m.isRequest && m.status >= 200 && m.status < 300 && m.cseq && m.cseq.method === 'INVITE'; });
    if (!oks.length) return null;
    var first = oks[0];
    var retrans = oks.filter(function (m) { return m.cseq.num === first.cseq.num; });
    var acks = call.messages.filter(function (m) { return m.isRequest && m.method === 'ACK' && m.cseq && m.cseq.num === first.cseq.num; });
    var lastOk = retrans[retrans.length - 1];
    var okAfterAck = acks.length && retrans.some(function (r) { return r.index > acks[0].index; });
    if (!acks.length && retrans.length < 2) return null;
    if (retrans.length < 3 && acks.length) return null;
    if (acks.length && !okAfterAck) return null;

    var evidence = [{ msg: lastOk.index, lineNo: 0, text: first.label + ' sent ' + retrans.length + ' times', note: 'The answer keeps being resent because no confirmation (ACK) reached its sender.' }];
    var contact = P.headers(first, 'contact')[0];
    var contactIp = contact ? (/@\[?([0-9.]+)/.exec(contact.value) || [])[1] : null;
    var cause = '';
    if (acks.length) {
      var ack = acks[0];
      var dst = ack.meta.dst ? ack.meta.dst.ip : (/@([0-9.]+)/.exec(ack.uri) || [])[1];
      if (dst && P.isPrivateIp(dst) && first.meta.src && P.isPublicIp(first.meta.src.ip)) {
        evidence.push({ msg: ack.index, lineNo: 0, text: ack.lines[0], note: 'The ACK was sent to ' + dst + ', a private address, but the answer came from ' + first.meta.src.ip + '.' });
        cause = 'nat';
      } else {
        evidence.push({ msg: ack.index, lineNo: 0, text: ack.lines[0], note: 'An ACK was sent, but the answer was still resent after it, so it didn’t arrive.' });
      }
    } else {
      evidence.push({ msg: first.index, lineNo: 0, text: 'No ACK for CSeq ' + first.cseq.num + ' in the trace', note: 'The confirmation never appears.' });
    }
    if (contact && contactIp && P.isPrivateIp(contactIp)) {
      evidence.push({ msg: first.index, lineNo: contact.lineNo, text: contact.display + ': ' + contact.value, note: 'The answer gives a private address as its contact, so requests inside the call are sent there.' });
      cause = cause || 'nat';
    }
    var bye = call.messages.filter(function (m) { return m.isRequest && m.method === 'BYE'; })[0];
    var after = (bye && bye.time !== null && first.time !== null) ? Math.round(bye.time - first.time) : null;
    if (bye) evidence.push({ msg: bye.index, lineNo: 0, text: bye.lines[0], note: after !== null ? 'The call is ended ' + after + ' s after the answer.' : 'The call is ended.' });

    return {
      id: 'missing-ack', rule: 'missing-ack', kind: 'error', badge: 'Call dropped', code: 'No ACK' + (after ? ' · ends at ' + after + ' s' : ''),
      title: 'The answer was never confirmed, so the call times out.',
      summary: 'The call was answered (' + first.label + '), but the confirmation (ACK) never reached the device that answered. It keeps resending its answer and then hangs up, usually after about 32 seconds.',
      confidence: cause ? 'high' : 'medium', failMsg: acks.length ? acks[0].index : lastOk.index, evidence: evidence,
      fixes: cause === 'nat' ? [
        { title: 'Turn on NAT handling for this device on the PBX or SBC', detail: 'Requests inside the call are then sent to its real public address, not the private one it advertises.', primary: true },
        { title: 'Turn off SIP ALG on the site router', detail: 'It often rewrites addresses in ways that break routing.' }
      ] : [
        { title: 'Check Record-Route on the PBX or SBC', detail: 'The ACK must follow the same path as the INVITE.', primary: true },
        { title: 'Check firewalls between the two sides', detail: 'Something may be dropping the ACK on its way.' }
      ]
    };
  }

  /* ---------------- Rule: private IP in SDP behind NAT ---------------- */

  function ruleNatAudio(call) {
    var withSdp = call.messages.filter(function (m) { return m.sdp; });
    for (var i = 0; i < withSdp.length; i++) {
      var m = withSdp[i];
      var audio = m.sdp.media.filter(function (md) { return md.kind === 'audio'; })[0];
      var conn = (audio && audio.connection) || m.sdp.connection;
      if (!conn || !P.isPrivateIp(conn.address)) continue;
      // Both ends on the same private network: no NAT involved.
      if (m.meta.src && m.meta.dst && P.isPrivateIp(m.meta.src.ip) && P.isPrivateIp(m.meta.dst.ip)) continue;

      var evidence = [{ msg: m.index, lineNo: conn.lineNo, text: 'c=IN IP4 ' + conn.address, note: 'Audio is to be sent here. ' + conn.address + ' is a private address: it only exists inside the local network.' }];
      var natSeen = null;
      if (m.meta.src && P.isPublicIp(m.meta.src.ip)) {
        natSeen = m.meta.src.ip;
        evidence.push({ msg: m.index, lineNo: 0, text: 'Packet source ' + m.meta.src.ip + ':' + m.meta.src.port, note: 'But the message itself arrived from a public address. The device is behind NAT.' });
      } else {
        var rec = viaReceived(call.messages);
        if (rec) {
          natSeen = rec.ip;
          evidence.push({ msg: rec.msg.index, lineNo: rec.lineNo, text: 'received=' + rec.ip, note: 'The server reports the request arrived from a different, public address. The device is behind NAT.' });
        }
      }
      var connected = call.messages.some(function (x) { return !x.isRequest && x.status >= 200 && x.status < 300 && x.cseq && x.cseq.method === 'INVITE'; }) &&
        call.messages.some(function (x) { return x.isRequest && x.method === 'ACK'; });
      var ackMsg = call.messages.filter(function (x) { return x.isRequest && x.method === 'ACK'; })[0];
      var media = (m.meta.src && m.meta.dst) ? {
        after: ackMsg ? ackMsg.index : m.index, from: m.meta.dst.ip, to: m.meta.src.ip,
        label: 'Return audio to ' + conn.address + ':' + (audio ? audio.port : '?')
      } : null;

      return {
        id: 'nat-audio', rule: 'nat-audio', kind: natSeen ? 'error' : 'warning', badge: natSeen ? 'Problem found' : 'Possible problem', code: 'Private IP in SDP',
        title: 'One-way audio: return audio is sent to a private address.',
        summary: (connected ? 'The call connected, but ' : '') + 'the device asked for audio to be sent to ' + conn.address + ', which can’t be reached from outside its network.' + (natSeen ? ' It sits behind NAT (seen as ' + natSeen + '), and NAT isn’t being handled, so the other side’s audio is likely lost.' : ' If the device is behind NAT, the other side’s audio will be lost.'),
        confidence: natSeen ? 'high' : 'medium', failMsg: m.index, evidence: evidence, media: media,
        caveat: 'Audio (RTP) isn\u2019t part of a text trace. A capture with RTP would confirm that the return audio never arrives.',
        fixes: [
          { title: 'Turn on NAT handling for this device on the PBX or SBC', detail: 'Often called symmetric RTP or "comedia": audio is sent back to where it really comes from, not to the address in the SDP.', primary: true },
          { title: 'Check the router at the site', detail: 'If SIP ALG is on, turn it off and test again.' },
          { title: 'Set NAT traversal on the device', detail: 'If the server can’t handle NAT, configure STUN or the site’s public address on the phone.' }
        ]
      };
    }
    return null;
  }

  /* ---------------- Run all rules ---------------- */

  var ORDER = [ruleCodec, ruleAuth, ruleRejected, ruleMissingAck, ruleNatAudio];
  var KIND_RANK = { error: 0, warning: 1, info: 2 };

  function summarise(call) {
    var invite = call.messages.filter(function (m) { return m.isRequest && m.method === 'INVITE'; })[0];
    var finals = call.messages.filter(isInviteFinal);
    var last = finals[finals.length - 1];
    var bye = call.messages.filter(function (m) { return m.isRequest && m.method === 'BYE'; })[0];
    var times = call.messages.map(function (m) { return m.time; }).filter(function (t) { return t !== null; });
    return {
      callId: call.callId,
      from: invite ? (P.header(invite, 'from') || '') : '',
      to: invite ? (P.header(invite, 'to') || '') : '',
      result: last ? last.label : (invite ? 'No final answer' : 'No INVITE in trace'),
      connected: !!(last && last.status < 300),
      endedBy: bye ? bye.meta.src ? bye.meta.src.ip : 'one side' : null,
      duration: times.length ? Math.round((Math.max.apply(null, times) - Math.min.apply(null, times)) * 10) / 10 : null,
      messageCount: call.messages.length
    };
  }

  function diagnose(parsed) {
    var calls = byCall(parsed.messages);
    var findings = [];
    calls.forEach(function (call) {
      ORDER.forEach(function (rule) {
        var f = rule(call);
        if (f) { f.callId = call.callId; findings.push(f); }
      });
    });
    // Missing ACK and private SDP often share one cause: keep the ACK finding first.
    // A B2BUA (SBC, PBX) relays the same failure on each call leg: keep the
    // leg where it happened first and note how many legs showed it.
    var byId = {};
    var ids = [];
    findings.forEach(function (f) {
      if (!byId[f.id]) { ids.push(f.id); byId[f.id] = []; }
      byId[f.id].push(f);
    });
    findings = ids.map(function (id) {
      var group = byId[id].slice().sort(function (a, b) { return a.failMsg - b.failMsg; });
      group[0].legs = group.length;
      return group[0];
    });
    findings.sort(function (a, b) {
      var k = KIND_RANK[a.kind] - KIND_RANK[b.kind];
      if (k) return k;
      return ruleRank(a.rule) - ruleRank(b.rule);
    });
    return { findings: findings, calls: calls.map(summarise) };
  }

  function ruleRank(r) {
    return ['codec', 'auth', 'rejected', 'missing-ack', 'nat-audio'].indexOf(r);
  }

  var api = { diagnose: diagnose, codecNames: codecNames };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else { root.SIPLens = root.SIPLens || {}; root.SIPLens.diagnose = diagnose; }
})(this);
