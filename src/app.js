/*
 * SIP Lens - user interface
 * Builds the diagnosis, call diagram and message views from a parsed trace.
 * Trace content is untrusted: it is only ever inserted with textContent.
 */
(function () {
  'use strict';

  var S = window.SIPLens;
  var state = { parsed: null, dx: null, anon: identity, name: '', view: 'diagnosis', diagramMode: 'diagram', msg: 1, finding: 0 };

  function identity(x) { return x == null ? '' : String(x); }
  function $(id) { return document.getElementById(id); }

  /** Tiny element builder: el('p', {class: 'x'}, ['text', child]) */
  function el(tag, attrs, children) {
    var node = document.createElement(tag);
    Object.keys(attrs || {}).forEach(function (k) {
      var v = attrs[k];
      if (v === null || v === undefined || v === false) return;
      if (k === 'class') node.className = v;
      else if (k === 'text') node.textContent = v;
      else if (k === 'style') node.setAttribute('style', v);
      else if (k.indexOf('on') === 0) node.addEventListener(k.slice(2), v);
      else node.setAttribute(k, v === true ? '' : v);
    });
    (children || []).forEach(function (c) {
      if (c === null || c === undefined || c === false) return;
      node.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
    });
    return node;
  }

  function svgIcon(kind, color) {
    var paths = {
      warn: '<path d="M12 3L22 20H2L12 3z"></path><path d="M12 10v4M12 17.5v.5"></path>',
      ok: '<path d="M5 12l5 5 9-10"></path>',
      x: '<path d="M6 6l12 12M18 6L6 18"></path>'
    };
    var span = document.createElement('span');
    span.setAttribute('aria-hidden', 'true');
    span.style.display = 'inline-flex';
    // Static markup only, no trace data.
    span.innerHTML = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="' + color + '" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">' + paths[kind] + '</svg>';
    return span;
  }

  /* ---------------- Upload ---------------- */

  function renderSamples() {
    var list = $('samples');
    (S.samples || []).forEach(function (s) {
      list.appendChild(el('li', {}, [
        el('button', { type: 'button', class: 'sample', onclick: function () { state.name = s.file; if (s.pcap) analyseCapture(base64ToBuffer(s.pcap)); else analyse(s.text); } }, [
          el('span', {}, [el('span', { class: 'sample-t', text: s.title }), el('span', { class: 'sample-h', text: s.hint })]),
          el('span', { 'aria-hidden': 'true', text: '→' })
        ])
      ]));
    });
  }

  function showError(msg) {
    var e = $('error');
    e.textContent = msg;
    e.hidden = !msg;
  }

  function readFile(file) {
    if (!file) return;
    $('file-name').textContent = file.name;
    state.name = file.name;
    if (file.size > 200 * 1024 * 1024) { showError('This file is larger than 200 MB. Filter the capture down to the call you need first.'); return; }
    var reader = new FileReader();
    reader.onload = function () {
      var buf = reader.result;
      if (S.isCapture(buf)) { analyseCapture(buf); return; }
      var text = new TextDecoder('utf-8').decode(buf);
      if (/[\x00-\x08\x0E-\x1F]/.test(text.slice(0, 2000))) {
        showError('This doesn\u2019t look like a text trace or a pcap/pcapng capture.');
        return;
      }
      $('paste').value = text;
      showError('');
    };
    reader.onerror = function () { showError('The file couldn’t be read.'); };
    reader.readAsArrayBuffer(file);
  }

  function bindUpload() {
    var drop = $('drop');
    $('file').addEventListener('change', function (e) { readFile(e.target.files[0]); });
    ['dragenter', 'dragover'].forEach(function (t) { drop.addEventListener(t, function (e) { e.preventDefault(); drop.classList.add('over'); }); });
    ['dragleave', 'drop'].forEach(function (t) { drop.addEventListener(t, function (e) { e.preventDefault(); drop.classList.remove('over'); }); });
    drop.addEventListener('drop', function (e) { if (e.dataTransfer.files[0]) readFile(e.dataTransfer.files[0]); });
    $('form').addEventListener('submit', function (e) {
      e.preventDefault();
      if (!state.name || state.name === 'pasted') state.name = $('file').files[0] ? $('file').files[0].name : 'pasted';
      analyse($('paste').value);
    });
    $('home').addEventListener('click', reset);
  }

  function reset() {
    state.parsed = null;
    $('tabs').hidden = true;
    setTopMeta(false);
    ['diagnosis', 'diagram', 'messages'].forEach(function (v) { $('view-' + v).hidden = true; });
    $('view-upload').hidden = false;
    $('main').focus();
  }

  function base64ToBuffer(b64) {
    var bin = atob(b64);
    var bytes = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes.buffer;
  }

  function analyseCapture(buffer) {
    var parsed;
    try { parsed = S.parseCapture(buffer); }
    catch (e) { showError(e.message || 'The capture couldn\u2019t be read.'); return; }
    if (!parsed.messages.length) {
      showError('No SIP messages were found in this capture (' + parsed.source.packets + ' packets). SIP over TLS can\u2019t be read; if the capture is filtered, make sure it includes port 5060.');
      return;
    }
    show(parsed);
  }

  function analyse(text) {
    if (!text || !text.trim()) { showError('Paste a trace or choose a file first.'); return; }
    var parsed = S.parseTrace(text);
    if (!parsed.messages.length) { showError('No SIP messages were found. Each message should start with a line like "INVITE sip:... SIP/2.0" or "SIP/2.0 200 OK".'); return; }
    show(parsed);
  }

  function show(parsed) {
    showError('');
    state.parsed = parsed;
    state.dx = S.diagnose(parsed);
    state.anon = $('anon').checked ? S.makeAnonymiser() : identity;
    state.finding = 0;
    var f = state.dx.findings[0];
    state.msg = f ? ((f.evidence[0] && f.evidence[0].msg) || f.failMsg) : 1;
    $('view-upload').hidden = true;
    $('tabs').hidden = false;
    setTopMeta(true);
    go('diagnosis');
  }

  function setTopMeta(results) {
    var meta = $('top-meta');
    if (!results) {
      meta.querySelectorAll('[data-results]').forEach(function (n) { n.remove(); });
      meta.firstElementChild.hidden = false;
      return;
    }
    meta.firstElementChild.hidden = true;
    meta.querySelectorAll('[data-results]').forEach(function (n) { n.remove(); });
    meta.appendChild(el('span', { 'data-results': '1', class: 'mono', style: 'font-size:13px', text: state.name || 'pasted trace' }));
    if (state.anon !== identity) meta.appendChild(el('span', { 'data-results': '1', class: 'chip', text: 'Anonymised' }));
    meta.appendChild(el('button', { 'data-results': '1', type: 'button', class: 'linkish', text: 'Load another trace', onclick: reset }));
  }

  /* ---------------- Navigation ---------------- */

  function go(view, opts) {
    opts = opts || {};
    if (opts.msg) state.msg = opts.msg;
    state.view = view;
    var tabs = $('tabs');
    tabs.textContent = '';
    [['diagnosis', 'Diagnosis'], ['diagram', 'Call diagram'], ['messages', 'Messages (' + state.parsed.messages.length + ')']].forEach(function (t) {
      tabs.appendChild(el('button', { type: 'button', class: 'tab', 'aria-current': t[0] === view ? 'page' : null, text: t[1], onclick: function () { go(t[0]); } }));
    });
    ['diagnosis', 'diagram', 'messages'].forEach(function (v) { $('view-' + v).hidden = v !== view; });
    ({ diagnosis: renderDiagnosis, diagram: renderDiagram, messages: renderMessages })[view]();
    if (!opts.keepFocus) { window.scrollTo(0, 0); $('main').focus({ preventScroll: true }); }
  }

  function evidenceFor(msgIndex) {
    var f = state.dx.findings[state.finding];
    if (!f) return [];
    return f.evidence.filter(function (e) { return e.msg === msgIndex; });
  }

  function msgLabel(m) { return m ? state.anon(m.label) : ''; }

  /* ---------------- Diagnosis ---------------- */

  function renderDiagnosis() {
    var root = $('view-diagnosis');
    root.textContent = '';
    var a = state.anon;
    var f = state.dx.findings[state.finding];
    var main = el('div', { class: 'dx-main' });

    if (!f) {
      main.appendChild(el('div', { class: 'stack' }, [
        el('p', { class: 'status' }, [el('span', { class: 'badge ok' }, [svgIcon('ok', '#1E6B45'), 'No known problem found'])]),
        el('h1', { class: 'dx-title', text: 'None of the known failure patterns appear in this trace.' }),
        el('p', { class: 'dx-summary', text: 'SIP Lens checks for codec mismatches, authentication loops, rejected calls, missing ACKs and private addresses in SDP behind NAT. The problem may be outside the signalling, for example in the audio itself or the network.' }),
        el('div', { class: 'row-btns' }, [el('button', { type: 'button', class: 'btn btn-primary', text: 'See the call diagram', onclick: function () { go('diagram'); } })])
      ]));
    } else {
      var kindIcon = f.kind === 'error' ? svgIcon('warn', '#9A1C12') : f.kind === 'warning' ? svgIcon('warn', '#8A4A0B') : svgIcon('ok', '#1E6B45');
      main.appendChild(el('section', { class: 'stack', 'aria-labelledby': 'dx-title' }, [
        el('p', { class: 'status' }, [
          el('span', { class: 'badge ' + f.kind }, [kindIcon, f.badge]),
          el('span', { class: 'mono', style: 'font-size:13px;color:var(--ink-3)', text: a(f.code) }),
          el('span', { style: 'font-size:14px;color:var(--ink-3)', text: (f.confidence === 'high' ? 'High confidence' : 'Medium confidence') + ' - ' + f.evidence.length + ' signals' + (f.legs > 1 ? ', seen on ' + f.legs + ' call legs' : '') })
        ]),
        el('h1', { id: 'dx-title', class: 'dx-title', text: f.title }),
        el('p', { class: 'dx-summary', text: a(f.summary) }),
        el('div', { class: 'row-btns' }, [
          el('button', { type: 'button', class: 'btn btn-primary', text: 'See it in the call diagram', onclick: function () { go('diagram'); } }),
          copyButton(f)
        ])
      ]));

      var ev = el('ol', { class: 'ev' });
      f.evidence.forEach(function (e, i) {
        var m = e.msg ? state.parsed.messages[e.msg - 1] : null;
        ev.appendChild(el('li', {}, [
          el('span', { class: 'ev-n', text: String(i + 1).padStart(2, '0') }),
          el('div', { class: 'ev-body' }, [
            el('p', { text: a(e.note) }),
            el('code', { text: m ? 'Message ' + e.msg + ' · ' + msgLabel(m) + (e.lineNo ? ' · line ' + (e.lineNo + 1) : '') + (e.text === m.lines[0] ? '' : ' · ' + a(e.text)) : a(e.text) })
          ]),
          m ? el('button', { type: 'button', class: 'linkish', text: 'View message', onclick: function () { go('messages', { msg: e.msg }); } })
            : el('button', { type: 'button', class: 'linkish', text: 'View in diagram', onclick: function () { go('diagram'); } })
        ]));
      });
      main.appendChild(el('section', { class: 'stack', 'aria-labelledby': 'ev-title' }, [
        el('h2', { id: 'ev-title', class: 'lbl', text: 'Evidence' }), ev,
        f.caveat ? el('p', { class: 'caveat', text: f.caveat }) : null
      ]));

      if (f.fixes.length) {
        var fx = el('ol', { class: 'fixes' });
        f.fixes.forEach(function (x, i) {
          fx.appendChild(el('li', {}, [
            el('p', { class: 't' }, [(i + 1) + '. ' + x.title, x.primary ? el('span', { class: 'pill', text: 'Most likely fix' }) : null]),
            el('p', { class: 'd', text: a(x.detail) })
          ]));
        });
        main.appendChild(el('section', { class: 'stack', 'aria-labelledby': 'fx-title' }, [el('h2', { id: 'fx-title', class: 'lbl', text: 'What to try, in order' }), fx]));
      }

      if (state.dx.findings.length > 1) {
        var also = el('ul', { class: 'also' });
        state.dx.findings.forEach(function (o, i) {
          if (i === state.finding) return;
          also.appendChild(el('li', {}, [el('button', { type: 'button', onclick: function () { state.finding = i; state.msg = (o.evidence[0] && o.evidence[0].msg) || o.failMsg; go('diagnosis'); } }, [
            el('span', { style: 'font-weight:500', text: o.title }),
            el('span', { class: 'hint', text: o.badge + ' · ' + a(o.code) })
          ])]));
        });
        main.appendChild(el('section', { class: 'stack', 'aria-labelledby': 'also-title' }, [el('h2', { id: 'also-title', class: 'lbl', text: 'Also found' }), also]));
      }
    }

    root.appendChild(el('div', { class: 'dx' }, [main, summaryAside()]));
  }

  function copyButton(f) {
    var btn = el('button', { type: 'button', class: 'btn', text: 'Copy explanation' });
    btn.addEventListener('click', function () {
      var a = state.anon;
      var text = f.title + '\n\n' + a(f.summary) + '\n\nEvidence:\n' + f.evidence.map(function (e) { return '- ' + a(e.note) + ' (' + a(e.text) + ')'; }).join('\n') +
        (f.fixes.length ? '\n\nWhat to try:\n' + f.fixes.map(function (x, i) { return (i + 1) + '. ' + x.title + ' - ' + a(x.detail); }).join('\n') : '');
      var done = function () { btn.textContent = 'Copied'; setTimeout(function () { btn.textContent = 'Copy explanation'; }, 1600); };
      if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(text).then(done, function () { btn.textContent = 'Copy failed'; });
      else btn.textContent = 'Copy not available';
    });
    return btn;
  }

  function summaryAside() {
    var a = state.anon;
    var f = state.dx.findings[state.finding];
    var call = (f && state.dx.calls.filter(function (c) { return c.callId === f.callId; })[0]) || state.dx.calls[0];
    var dl = el('dl', { class: 'sum' });
    function row(k, v, extra) { if (!v && v !== 0) return; dl.appendChild(el('div', {}, [el('dt', { text: k }), el('dd', extra || {}, [String(v)])])); }
    if (call) {
      row('From', a(call.from.replace(/;tag=.*$/, '')));
      row('To', a(call.to.replace(/;tag=.*$/, '')));
      row('Result', a(call.result));
      row('Messages in this leg', call.messageCount);
      if (call.duration !== null) row('Time span', call.duration + ' s');
    }
    row('Call legs in trace', state.dx.calls.length);
    if (state.parsed.source) row('Source', state.parsed.source.format + ' capture, ' + state.parsed.source.packets + ' packets');
    if (state.parsed.rtp) row('Audio streams', state.parsed.rtp.length ? state.parsed.rtp.map(function (s) { return a(s.src) + ' \u2192 ' + a(s.dst) + ': ' + s.packets; }).join('; ') : 'None in the capture');
    row('Hosts', state.parsed.participants.map(function (p) { return a(p.ip); }).join(' · ') || 'No network info in trace');
    return el('aside', { class: 'dx-side', 'aria-labelledby': 'sum-title' }, [
      el('h2', { id: 'sum-title', class: 'lbl', text: 'Call summary' }), dl,
      el('p', { class: 'side-note', text: 'Parsed on this device.' + (state.anon !== identity ? ' Numbers and public IPs are anonymised.' : '') })
    ]);
  }

  /* ---------------- Diagram ---------------- */

  function renderDiagram() {
    var root = $('view-diagram');
    root.textContent = '';
    var a = state.anon;
    var f = state.dx.findings[state.finding];
    var msgs = state.parsed.messages;
    var lanes = lanesFor();
    var canDraw = lanes.length >= 2 && msgs.every(function (m) { return m.meta.src && m.meta.dst; });
    var mode = canDraw ? state.diagramMode : 'list';

    var seg = el('div', { class: 'seg', role: 'group', 'aria-label': 'View as' }, [
      el('button', { type: 'button', 'aria-pressed': String(mode === 'diagram'), disabled: !canDraw, text: 'Diagram', onclick: function () { state.diagramMode = 'diagram'; go('diagram', { keepFocus: true }); } }),
      el('button', { type: 'button', 'aria-pressed': String(mode === 'list'), text: 'List', onclick: function () { state.diagramMode = 'list'; go('diagram', { keepFocus: true }); } })
    ]);
    var span = msgs.filter(function (m) { return m.time !== null; });
    root.appendChild(el('div', { class: 'stack', style: 'gap:28px' }, [
      el('div', { class: 'head-row' }, [
        el('div', { class: 'stack', style: 'gap:8px' }, [
          el('h1', { style: 'font-size:36px;letter-spacing:-0.025em', text: 'Call diagram' }),
          el('p', { class: 'hint', style: 'font-size:16px;color:var(--ink-3)', text: msgs.length + ' SIP messages' + ((state.parsed.rtp || []).length ? ' and ' + state.parsed.rtp.length + ' audio streams' : '') + (lanes.length ? ' between ' + lanes.length + ' hosts' : '') + (span.length ? ', over ' + Math.round(span[span.length - 1].time) + ' seconds.' : '.') })
        ]),
        seg
      ]),
      f ? el('button', { type: 'button', class: 'failbar', style: 'border:0;text-align:left;cursor:pointer', onclick: function () { go('messages', { msg: f.failMsg }); } }, [
        el('b', {}, [svgIcon('warn', '#9A1C12'), f.media ? (f.media.stream && f.media.stream.start !== null ? ' Failure point: return audio, from ' + f.media.stream.start.toFixed(2) + ' s' : ' Failure point: return audio, after message ' + f.media.after) : ' Failure point: message ' + f.failMsg]),
        el('span', { text: f.title }),
        el('span', { class: 'linkish', style: 'margin-left:auto', text: 'Open message' })
      ]) : null,
      !canDraw ? el('p', { class: 'hint', text: 'The diagram needs network addresses for each message (lines like "10.0.0.1:5060 -> 10.0.0.2:5060"). Showing the list instead.' }) : null,
      mode === 'diagram' ? ladder(f) : listTable(f),
      mode === 'diagram' ? el('p', { class: 'legend' }, [
        el('span', { text: 'Solid line: SIP message' }),
        el('span', { style: 'color:var(--accent-ink)', text: 'Blue: used as evidence' }),
        (state.parsed.rtp || []).length ? el('span', { style: 'color:var(--accent-ink)', text: 'Dashed blue: audio (RTP)' }) : null,
        el('span', { style: 'color:var(--bad)', text: 'Red, dashed, with ×: failure point' }),
        el('span', { text: 'Times in seconds from the first message' })
      ]) : null
    ]));
  }

  function laneName(p) {
    var a = state.anon;
    var tags = [];
    if (S.isPrivateIp(p.ip)) tags.push('private');
    var natted = state.parsed.messages.some(function (m) {
      return S.headers(m, 'via').some(function (v) { return v.value.indexOf('received=' + p.ip) >= 0; });
    });
    if (natted) tags.push('behind NAT');
    return { ip: a(p.ip), ports: p.ports.join(', '), tags: tags };
  }

  var CODEC_NAMES = { 0: 'PCMU', 8: 'PCMA', 9: 'G.722', 18: 'G.729' };

  function rtpText(s) {
    return 'RTP · ' + (CODEC_NAMES[s.payloadType] || 'PT ' + s.payloadType) + ' · ' + s.packets + ' packets' + (s.lost ? ' (' + s.lost + ' lost)' : '');
  }

  /** SIP hosts plus any host that only shows up in the audio. */
  function lanesFor() {
    var lanes = state.parsed.participants.map(function (p) { return { ip: p.ip, ports: p.ports.slice() }; });
    (state.parsed.rtp || []).forEach(function (s) {
      [s.src, s.dst].forEach(function (ip) {
        if (!lanes.some(function (l) { return l.ip === ip; })) lanes.push({ ip: ip, ports: [] });
      });
    });
    return lanes;
  }

  /** Messages and audio streams in time order. The failing audio, if any, is marked. */
  function timeline(f) {
    var rows = state.parsed.messages.map(function (m) { return { type: 'msg', m: m, t: m.time }; });
    var failStream = f && f.media && f.media.stream;
    var streams = (state.parsed.rtp || []).slice().sort(function (x, y) { return (x.start || 0) - (y.start || 0); });
    streams.forEach(function (s) {
      var at = -1;
      rows.forEach(function (r, i) { if (r.t !== null && s.start !== null && r.t <= s.start) at = i; });
      rows.splice(at + 1, 0, { type: 'rtp', s: s, t: s.start, fail: s === failStream });
    });
    if (f && f.media && !failStream) {
      var after = -1;
      rows.forEach(function (r, i) { if (r.type === 'msg' && r.m.index === f.media.after) after = i; });
      rows.splice(after + 1, 0, { type: 'media', media: f.media, t: null, fail: true });
    }
    return rows;
  }

  function ladder(f) {
    var lanes = lanesFor();
    var L = lanes.length;
    var pos = {};
    lanes.forEach(function (p, i) { pos[p.ip] = i; });
    var centre = function (i) { return (i + 0.5) / L * 100; };
    var ev = {};
    if (f) f.evidence.forEach(function (e) { if (e.msg) ev[e.msg] = true; });

    var heads = el('div', { class: 'lane-heads', style: 'grid-template-columns:repeat(' + L + ', minmax(0, 1fr))' });
    lanes.forEach(function (p) {
      var n = laneName(p);
      heads.appendChild(el('div', { class: 'lane-head' }, [
        n.ip, el('small', { text: n.ports ? 'port ' + n.ports : 'audio only' }),
        n.tags.length ? el('span', { class: 'tag', text: n.tags.join(' · ') }) : null
      ]));
    });

    var a = state.anon;
    var rowsWrap = el('div', {});
    timeline(f).forEach(function (r) {
      var from, to, label, cls, aria, time, node;
      if (r.type === 'msg') {
        var m = r.m;
        from = m.meta.src.ip; to = m.meta.dst.ip;
        var isFail = f && !f.media && f.failMsg === m.index;
        label = m.index + '  ' + msgLabel(m) + (m.sdp ? ' · SDP' : '');
        cls = isFail ? ' fail' : ev[m.index] ? ' evidence' : '';
        aria = 'Message ' + m.index + ': ' + msgLabel(m) + ' from ' + a(from) + ' to ' + a(to) + (isFail ? '. Failure point.' : ev[m.index] ? '. Used as evidence.' : '');
        time = m.time === null ? '' : m.time.toFixed(3);
        node = 'button';
        r.fail = isFail;
      } else {
        var s = r.s;
        from = r.type === 'rtp' ? s.src : r.media.from;
        to = r.type === 'rtp' ? s.dst : r.media.to;
        label = r.fail ? a(f.media.label) : rtpText(s);
        cls = r.fail ? ' fail' : ' rtp';
        aria = (r.fail ? 'Failure point: ' : 'Audio stream: ') + label + ', from ' + a(from) + ' to ' + a(to) + '.';
        time = r.type === 'rtp' && s.start !== null ? s.start.toFixed(3) : 'RTP';
        node = 'div';
      }
      var si = pos[from], di = pos[to];
      if (si === undefined || di === undefined) return;
      var right = di > si;
      var attrs = { class: 'arrow ' + (right ? 'right' : 'left') + cls, style: 'left:' + centre(Math.min(si, di)) + '%;width:' + (Math.abs(centre(di) - centre(si)) || 4) + '%', 'aria-label': aria };
      if (node === 'button') { attrs.type = 'button'; attrs.onclick = (function (idx) { return function () { go('messages', { msg: idx }); }; })(r.m.index); }
      else { attrs.role = 'img'; attrs.style += ';cursor:default'; }
      var arrow = el(node, attrs, [el('span', { class: 'txt', text: label }), el('span', { class: 'line' }), el('span', { class: 'head' })]);
      if (r.fail) arrow.appendChild(el('span', { class: 'x', 'aria-hidden': 'true', style: right ? 'right:-30px' : 'left:-30px', text: '×' }));
      rowsWrap.appendChild(el('div', { class: 'lrow' + (r.type === 'msg' ? '' : ' media') + (r.fail && r.type !== 'msg' ? ' fail' : '') }, [
        el('span', { class: 'ltime', text: time }),
        el('div', { class: 'ltrack' }, [arrow])
      ]));
    });

    var track = el('div', { class: 'rows' });
    // Lifelines sit behind the rows, inside the lanes column.
    var lifeWrap = el('div', { style: 'position:absolute;top:0;bottom:0;left:88px;right:0', 'aria-hidden': 'true' });
    lanes.forEach(function (p, i) { lifeWrap.appendChild(el('span', { class: 'lifeline', style: 'left:' + centre(i) + '%' })); });
    track.appendChild(lifeWrap);
    track.appendChild(rowsWrap);

    return el('div', { class: 'panel' }, [el('div', { class: 'ladder', style: 'min-width:' + Math.max(760, L * 220) + 'px' }, [
      el('div', { class: 'lanes' }, [el('span', { class: 'lbl', style: 'align-self:end;font-size:11px', text: 'Time' }), heads]),
      track
    ])]);
  }

  function listTable(f) {
    var a = state.anon;
    var notes = {};
    if (f) f.evidence.forEach(function (e) { if (e.msg && !notes[e.msg]) notes[e.msg] = a(e.note); });
    var tbody = el('tbody');
    timeline(f).forEach(function (r) {
      if (r.type === 'msg') {
        var m = r.m;
        var isFail = f && !f.media && f.failMsg === m.index;
        tbody.appendChild(el('tr', { class: isFail ? 'fail' : null }, [
          el('td', { class: 'mono', text: String(m.index) }),
          el('td', { class: 'mono', text: m.time === null ? '-' : m.time.toFixed(3) }),
          el('td', { text: m.meta.src ? a(m.meta.src.ip) : '-' }),
          el('td', { text: m.meta.dst ? a(m.meta.dst.ip) : '-' }),
          el('td', {}, [el('button', { type: 'button', class: 'linkish', style: 'font-size:15px', text: msgLabel(m) + (m.sdp ? ' (SDP)' : ''), onclick: function () { go('messages', { msg: m.index }); } })]),
          el('td', { text: (isFail ? 'Failure point. ' : '') + (notes[m.index] || '') })
        ]));
      } else {
        var from = r.type === 'rtp' ? r.s.src : r.media.from, to = r.type === 'rtp' ? r.s.dst : r.media.to;
        tbody.appendChild(el('tr', { class: r.fail ? 'fail' : null }, [
          el('td', { class: 'mono', text: '-' }),
          el('td', { class: 'mono', text: r.type === 'rtp' && r.s.start !== null ? r.s.start.toFixed(3) : 'RTP' }),
          el('td', { text: a(from) }), el('td', { text: a(to) }),
          el('td', { text: r.type === 'rtp' ? rtpText(r.s) : 'Audio' }),
          el('td', { text: r.fail ? 'Failure point. ' + a(f.media.label) + '.' : 'Audio stream, until ' + (r.s.end !== null ? r.s.end.toFixed(1) + ' s' : 'the end') + '.' })
        ]));
      }
    });
    return el('div', { class: 'panel' }, [el('table', { class: 'list' }, [
      el('caption', { class: 'sr-only', text: 'Call messages and audio streams in order' + (f ? '. The failure point is marked.' : '.') }),
      el('thead', {}, [el('tr', {}, ['#', 'Time (s)', 'From', 'To', 'Message', 'Note'].map(function (h) { return el('th', { scope: 'col', class: 'lbl', text: h }); }))]),
      tbody
    ])]);
  }

  /* ---------------- Messages ---------------- */

  function renderMessages() {
    var root = $('view-messages');
    root.textContent = '';
    var a = state.anon;
    var msgs = state.parsed.messages;
    var m = msgs[state.msg - 1] || msgs[0];
    var f = state.dx.findings[state.finding];
    var evMsgs = {};
    if (f) f.evidence.forEach(function (e) { evMsgs[e.msg] = true; });

    var list = el('ol', {});
    msgs.forEach(function (x) {
      list.appendChild(el('li', {}, [el('button', { type: 'button', 'aria-current': x.index === m.index ? 'true' : null, onclick: function () { go('messages', { msg: x.index, keepFocus: true }); } }, [
        el('span', { class: 'n', text: String(x.index) }),
        el('span', { style: 'flex:1', text: msgLabel(x) }),
        evMsgs[x.index] ? el('span', { class: 'dot', 'aria-label': 'Used as evidence', text: '!' }) : null
      ])]));
    });

    var evs = evidenceFor(m.index);
    var hitLines = {};
    evs.forEach(function (e) { if (e.lineNo) hitLines[e.lineNo] = true; });
    var lines = m.lines.slice();
    while (lines.length && !lines[lines.length - 1].trim()) lines.pop();
    var raw = el('pre', { class: 'raw', 'aria-label': 'Raw SIP message, ' + lines.length + ' lines' });
    lines.forEach(function (line, i) {
      raw.appendChild(el('span', { class: 'ln' + (hitLines[i] ? ' hit' : '') }, [el('span', { class: 'n', text: String(i + 1) }), el('span', { text: a(line) || ' ' })]));
    });

    var notes = el('div', { class: 'notes', 'aria-label': 'What this message tells us' });
    if (evs.length) {
      evs.forEach(function (e) {
        notes.appendChild(el('div', { class: 'note' + (e.lineNo ? '' : ' note-plain') }, [
          el('p', { class: 'k', text: e.lineNo ? 'Line ' + (e.lineNo + 1) : 'This message' }),
          el('p', { text: a(e.note) })
        ]));
      });
    } else {
      notes.appendChild(el('div', { class: 'note note-plain' }, [el('p', { text: 'Nothing unusual was found in this message.' })]));
    }

    var dir = m.meta.src ? a(m.meta.src.ip) + ' → ' + a(m.meta.dst.ip) : '';
    var prev = el('button', { type: 'button', class: 'btn btn-sm', disabled: m.index === 1, text: '← Previous', onclick: function () { go('messages', { msg: m.index - 1, keepFocus: true }); } });
    var next = el('button', { type: 'button', class: 'btn btn-sm', disabled: m.index === msgs.length, text: 'Next →', onclick: function () { go('messages', { msg: m.index + 1, keepFocus: true }); } });

    root.appendChild(el('div', { class: 'msgs' }, [
      el('nav', { class: 'msgs-nav', 'aria-label': 'Messages in this trace' }, [el('h2', { class: 'lbl', text: 'Messages' }), list]),
      el('div', { class: 'msgs-main' }, [
        el('div', { class: 'head-row' }, [
          el('div', { class: 'stack', style: 'gap:8px' }, [
            el('p', { class: 'lbl', text: 'Message ' + m.index + ' of ' + msgs.length + (m.time !== null ? ' · ' + m.time.toFixed(3) + ' s' : '') }),
            el('h1', { style: 'font-size:36px;letter-spacing:-0.025em' }, [msgLabel(m) + ' ', el('span', { style: 'font-weight:400;color:var(--ink-3)', text: dir })])
          ]),
          el('div', { class: 'row-btns', style: 'gap:8px' }, [prev, next])
        ]),
        el('div', { class: 'msg-grid' }, [raw, notes])
      ])
    ]));
  }

  /* ---------------- Start ---------------- */
  renderSamples();
  bindUpload();
})();
