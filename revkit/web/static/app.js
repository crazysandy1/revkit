'use strict';
/* revkit web UI — vanilla JS, no external dependencies (works offline). */
const TOKEN = (location.hash.match(/token=([^&]+)/) || [])[1] || sessionStorage.getItem('rk-token') || '';
if (TOKEN) sessionStorage.setItem('rk-token', TOKEN);

const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const esc = s => String(s ?? '').replace(/[&<>"]/g, c => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;'}[c]));
const hex = n => '0x' + Number(n).toString(16);
const h8 = n => Number(n).toString(16).toUpperCase().padStart(8, '0');
const sleep = ms => new Promise(r => setTimeout(r, ms));

async function api(path, params, body) {
  const qs = params ? '?' + new URLSearchParams(Object.entries(params).filter(([, v]) => v !== undefined && v !== null)).toString() : '';
  const opt = {headers: {'X-Revkit-Token': TOKEN}};
  if (body !== undefined) { opt.method = 'POST'; opt.body = JSON.stringify(body); opt.headers['Content-Type'] = 'application/json'; }
  const r = await fetch(path + qs, opt);
  const j = await r.json().catch(() => ({error: 'bad response'}));
  if (!r.ok) throw new Error(j.error || r.statusText);
  return j;
}
const post = (p, b) => api(p, null, b || {});

function toast(msg, err) {
  const t = $('#toast'); t.textContent = msg; t.className = err ? 'err' : ''; t.style.display = 'block';
  clearTimeout(toast.t); toast.t = setTimeout(() => t.style.display = 'none', err ? 6000 : 2500);
}
const guard = fn => async (...a) => { try { return await fn(...a); } catch (e) { toast(e.message, true); } };

// ---------------------------------------------------------------- modal helpers
function modal(title, bodyHTML, buttons) {
  return new Promise(res => {
    const root = $('#modal-root');
    const bg = document.createElement('div'); bg.className = 'modal-bg';
    bg.innerHTML = `<div class="modal"><h3>${esc(title)}</h3><div class="mbody">${bodyHTML}</div><div class="btns"></div></div>`;
    root.appendChild(bg);
    const done = v => { bg.remove(); res(v); };
    const btns = $('.btns', bg);
    (buttons || [['Cancel', null], ['OK', 'ok', true]]).forEach(([label, val, primary]) => {
      const b = document.createElement('button'); b.textContent = label; if (primary) b.className = 'primary';
      b.onclick = () => done(val === 'ok' ? collect(bg) : val); btns.appendChild(b);
    });
    bg.addEventListener('keydown', e => { if (e.key === 'Escape') done(null); if (e.key === 'Enter' && e.target.tagName !== 'TEXTAREA') { e.preventDefault(); done(collect(bg)); } });
    bg.addEventListener('mousedown', e => { if (e.target === bg) done(null); });
    const first = $('input,select,textarea', bg); if (first) { first.focus(); if (first.select) first.select(); }
  });
}
function collect(bg) { const o = {}; $$('[name]', bg).forEach(e => o[e.name] = e.type === 'checkbox' ? e.checked : e.value); return o; }
async function ask(title, label, initial = '') {
  const r = await modal(title, `<label>${esc(label)}<br><input type="text" name="v" value="${esc(initial)}"></label>`);
  return r ? r.v : null;
}

// ---------------------------------------------------------------- state
const S = {
  cur: null, hist: [], hi: -1, view: 'disasm', names: new Map(), nameOf: new Map(), funcs: [], func: null,
  info: null, settings: {theme: 'dark', font: 'Consolas, monospace', fontSize: 13, shortcuts: {}}, tok: null,
  dbg: null, bps: new Map(), pcStatic: null, regsPrev: {}, leftTab: 'Functions', state: {},
};
const DEFAULT_KEYS = {rename: 'n', comment: ';', rcomment: ':', goto: 'g', xrefs: 'x', toggleGraph: ' ', toggleCode: 'Tab', decompile: 'F5',
  makeCode: 'c', makeData: 'd', undefine: 'u', makeFunc: 'p', makeString: 'a', setType: 'y', opFormat: 'h', bookmark: 'b', back: 'Escape',
  search: '/', undo: 'ctrl+z', redo: 'ctrl+y', save: 'ctrl+s', bp: 'F2', stepInto: 'F7', stepOver: 'F8', cont: 'F9', hexView: 'e', patch: 'ctrl+p'};
const keys = () => ({...DEFAULT_KEYS, ...(S.settings.shortcuts || {})});

const REGS = new Set('rax rbx rcx rdx rsi rdi rbp rsp rip r8 r9 r10 r11 r12 r13 r14 r15 eax ebx ecx edx esi edi ebp esp eip ax bx cx dx si di bp sp al bl cl dl ah bh ch dh sil dil r8d r9d r10d r11d r12d r13d r14d r15d xmm0 xmm1 xmm2 xmm3 xmm4 xmm5 xmm6 xmm7 cs ds es fs gs ss lr pc fp ip zero ra'.split(' '));
for (let i = 0; i < 32; i++) { REGS.add('x' + i); REGS.add('w' + i); REGS.add('r' + i); REGS.add('v' + i); REGS.add('$' + i); }
const KW = new Set('if else while for do return switch case default break continue goto void int char unsigned struct sizeof'.split(' '));

// ---------------------------------------------------------------- text coloring / linkification
function tokenize(text, kind) {
  let out = '', first = kind === 'code';
  const re = /(0x[0-9a-fA-F]+|[A-Za-z_.$?@][\w.$?@:]*|\d+|\s+|.)/g;
  let m;
  while ((m = re.exec(text))) {
    const t = m[0];
    if (/^\s+$/.test(t)) { out += t; continue; }
    if (first) { out += `<span class="mn">${esc(t)}</span>`; first = false; continue; }
    first = false;
    if (/^0x[0-9a-fA-F]+$/.test(t) || /^\d+$/.test(t)) {
      const a = parseInt(t, 16 === 0 ? 10 : (t.startsWith('0x') ? 16 : 10));
      if (t.startsWith('0x') && S.addrKnown && S.addrKnown.has(a)) out += `<span class="link" data-a="${a}">${esc(t)}</span>`;
      else out += `<span class="num">${esc(t)}</span>`;
    } else if (S.names.has(t)) out += `<span class="link" data-a="${S.names.get(t)}">${esc(t)}</span>`;
    else if (REGS.has(t.toLowerCase())) out += `<span class="reg">${esc(t)}</span>`;
    else out += esc(t);
  }
  return out;
}
function colorC(text) {
  let out = '';
  const re = /("(?:\\.|[^"\\])*")|(0x[0-9a-fA-F]+|\b\d+\b)|([A-Za-z_][\w]*)|(\s+)|(.)/g; let m;
  while ((m = re.exec(text))) {
    if (m[1]) out += `<span class="str">${esc(m[1])}</span>`;
    else if (m[2]) out += `<span class="num">${esc(m[2])}</span>`;
    else if (m[3]) {
      const t = m[3];
      if (KW.has(t)) out += `<span class="kw">${t}</span>`;
      else if (/^(_?[DQW]?WORD|_BYTE|__int(8|16|32|64)|_OWORD|HANDLE|DWORD|LPCSTR|size_t)$/.test(t)) out += `<span class="ty">${t}</span>`;
      else if (S.names.has(t)) out += `<span class="link" data-a="${S.names.get(t)}">${esc(t)}</span>`;
      else out += `<span class="var" data-v="${esc(t)}">${esc(t)}</span>`;
    } else out += esc(m[0]);
  }
  return out;
}

// ---------------------------------------------------------------- navigation
async function refreshNames() {
  const [names, funcs] = await Promise.all([api('/api/names'), api('/api/functions')]);
  S.funcs = funcs; S.names = new Map(); S.addrKnown = new Set();
  funcs.forEach(f => { S.names.set(f.name, f.addr); S.addrKnown.add(f.addr); });
  names.forEach(n => { S.names.set(n.name, n.addr); S.addrKnown.add(n.addr); });
}
function resolveLocal(t) {
  t = String(t).trim();
  if (S.names.has(t)) return S.names.get(t);
  if (/^(0x)?[0-9a-fA-F]+$/.test(t)) return parseInt(t, t.startsWith('0x') ? 16 : (/^[0-9]+$/.test(t) ? 10 : 16));
  return null;
}
async function gotoAddr(a, opts = {}) {
  if (a === null || a === undefined) return;
  a = Number(a);
  if (!opts.noHist && S.cur !== null && S.cur !== a) { S.hist = S.hist.slice(0, S.hi + 1); S.hist.push(S.cur); S.hi = S.hist.length - 1; }
  const prev = S.cur; S.cur = a;
  $('#status-addr').textContent = hex(a);
  await showView(S.view, {from: opts.from, prev});
  updateContext();
}
const goBack = () => { if (S.hist.length && S.hi >= 0) { const a = S.hist[S.hi]; S.hi--; const cur = S.cur; S.cur = null; gotoAddr(a, {noHist: true}); S.fwd = (S.fwd || []).concat([cur]); } };
const goForward = () => { if (S.fwd && S.fwd.length) { const a = S.fwd.pop(); gotoAddr(a); } };

// ---------------------------------------------------------------- left panel
const LEFT_TABS = ['Functions', 'Names', 'Strings', 'Imports', 'Exports', 'Segments', 'Types', 'Bookmarks', 'Patches', 'Problems', 'Plugins'];
function buildLeftTabs() {
  const nav = $('#left-tabs'); nav.innerHTML = '';
  LEFT_TABS.forEach(t => { const b = document.createElement('button'); b.textContent = t; b.dataset.t = t; b.onclick = () => { S.leftTab = t; $('#left-filter').value = ''; renderLeft(); }; nav.appendChild(b); });
}
async function renderLeft() {
  $$('#left-tabs button').forEach(b => b.classList.toggle('active', b.dataset.t === S.leftTab));
  const body = $('#left-body'); const f = $('#left-filter').value.toLowerCase();
  let rows = [], extra = '';
  try {
    switch (S.leftTab) {
      case 'Functions': rows = S.funcs.filter(x => !f || x.name.toLowerCase().includes(f)).map(x => ({a: x.addr, n: x.name, cls: x.flags.includes('library') ? 'lib' : '', t: `${x.size}b`})); break;
      case 'Names': rows = (await api('/api/names')).filter(x => !f || x.name.toLowerCase().includes(f)).map(x => ({a: x.addr, n: x.name})); break;
      case 'Strings': rows = (await api('/api/strings', {min: 4, filter: f ? f.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') : undefined})).map(x => ({a: x.addr, n: JSON.stringify(x.text), t: x.encoding === 'utf16' ? 'W' : ''})); break;
      case 'Imports': rows = (await api('/api/imports')).filter(x => !f || (x.module + x.name).toLowerCase().includes(f)).map(x => ({a: x.stub || x.addr, n: `${x.module ? x.module + '!' : ''}${x.name}`, t: x.xrefs.length + 'x'})); break;
      case 'Exports': rows = (await api('/api/exports')).filter(x => !f || x.name.toLowerCase().includes(f)).map(x => ({a: x.addr, n: x.name})); break;
      case 'Segments': rows = (await api('/api/segments')).map(x => ({a: x.start, n: `${x.name}  ${x.perms}`, t: hex(x.size)})); break;
      case 'Bookmarks': rows = (await api('/api/bookmarks')).map(x => ({a: x.addr, n: `[${x.slot}] ${x.desc}`})); break;
      case 'Patches': rows = (await api('/api/patches')).map(x => ({a: x.addr, n: `${x.original} → ${x.patched}`})); break;
      case 'Problems': rows = (await api('/api/problems')).filter(x => !f || x.message.toLowerCase().includes(f)).map(x => ({a: x.addr, n: x.message})); break;
      case 'Types': return renderTypes(body, f);
      case 'Plugins': return renderPlugins(body);
    }
  } catch (e) { body.innerHTML = `<div class="pad muted">${esc(e.message)}</div>`; return; }
  const MAX = 800; const shown = rows.slice(0, MAX);
  body.innerHTML = shown.map(r => `<div class="list-row ${r.cls || ''}" data-a="${r.a}"><span class="a">${h8(r.a)}</span><span class="n">${esc(r.n)}</span><span class="a">${esc(r.t || '')}</span></div>`).join('') +
    (rows.length > MAX ? `<div class="pad muted">${rows.length - MAX} more — refine the filter</div>` : '') + (rows.length === 0 ? '<div class="pad muted">nothing</div>' : '');
}
async function renderTypes(body, f) {
  const t = await api('/api/types');
  const mk = (title, items) => `<div class="panel-title">${title}</div>` + items.filter(n => !f || n.toLowerCase().includes(f)).slice(0, 400).map(n => `<div class="list-row" data-type="${esc(n)}"><span class="n">${esc(n)}</span></div>`).join('');
  body.innerHTML = `<div class="pad"><button id="add-types">Add C declarations…</button></div>` + mk('Structures / unions', t.structs) + mk('Enums', t.enums);
  $('#add-types').onclick = guard(async () => {
    const r = await modal('Add C declarations', '<textarea name="src" rows="12" placeholder="struct foo { int a; char *b; };"></textarea>');
    if (r && r.src.trim()) { const d = await post('/api/types/add', {source: r.src}); toast('declared: ' + d.declared.join(', ')); renderLeft(); }
  });
  $$('[data-type]', body).forEach(e => e.onclick = guard(async () => {
    const d = await api('/api/types', {name: e.dataset.type});
    modal(e.dataset.type, `<pre class="code">${esc(d.text || d.members.map(m => m[0] + ' = ' + m[1]).join('\n'))}</pre>`, [['Close', null, true]]);
  }));
}
async function renderPlugins(body) {
  const p = await api('/api/plugins');
  body.innerHTML = p.plugins.map(x => `<div class="pad"><b>${esc(x.name)}</b> <span class="muted">v${esc(x.version)} ${x.builtin ? 'builtin' : 'external'}</span><br><span class="muted">${esc(x.description)}</span><br>
    ${x.permissions.length ? '<span class="pill">needs: ' + esc(x.permissions.join(', ')) + '</span>' : ''}<button data-run="${esc(x.name)}">Run</button> ${x.hotkey ? `<span class="kbd">${esc(x.hotkey)}</span>` : ''}</div>`).join('') +
    p.rejected.map(r => `<div class="pad muted">rejected: ${esc(r.path)}<br>${esc(r.reason)}</div>`).join('');
  $$('[data-run]', body).forEach(b => b.onclick = guard(async () => {
    const r = await post('/api/plugin/run', {name: b.dataset.run}); toast(b.dataset.run + ' finished');
    showConsoleOutput(JSON.stringify(r.result, null, 1)); await refreshNames(); refreshAll();
  }));
}

// ---------------------------------------------------------------- center views
const VIEWS = {};
const VIEW_ORDER = [['disasm', 'Disassembly'], ['graph', 'Graph'], ['pseudo', 'Pseudocode'], ['hex', 'Hex'], ['results', 'Results'], ['debug', 'Debugger'],
  ['findings', 'Findings'], ['report', 'Report'], ['console', 'Console']];
function buildCenter() {
  const nav = $('#center-tabs'), body = $('#center-body');
  VIEW_ORDER.forEach(([id, label]) => {
    const b = document.createElement('button'); b.textContent = label; b.dataset.v = id; b.onclick = () => showView(id); nav.appendChild(b);
    const d = document.createElement('div'); d.className = 'view'; d.id = 'view-' + id; body.appendChild(d); VIEWS[id] = {el: d};
  });
}
async function showView(id, ctx = {}) {
  S.view = id;
  $$('#center-tabs button').forEach(b => b.classList.toggle('active', b.dataset.v === id));
  $$('.view').forEach(v => v.classList.toggle('active', v.id === 'view-' + id));
  const fn = {disasm: viewDisasm, graph: viewGraph, pseudo: viewPseudo, hex: viewHex, results: () => {}, debug: viewDebug, findings: viewFindings,
    report: viewReport, console: viewConsole}[id];
  if (fn) await guard(fn)(ctx);
}

// ---- disassembly
const D = {lines: [], busy: false};
function lineHTML(l, i) {
  const bp = S.bps.has(l.addr) && (l.kind === 'code');
  const pc = S.pcStatic === l.addr && l.kind === 'code';
  const cur = S.cur !== null && l.addr === S.cur && (l.kind === 'code' || l.kind === 'data' || l.kind === 'unknown');
  let h = `<div class="ln k-${l.kind}${cur ? ' cur' : ''}${pc ? ' pc' : ''}" data-i="${i}" data-a="${l.addr}"><span class="gut" data-bp="${l.addr}">${bp ? '●' : pc ? '▶' : ''}</span>`;
  if (l.kind === 'code' || l.kind === 'data' || l.kind === 'unknown') {
    h += `<span class="addr">${h8(l.addr)}</span><span class="bytes">${esc(l.bytes || '')}</span><span class="txt">${tokenize(l.text, l.kind)}</span>${l.comment ? `<span class="cmt">; ${esc(l.comment)}</span>` : ''}`;
  } else h += `<span class="addr">${l.kind === 'blank' ? '' : h8(l.addr)}</span><span class="txt">${tokenize(l.text, l.kind)}</span>`;
  return h + '</div>';
}
function renderDisasm(keepScroll) {
  const el = VIEWS.disasm.dis;
  const st = el.scrollTop;
  el.innerHTML = D.lines.map(lineHTML).join('');
  if (keepScroll) el.scrollTop = st;
}
async function viewDisasm(ctx) {
  const root = VIEWS.disasm.el;
  if (!VIEWS.disasm.dis) {
    root.innerHTML = '<div class="dis" style="height:100%;overflow:auto"></div>'; VIEWS.disasm.dis = root.firstChild;
    const el = VIEWS.disasm.dis;
    el.addEventListener('scroll', guard(async () => {
      if (D.busy || !D.lines.length) return;
      if (el.scrollTop + el.clientHeight > el.scrollHeight - 300) await extendDown();
      else if (el.scrollTop < 60) await extendUp();
    }));
    el.addEventListener('click', e => {
      const ln = e.target.closest('.ln'); if (!ln) return;
      const bp = e.target.closest('[data-bp]'); if (bp) { toggleBp(Number(bp.dataset.bp)); return; }
      S.cur = Number(ln.dataset.a); $('#status-addr').textContent = hex(S.cur);
      const lk = e.target.closest('.link'); S.tok = null;
      if (lk) { S.tok = {text: lk.textContent, addr: Number(lk.dataset.a)}; if (e.detail === 1 && (e.ctrlKey || e.metaKey)) return gotoAddr(S.tok.addr); }
      $$('.ln.cur', el).forEach(x => x.classList.remove('cur')); ln.classList.add('cur'); updateContext();
    });
    el.addEventListener('dblclick', e => { const lk = e.target.closest('.link'); if (lk) gotoAddr(Number(lk.dataset.a)); });
  }
  if (S.cur === null) return;
  if (ctx.prev !== undefined && D.lines.length && ctx.from !== 'reload') {
    const i = D.lines.findIndex(l => l.addr === S.cur && ['code', 'data', 'unknown'].includes(l.kind));
    if (i >= 0) { renderDisasm(true); scrollToLine(i); return; }
  }
  const r = await api('/api/disasm', {addr: hex(S.cur), count: 160, back: 40});
  D.lines = r.lines; renderDisasm(false);
  const i = D.lines.findIndex(l => l.addr >= S.cur && ['code', 'data', 'unknown'].includes(l.kind));
  scrollToLine(Math.max(0, i));
}
function scrollToLine(i) {
  const el = VIEWS.disasm.dis; const n = el.children[i]; if (!n) return;
  el.scrollTop = n.offsetTop - el.clientHeight / 3;
  $$('.ln.cur', el).forEach(x => x.classList.remove('cur')); n.classList.add('cur');
}
async function extendDown() {
  D.busy = true; try {
    const last = D.lines[D.lines.length - 1]; const next = last.addr + Math.max(last.size || 1, 1);
    const r = await api('/api/disasm', {addr: hex(next), count: 120});
    const seen = new Set(D.lines.slice(-40).map(l => l.addr + l.kind + l.text));
    const add = r.lines.filter(l => !seen.has(l.addr + l.kind + l.text));
    if (add.length) { D.lines = D.lines.concat(add); const el = VIEWS.disasm.dis; const st = el.scrollTop; el.insertAdjacentHTML('beforeend', add.map((l, k) => lineHTML(l, D.lines.length - add.length + k)).join('')); el.scrollTop = st; }
  } finally { D.busy = false; }
}
async function extendUp() {
  D.busy = true; try {
    const first = D.lines[0];
    const r = await api('/api/disasm', {addr: hex(first.addr), count: 90, back: 80});
    const add = r.lines.filter(l => l.addr < first.addr);
    if (add.length) {
      const el = VIEWS.disasm.dis; const oldH = el.scrollHeight; D.lines = add.concat(D.lines); renderDisasm(false); el.scrollTop = el.scrollHeight - oldH;
    }
  } finally { D.busy = false; }
}

// ---- pseudocode
const P = {fn: null, lines: []};
async function viewPseudo(ctx) {
  const el = VIEWS.pseudo.el;
  if (S.cur === null) return;
  const f = await api('/api/function', {addr: hex(S.cur)}).catch(() => null);
  if (!f) { el.innerHTML = '<div class="pad muted">no function at the cursor</div>'; return; }
  if (P.fn !== f.start || ctx.from === 'reload') {
    el.innerHTML = '<div class="pad muted">decompiling…</div>';
    const d = await api('/api/decompile', {addr: hex(f.start)}).catch(e => ({error: e.message}));
    if (d.error) { el.innerHTML = `<div class="pad" style="color:var(--red)">${esc(d.error)}</div>`; return; }
    P.fn = f.start; P.lines = d.lines;
    el.innerHTML = '<div class="dis pseudo"></div>';
    const box = el.firstChild;
    box.innerHTML = d.lines.map((l, i) => `<div class="ln" data-i="${i}" data-a="${l.addr}"><span class="addr">${l.addr ? h8(l.addr) : ''}</span><span class="txt">${colorC(l.text)}</span></div>`).join('');
    box.onclick = e => {
      const ln = e.target.closest('.ln'); if (!ln) return;
      $$('.ln.cur', box).forEach(x => x.classList.remove('cur')); ln.classList.add('cur');
      const lk = e.target.closest('.link'); const v = e.target.closest('.var');
      S.tok = lk ? {text: lk.textContent, addr: Number(lk.dataset.a)} : (v ? {text: v.textContent, var: true} : null);
      if (lk && (e.ctrlKey || e.detail > 1)) return gotoAddr(Number(lk.dataset.a));
      const a = Number(ln.dataset.a); if (a) { S.cur = a; $('#status-addr').textContent = hex(a); updateContext(); }
    };
  }
  // highlight the line for the cursor
  const box = el.firstChild; let best = -1;
  P.lines.forEach((l, i) => { if (l.addr && l.addr <= S.cur) best = i; });
  if (best >= 0 && box.children[best]) { $$('.ln.cur', box).forEach(x => x.classList.remove('cur')); box.children[best].classList.add('cur'); box.scrollTop = box.children[best].offsetTop - box.clientHeight / 3; el.scrollTop = box.children[best].offsetTop - el.clientHeight / 3; }
}

// ---- hex
async function viewHex() {
  const el = VIEWS.hex.el; if (S.cur === null) return;
  const base = S.cur - (S.cur % 16) - 128;
  const r = await api('/api/hex', {addr: hex(Math.max(0, base)), len: 1024});
  el.innerHTML = '<div class="dis" style="padding:6px 0"></div>';
  el.firstChild.innerHTML = r.rows.map(row => {
    const bytes = row.bytes.map((b, i) => `<span data-a="${row.addr + i}" class="${row.addr + i === S.cur ? 'cur' : ''}">${b.toString(16).padStart(2, '0')}</span>`).join(' ');
    return `<div class="hexrow"><span class="a">${h8(row.addr)}</span><span class="b">${bytes}</span><span class="muted">${esc(row.ascii)}</span></div>`;
  }).join('');
  el.firstChild.onclick = e => { const s = e.target.closest('[data-a]'); if (s) { S.cur = Number(s.dataset.a); $$('.b span.cur', el).forEach(x => x.classList.remove('cur')); s.classList.add('cur'); $('#status-addr').textContent = hex(S.cur); updateContext(); } };
}

// ---- graph
const G = {fn: null, zoom: 1, tx: 20, ty: 20, mode: 'cfg', depth: 2};
async function viewGraph(ctx) {
  const el = VIEWS.graph.el; if (S.cur === null) return;
  const f = await api('/api/function', {addr: hex(S.cur)}).catch(() => null);
  if (!f) { el.innerHTML = '<div class="pad muted">no function at the cursor</div>'; return; }
  if (G.fn !== f.start || ctx.from === 'reload' || G.drawnMode !== G.mode) {
    G.fn = f.start; G.drawnMode = G.mode;
    let g;
    if (G.mode === 'cfg') g = await api('/api/cfg', {addr: hex(f.start)});
    else {
      const p = await api('/api/proximity', {addr: hex(f.start), depth: G.depth});
      g = {function: p.center, nodes: p.nodes.map(n => ({id: n.id, start: n.id, end: n.id + 1, label: n.name, lines: []})),
           edges: p.edges.map(e => ({from: e.from, to: e.to, kind: 'jump'}))};
    }
    drawGraph(el, g);
    const bar = document.createElement('div'); bar.style.cssText = 'position:absolute;top:6px;left:8px;display:flex;gap:6px;z-index:3';
    bar.innerHTML = `<button data-m="cfg" class="${G.mode === 'cfg' ? 'primary' : ''}">Flow graph</button><button data-m="call" class="${G.mode === 'call' ? 'primary' : ''}">Call graph</button>` +
      (G.mode === 'call' ? `<button data-d="-1">−</button><span class="muted" style="align-self:center">depth ${G.depth}</span><button data-d="1">+</button>` : '');
    el.appendChild(bar);
    bar.onclick = guard(async e => { const b = e.target.closest('button'); if (!b) return;
      if (b.dataset.m) G.mode = b.dataset.m; if (b.dataset.d) G.depth = Math.max(1, Math.min(5, G.depth + Number(b.dataset.d)));
      G.fn = null; await viewGraph({}); });
  }
  $$('.gnode', el).forEach(n => n.classList.toggle('cur', S.cur >= Number(n.dataset.s) && S.cur < Number(n.dataset.e)));
}
function layoutGraph(g) {
  const CW = 7.4, LH = 15, PAD = 8;
  const nodes = new Map(g.nodes.map(n => {
    const lines = [n.label + ':'].concat(n.lines.map(l => `${h8(l.addr).slice(-6)}  ${l.text}`));
    return [n.id, {...n, text: lines, w: Math.max(...lines.map(s => s.length)) * CW + 2 * PAD, h: lines.length * LH + 2 * PAD, layer: 0, succ: [], pred: []}];
  }));
  g.edges.forEach(e => { if (nodes.has(e.from) && nodes.has(e.to)) { nodes.get(e.from).succ.push(e); nodes.get(e.to).pred.push(e); } });
  // layering: DFS, ignore back edges
  const state = new Map(), order = [];
  const back = new Set();
  const dfs = id => { state.set(id, 1); for (const e of nodes.get(id).succ) { const s = state.get(e.to); if (s === 1) back.add(e); else if (!s) dfs(e.to); } state.set(id, 2); order.push(id); };
  const entry = g.function; if (nodes.has(entry)) dfs(entry); nodes.forEach((_, id) => { if (!state.has(id)) dfs(id); });
  order.reverse();
  order.forEach(id => { const n = nodes.get(id); n.layer = 0; });
  order.forEach(id => { const n = nodes.get(id); n.succ.forEach(e => { if (!back.has(e)) { const t = nodes.get(e.to); t.layer = Math.max(t.layer, n.layer + 1); } }); });
  const layers = []; nodes.forEach(n => { (layers[n.layer] = layers[n.layer] || []).push(n); });
  layers.forEach(L => L && L.sort((a, b) => a.start - b.start));
  for (let pass = 0; pass < 4; pass++) {
    layers.forEach((L, li) => { if (!L || li === 0) return; L.forEach(n => { const ps = n.pred.filter(e => !back.has(e)).map(e => nodes.get(e.from).ord ?? 0); n.bary = ps.length ? ps.reduce((a, b) => a + b, 0) / ps.length : n.ord ?? 0; });
      L.sort((a, b) => a.bary - b.bary || a.start - b.start); L.forEach((n, i) => n.ord = i); });
    if (pass === 0) layers[0] && layers[0].forEach((n, i) => n.ord = i);
  }
  let y = 0; const GAPX = 40, GAPY = 46; let maxW = 0;
  const rows = layers.filter(Boolean);
  rows.forEach(L => { L.forEach(n => n.ord = L.indexOf(n)); maxW = Math.max(maxW, L.reduce((a, n) => a + n.w + GAPX, 0)); });
  rows.forEach(L => { const rowW = L.reduce((a, n) => a + n.w + GAPX, -GAPX); let x = (maxW - rowW) / 2; const rh = Math.max(...L.map(n => n.h)); L.forEach(n => { n.x = x; n.y = y; x += n.w + GAPX; }); y += rh + GAPY; });
  return {nodes, back, width: maxW, height: y};
}
function drawGraph(el, g) {
  const L = layoutGraph(g);
  const svgNS = 'http://www.w3.org/2000/svg';
  let svg = `<svg class="graph" xmlns="${svgNS}"><defs>${['true', 'false', 'jump', 'fall', 'switch'].map(k => `<marker id="ah-${k}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto"><path d="M0,0L10,5L0,10z" class="ahead ${k}" fill="${{true: '#5fd08a', false: '#ff6b6b', jump: '#4ea1ff', fall: '#8b93a1', switch: '#c678dd'}[k]}"/></marker>`).join('')}</defs><g id="gview">`;
  g.edges.forEach(e => {
    const a = L.nodes.get(e.from), b = L.nodes.get(e.to); if (!a || !b) return;
    const sx = a.x + a.w / 2 + ({true: -14, false: 14}[e.kind] || 0), sy = a.y + a.h, ex = b.x + b.w / 2, ey = b.y;
    let d;
    if (ey > sy + 4) { const my = (sy + ey) / 2; d = `M${sx},${sy} C${sx},${my} ${ex},${my} ${ex},${ey - 2}`; }
    else { const off = Math.max(a.w, b.w) / 2 + 30; d = `M${sx},${sy} C${sx},${sy + 40} ${Math.max(a.x + a.w, b.x + b.w) + off},${sy + 40} ${Math.max(a.x + a.w, b.x + b.w) + off},${(sy + ey) / 2} S${ex},${ey - 40} ${ex},${ey - 2}`; }
    svg += `<path class="edge ${e.kind}" d="${d}" marker-end="url(#ah-${e.kind})"/>`;
  });
  L.nodes.forEach(n => {
    svg += `<g class="gnode${n.id === g.function ? ' entry' : ''}" data-s="${n.start}" data-e="${n.end}" transform="translate(${n.x},${n.y})"><rect width="${n.w}" height="${n.h}"/>`;
    n.text.forEach((t, i) => { svg += `<text class="${i === 0 ? 'title' : ''}" x="8" y="${8 + (i + 1) * 15 - 3}">${esc(t)}</text>`; });
    svg += '</g>';
  });
  svg += '</g></svg>';
  el.innerHTML = svg;
  const s = el.firstChild, gv = $('#gview', el);
  const apply = () => gv.setAttribute('transform', `translate(${G.tx},${G.ty}) scale(${G.zoom})`);
  G.zoom = Math.min(1, (el.clientWidth - 40) / Math.max(L.width, 1)) || 1; G.tx = 20; G.ty = 20; apply();
  let drag = null;
  s.onmousedown = e => { if (e.target.closest('.gnode')) return; drag = {x: e.clientX, y: e.clientY, tx: G.tx, ty: G.ty}; };
  window.addEventListener('mousemove', e => { if (drag) { G.tx = drag.tx + e.clientX - drag.x; G.ty = drag.ty + e.clientY - drag.y; apply(); } });
  window.addEventListener('mouseup', () => drag = null);
  s.onwheel = e => { e.preventDefault(); const k = e.deltaY < 0 ? 1.1 : 0.9; const r = s.getBoundingClientRect(); const mx = e.clientX - r.left, my = e.clientY - r.top; G.tx = mx - (mx - G.tx) * k; G.ty = my - (my - G.ty) * k; G.zoom *= k; apply(); };
  s.ondblclick = e => { const n = e.target.closest('.gnode'); if (n) { S.cur = Number(n.dataset.s); showView(G.mode === 'call' ? 'graph' : 'disasm'); } };
  s.onclick = e => { const n = e.target.closest('.gnode'); if (n) { S.cur = Number(n.dataset.s); $('#status-addr').textContent = hex(S.cur); $$('.gnode', el).forEach(x => x.classList.remove('cur')); n.classList.add('cur'); updateContext(); } };
}

// ---- results (xrefs / search)
function showResults(title, rows, cols) {
  const el = VIEWS.results.el;
  el.innerHTML = `<div class="pad"><b>${esc(title)}</b> <span class="muted">${rows.length} result(s)</span></div><table class="t"><thead><tr>${cols.map(c => `<th>${esc(c[0])}</th>`).join('')}</tr></thead><tbody>${rows.map(r => `<tr data-a="${r.addr}" style="cursor:pointer">${cols.map(c => `<td class="${c[2] || ''}">${c[1](r)}</td>`).join('')}</tr>`).join('')}</tbody></table>`;
  $$('tbody tr', el).forEach(tr => tr.onclick = () => { S.view = 'disasm'; gotoAddr(Number(tr.dataset.a)); });
  showView('results');
}
async function doXrefs() {
  const a = S.tok && S.tok.addr !== undefined ? S.tok.addr : S.cur; if (a === null) return;
  const x = await api('/api/xrefs', {addr: hex(a)});
  const rows = x.to.map(r => ({addr: r.from, kind: r.kind, fn: r.function, text: r.text}));
  showResults(`Cross-references to ${hex(a)}`, rows, [['Address', r => h8(r.addr), 'mono'], ['Type', r => esc(r.kind)], ['Function', r => esc(r.fn !== null && r.fn !== undefined ? ([...S.names].find(([, v]) => v === r.fn) || ['?'])[0] : '')], ['Instruction', r => esc(r.text), 'mono']]);
}
async function doSearch() {
  const r = await modal('Search', `<div class="row"><select name="kind"><option value="text">disassembly text</option><option value="bytes">bytes (48 8B ?? 05)</option><option value="imm">immediate value</option><option value="name">names</option><option value="string">strings</option></select><label><input type="checkbox" name="regex"> regex</label></div><input type="text" name="q" placeholder="query">`);
  if (!r || !r.q) return;
  const rows = await api('/api/search', {kind: r.kind, q: r.q, regex: r.regex ? '1' : '0'});
  showResults(`Search ${r.kind}: ${r.q}`, rows, [['Address', x => h8(x.addr), 'mono'], ['Match', x => esc(x.text), 'mono']]);
}

// ---- findings / report / console
async function viewFindings() {
  const el = VIEWS.findings.el; el.innerHTML = '<div class="pad muted">scanning…</div>';
  const fs = await api('/api/triage'); const pk = await api('/api/packer');
  el.innerHTML = `<div class="pad"><b>Packing verdict:</b> ${esc(pk.verdict)} <span class="muted">(code coverage ${(pk.code_coverage * 100).toFixed(0)}%)</span></div>
  <table class="t"><thead><tr><th>Severity</th><th>Finding</th><th>Where</th><th>Evidence</th><th>Status</th></tr></thead><tbody>${fs.map(f => `<tr data-a="${f.address ?? ''}"><td><span class="sev-${f.severity}">${f.severity}</span></td><td>${esc(f.title)}<br><span class="muted">${esc(f.category)} · ${esc(f.confidence)} confidence</span></td><td class="mono">${f.address != null ? `<span class="link" data-a="${f.address}">${hex(f.address)}</span>` : ''}<br>${esc(f.function || '')}</td><td class="small">${f.evidence.slice(0, 3).map(esc).join('<br>')}</td><td><select data-f="${f.id}">${['new', 'confirmed', 'false-positive', 'fixed', 'accepted-risk', 'needs-info'].map(s => `<option ${s === f.status ? 'selected' : ''}>${s}</option>`).join('')}</select></td></tr>`).join('')}</tbody></table>`;
  $$('select[data-f]', el).forEach(s => s.onchange = guard(async () => { await post('/api/triage/status', {id: s.dataset.f, status: s.value}); toast('status saved'); }));
  $$('.link', el).forEach(l => l.onclick = () => { S.view = 'disasm'; gotoAddr(Number(l.dataset.a)); });
}
async function viewReport() {
  const el = VIEWS.report.el;
  if (!el.dataset.init) {
    el.dataset.init = 1;
    el.innerHTML = `<div class="pad"><div class="row"><button data-f="markdown">Markdown</button><button data-f="html">HTML</button><button data-f="json">JSON</button><button id="rep-dl">Download</button></div><pre id="rep-out" class="code" style="white-space:pre-wrap"></pre></div>`;
    $$('button[data-f]', el).forEach(b => b.onclick = guard(async () => { $('#rep-out').textContent = 'generating…'; const r = await api('/api/report', {fmt: b.dataset.f}); el.dataset.fmt = b.dataset.f; $('#rep-out').textContent = r.text; }));
    $('#rep-dl').onclick = () => { const t = $('#rep-out').textContent; const f = el.dataset.fmt || 'markdown'; const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([t])); a.download = 'report.' + (f === 'markdown' ? 'md' : f); a.click(); };
  }
}
function showConsoleOutput(t) { const o = $('#con-out'); if (o) o.textContent = t; }
async function viewConsole() {
  const el = VIEWS.console.el;
  if (el.dataset.init) return; el.dataset.init = 1;
  el.innerHTML = `<div class="pad"><div class="row"><b>Python console</b><span class="muted">objects: proj, db, image; scripting shims: rk, rkutil, rkapi</span><div class="spacer"></div><button class="primary" id="con-run">Run (Ctrl+Enter)</button></div>
  <textarea id="con-src" rows="12">for f in rkutil.Functions():\n    print(hex(f), rk.get_func_name(f))\n    break</textarea><pre id="con-out" class="code" style="min-height:120px"></pre></div>`;
  $('#con-src').value = "# proj is the revkit Project\nprint(proj.info()['sha256'])\nfor ea in list(rkutil.Functions())[:5]:\n    print(hex(ea), rk.get_func_name(ea))";
  const run = guard(async () => { const r = await post('/api/script', {code: $('#con-src').value}); $('#con-out').textContent = r.output + (r.ok ? '' : '\n' + r.error); await refreshNames(); });
  $('#con-run').onclick = run; $('#con-src').addEventListener('keydown', e => { if (e.ctrlKey && e.key === 'Enter') run(); });
}

// ---- debugger
async function viewDebug() {
  const el = VIEWS.debug.el;
  if (!el.dataset.init) {
    el.dataset.init = 1;
    el.innerHTML = `<div class="pad"><div class="row">
      <button id="dbg-launch">Launch</button><button id="dbg-gdb">Connect GDB…</button>
      <button data-c="cont">Continue (F9)</button><button data-c="step">Step into (F7)</button><button data-c="over">Step over (F8)</button><button data-c="out">Step out</button><button data-c="pause">Pause</button><button data-c="kill">Kill</button></div>
      <div id="dbg-state" class="muted">no session</div>
      <div class="row" style="align-items:flex-start"><div style="min-width:260px"><b>Registers</b><div id="dbg-regs" class="regs"></div></div>
      <div style="flex:1;min-width:320px"><b>Disassembly at PC</b><div id="dbg-dis" class="code" style="white-space:pre"></div><b>Backtrace</b><div id="dbg-bt" class="code" style="white-space:pre"></div></div>
      <div style="min-width:260px"><b>Breakpoints</b><div id="dbg-bps"></div><b>Modules</b><div id="dbg-mods" class="small"></div></div></div>
      <div class="row"><input id="dbg-eval" placeholder="evaluate: rsp+8, qword(rsp), rax*2 …" style="width:340px"><button id="dbg-eval-go">Eval</button><span id="dbg-eval-out" class="mono"></span></div>
      <div class="row"><input id="dbg-mem-addr" placeholder="memory address" style="width:200px"><input id="dbg-mem-len" value="128" style="width:70px"><button id="dbg-mem-go">Read</button></div>
      <pre id="dbg-mem" class="code"></pre><b>Events</b><pre id="dbg-events" class="code small"></pre></div>`;
    $('#dbg-launch').onclick = guard(async () => { const r = await modal('Launch under debugger', '<div class="muted">This executes the sample on this machine. Use an isolated VM.</div><label>Arguments<br><input type="text" name="args" placeholder="optional"></label>'); if (!r) return; await post('/api/debug/start', {backend: 'native', args: r.args ? r.args.split(' ') : []}); toast('session started'); debugRefresh(); });
    $('#dbg-gdb').onclick = guard(async () => { const r = await ask('Connect to GDB stub', 'host:port', '127.0.0.1:1234'); if (!r) return; const [h, p] = r.split(':'); await post('/api/debug/start', {backend: 'gdb', host: h, port: Number(p)}); toast('connected'); debugRefresh(); });
    $$('button[data-c]', el).forEach(b => b.onclick = () => dbgCmd(b.dataset.c));
    $('#dbg-eval-go').onclick = guard(async () => { const r = await api('/api/debug/info', {what: 'eval', expr: $('#dbg-eval').value}); $('#dbg-eval-out').textContent = `= ${r.value} (${r.hex})`; });
    $('#dbg-mem-go').onclick = guard(async () => { const a = resolveLocal($('#dbg-mem-addr').value); const r = await api('/api/debug/mem', {addr: a ?? parseInt($('#dbg-mem-addr').value), len: $('#dbg-mem-len').value}); $('#dbg-mem').textContent = r.rows.map(x => `${h8(x.addr)}  ${x.hex.padEnd(47)}  ${x.ascii}`).join('\n'); });
  }
  debugRefresh();
}
const dbgCmd = guard(async cmd => { const r = await post('/api/debug/cmd', {cmd}); if (r.event && r.event.addr && S.pcStatic !== null) {} await debugRefresh(true); });
async function debugRefresh(follow) {
  const d = await api('/api/debug/state'); S.dbg = d; S.bps = new Map(); S.pcStatic = d.static_pc ?? null;
  (d.breakpoints || []).forEach(b => { if (b.static_addr != null) S.bps.set(b.static_addr, b); });
  $('#status-dbg').textContent = d.active ? `debugger: ${d.state}` : '';
  const st = $('#dbg-state'); if (!st) return;
  if (!d.active) { st.textContent = 'no session'; return; }
  st.textContent = `${d.state} — ${d.last_event ? d.last_event.kind : ''} ${d.pc != null ? hex(d.pc) : ''}${d.static_pc != null ? ' (static ' + hex(d.static_pc) + ')' : ''}`;
  if (d.regs) {
    $('#dbg-regs').innerHTML = Object.entries(d.regs).map(([k, v]) => `<span>${k}</span><span class="v ${S.regsPrev[k] !== undefined && S.regsPrev[k] !== v ? 'ch' : ''}" data-r="${k}">0x${v.toString(16).padStart(d.bits / 4, '0')}</span>`).join('');
    S.regsPrev = d.regs;
    $$('#dbg-regs .v').forEach(sp => sp.ondblclick = guard(async () => { const nv = await ask('Set ' + sp.dataset.r, 'new value', sp.textContent); if (nv) { await post('/api/debug/set_reg', {name: sp.dataset.r, value: nv}); debugRefresh(); } }));
    api('/api/debug/info', {what: 'disasm', n: 8}).then(r => $('#dbg-dis').textContent = r.map(x => `${hex(x.addr)}  ${x.bytes.padEnd(24)} ${x.text}`).join('\n')).catch(() => {});
    api('/api/debug/info', {what: 'bt'}).then(r => $('#dbg-bt').textContent = r.map((f, i) => `#${i} ${hex(f.pc)}  ${f.symbol || ''}`).join('\n')).catch(() => {});
  }
  $('#dbg-bps').innerHTML = (d.breakpoints || []).map(b => `<div class="list-row" data-bid="${b.id}"><span class="a">#${b.id}</span><span class="n">${hex(b.addr)} ${b.kind}${b.condition ? ' if ' + esc(b.condition) : ''}</span><span class="a">${b.hits}×</span><span class="link" data-rm="${b.id}">✕</span></div>`).join('') || '<span class="muted">none</span>';
  $$('[data-rm]').forEach(x => x.onclick = guard(async () => { await post('/api/debug/bp', {remove: true, id: x.dataset.rm}); debugRefresh(); }));
  api('/api/debug/info', {what: 'modules'}).then(r => $('#dbg-mods').innerHTML = r.slice(0, 40).map(m => `<div>${hex(m.base)} ${esc(m.name)}</div>`).join('')).catch(() => {});
  $('#dbg-events').textContent = (d.events || []).slice(-15).map(e => JSON.stringify(e)).join('\n');
  if (follow && d.static_pc != null) { S.view = 'disasm'; await gotoAddr(d.static_pc, {noHist: true, from: 'reload'}); }
  else if (VIEWS.disasm.dis && D.lines.length) renderDisasm(true);
}
const toggleBp = guard(async a => {
  const have = S.bps.get(a);
  if (have) await post('/api/debug/bp', {remove: true, id: have.id});
  else {
    if (!S.dbg || !S.dbg.active) { toast('start a debug session first (Debugger tab)', true); return; }
    await post('/api/debug/bp', {addr: hex(a)});
  }
  await debugRefresh();
});

// ---------------------------------------------------------------- context panel
let ctxTimer = null;
function updateContext() { clearTimeout(ctxTimer); ctxTimer = setTimeout(guard(renderContext), 60); }
async function renderContext() {
  if (S.cur === null) return;
  const [c, f] = await Promise.all([api('/api/context', {addr: hex(S.cur)}), api('/api/function', {addr: hex(S.cur)}).catch(() => null)]);
  S.func = f;
  const lk = (a, n) => `<span class="link" data-a="${a}">${esc(n)}</span>`;
  let h = `<div><span class="mono">${hex(c.addr)}</span> ${c.name ? '<b>' + esc(c.name) + '</b>' : ''}<br><span class="muted">${esc(c.segment || '')}</span></div>`;
  if (c.insn) h += `<div class="mono" style="margin-top:4px">${esc(c.insn.text)}</div><div class="muted mono">${esc(c.insn.bytes)} · ${c.insn.size}b · ${c.insn.flow}</div>`;
  if (c.comment) h += `<div style="margin-top:4px"><span class="muted">comment:</span> ${esc(c.comment)}</div>`;
  if (f) {
    h += `<hr style="border-color:var(--border)"><div><b>${esc(f.name)}</b> <span class="muted">${hex(f.start)}–${hex(f.end)}</span></div><div class="muted">${f.flags.map(x => `<span class="pill">${esc(x)}</span>`).join('')}</div>
    <div class="muted">${esc(f.callconv || '')} · frame ${f.frame} · complexity ${f.complexity} · loops ${f.loops.length}</div>${f.proto ? `<div class="mono">${esc(f.proto)}</div>` : ''}${f.comment ? `<div>${esc(f.comment)}</div>` : ''}
    <div style="margin-top:6px"><b>Callers (${f.callers.length})</b><br>${f.callers.slice(0, 30).map(x => lk(x.addr, x.name)).join('<br>')}</div>
    <div style="margin-top:6px"><b>Callees (${f.callees.length})</b><br>${f.callees.slice(0, 40).map(x => lk(x.addr, x.name)).join('<br>')}</div>`;
  }
  $('#context').innerHTML = h;
  $$('#context .link').forEach(l => l.onclick = () => gotoAddr(Number(l.dataset.a)));
}

// ---------------------------------------------------------------- actions
const target = () => (S.tok && S.tok.addr !== undefined && !S.tok.var) ? S.tok.addr : S.cur;
const actions = {
  rename: guard(async () => {
    if (S.view === 'pseudo' && S.tok && S.tok.var) {
      const nn = await ask('Rename variable', 'new name', S.tok.text); if (!nn) return;
      await post('/api/rename_var', {func: P.fn, old: S.tok.text, new: nn}); P.fn = null; showView('pseudo'); return;
    }
    const a = target(); if (a === null) return;
    const cur = [...S.names].find(([, v]) => v === a); const nn = await ask(`Rename ${hex(a)}`, 'name', cur ? cur[0] : '');
    if (nn === null) return; await post('/api/rename', {addr: a, name: nn}); await refreshNames(); refreshAll();
  }),
  comment: guard(async (rep) => { const a = S.cur; const t = await ask(rep ? 'Repeatable comment' : 'Comment', 'text'); if (t === null) return; await post('/api/comment', {addr: a, text: t, repeatable: !!rep}); refreshAll(); }),
  goto: guard(async () => { const t = await ask('Jump to address', 'address or name'); if (!t) return; const a = resolveLocal(t); if (a === null) return toast('unknown: ' + t, true); S.view = S.view === 'results' ? 'disasm' : S.view; gotoAddr(a); }),
  xrefs: guard(doXrefs), search: guard(doSearch),
  toggleGraph: () => showView(S.view === 'graph' ? 'disasm' : 'graph'),
  toggleCode: () => showView(S.view === 'pseudo' ? 'disasm' : 'pseudo'), decompile: () => showView('pseudo', {from: 'reload'}),
  makeCode: guard(async () => { await post('/api/make', {what: 'code', addr: S.cur}); await refreshNames(); refreshAll(); }),
  makeData: guard(async () => { const order = ['byte', 'word', 'dword', 'qword']; S.dkind = order[((order.indexOf(S.dkind) + 1) % 4)] || 'byte'; await post('/api/make', {what: 'data', addr: S.cur, kind: S.dkind}); toast('data: ' + S.dkind); refreshAll(); }),
  undefine: guard(async () => { await post('/api/make', {what: 'undefine', addr: S.cur, size: 1}); await refreshNames(); refreshAll(); }),
  makeFunc: guard(async () => { await post('/api/make', {what: 'function', addr: S.cur}); await refreshNames(); refreshAll(); }),
  makeString: guard(async () => { const r = await post('/api/make', {what: 'string', addr: S.cur}); toast('string: ' + r.text); refreshAll(); }),
  setType: guard(async () => { const t = await ask('Apply type / prototype', 'C declaration (e.g. int __cdecl f(char *s) or struct foo)', S.func && S.cur === S.func.start ? S.func.proto : ''); if (!t) return; await post('/api/type', {addr: S.cur, decl: t}); refreshAll(); }),
  opFormat: guard(async () => { const order = ['hex', 'dec', 'oct', 'bin', 'char', 'neg']; S.fmtI = ((S.fmtI ?? -1) + 1) % order.length; await post('/api/opfmt', {addr: S.cur, op: 1, fmt: order[S.fmtI]}); toast('operand format: ' + order[S.fmtI]); refreshAll(); }),
  bookmark: guard(async () => { const d = await ask('Bookmark', 'description'); if (d === null) return; await post('/api/bookmark', {addr: S.cur, desc: d}); if (S.leftTab === 'Bookmarks') renderLeft(); toast('bookmarked'); }),
  back: goBack, forward: goForward,
  undo: guard(async () => { const r = await post('/api/undo'); toast(r.undone ? 'undo: ' + r.undone : 'nothing to undo'); await refreshNames(); refreshAll(); }),
  redo: guard(async () => { const r = await post('/api/redo'); toast(r.redone ? 'redo: ' + r.redone : 'nothing to redo'); await refreshNames(); refreshAll(); }),
  save: guard(async () => { const r = await post('/api/save'); toast('saved ' + r.path); pollState(); }),
  bp: () => S.cur !== null && toggleBp(S.cur), stepInto: () => dbgCmd('step'), stepOver: () => dbgCmd('over'), cont: () => dbgCmd('cont'),
  hexView: () => showView('hex'),
  patch: guard(async () => {
    const r = await modal('Patch at ' + hex(S.cur), '<label>Assembly (optional)<br><input type="text" name="asm" placeholder="mov eax, 1"></label><br><label>or hex bytes<br><input type="text" name="bytes" placeholder="90 90"></label><br><label>or NOP count<br><input type="text" name="nop"></label>');
    if (!r) return; const body = {addr: S.cur}; if (r.asm) body.asm = r.asm; else if (r.bytes) body.bytes = r.bytes; else if (r.nop) body.nop = Number(r.nop); else return;
    await post('/api/patch', body); toast('patched'); refreshAll();
  }),
  settings: guard(openSettings),
};
const refreshAll = () => { P.fn = null; G.fn = null; showView(S.view, {from: 'reload', prev: undefined}); renderLeft(); updateContext(); pollState(); };

async function openSettings() {
  const k = keys();
  const r = await modal('Settings', `<div class="row"><label>Theme <select name="theme">${['dark', 'light', 'contrast'].map(t => `<option ${t === S.settings.theme ? 'selected' : ''}>${t}</option>`).join('')}</select></label>
    <label>Font <input name="font" value="${esc(S.settings.font)}"></label><label>Size <input name="fontSize" value="${S.settings.fontSize}" style="width:50px"></label></div>
    <b>Shortcuts</b> <span class="muted">(single key, or ctrl+key)</span><div style="display:grid;grid-template-columns:1fr 1fr;gap:3px 12px;margin-top:6px">${Object.keys(DEFAULT_KEYS).map(a => `<label>${a}<br><input name="k_${a}" value="${esc(k[a] === ' ' ? 'Space' : k[a])}" style="width:120px"></label>`).join('')}</div>`);
  if (!r) return;
  S.settings.theme = r.theme; S.settings.font = r.font; S.settings.fontSize = Number(r.fontSize) || 13; S.settings.shortcuts = {};
  Object.keys(DEFAULT_KEYS).forEach(a => { let v = r['k_' + a]; if (v === 'Space') v = ' '; if (v && v !== DEFAULT_KEYS[a]) S.settings.shortcuts[a] = v; });
  applySettings(); localStorage.setItem('rk-settings', JSON.stringify(S.settings)); await post('/api/settings', S.settings);
}
function applySettings() {
  document.body.dataset.theme = S.settings.theme;
  document.documentElement.style.setProperty('--font', S.settings.font); document.documentElement.style.setProperty('--fsize', S.settings.fontSize + 'px');
}

// ---------------------------------------------------------------- keyboard
document.addEventListener('keydown', e => {
  if (e.target.matches('input,textarea,select')) return;
  if ($('#modal-root').children.length) return;
  const K = keys(); let key = e.key; if (e.ctrlKey || e.metaKey) key = 'ctrl+' + key.toLowerCase();
  if (e.altKey && e.key === 'ArrowLeft') { e.preventDefault(); return actions.back(); }
  if (e.altKey && e.key === 'ArrowRight') { e.preventDefault(); return actions.forward(); }
  for (const [name, k] of Object.entries(K)) {
    if (k === key || (k.length === 1 && k === key && !e.ctrlKey)) {
      if (!actions[name]) continue; e.preventDefault(); actions[name](name === 'rcomment'); return;
    }
  }
});
$$('#topbar [data-act]').forEach(b => b.onclick = () => (actions[b.dataset.act] || (() => {}))());
$('#left-filter').addEventListener('input', () => { clearTimeout(renderLeft.t); renderLeft.t = setTimeout(renderLeft, 150); });
$('#left-body').addEventListener('click', e => { const r = e.target.closest('.list-row[data-a]'); if (r) { S.view = ['results', 'report', 'console', 'findings', 'debug'].includes(S.view) ? 'disasm' : S.view; gotoAddr(Number(r.dataset.a)); } });
// resizable side panels
[['gutter-left', 'left', 1], ['gutter-right', 'right', -1]].forEach(([g, p, dir]) => {
  const gut = $('#' + g), panel = $('#' + p);
  gut.onmousedown = e => { const x0 = e.clientX, w0 = panel.offsetWidth; const mv = ev => { panel.style.width = Math.max(120, w0 + dir * (ev.clientX - x0)) + 'px'; }; const up = () => { window.removeEventListener('mousemove', mv); window.removeEventListener('mouseup', up); }; window.addEventListener('mousemove', mv); window.addEventListener('mouseup', up); };
});

async function pollState() {
  try {
    const s = await api('/api/state'); S.state = s;
    $('#dirty').hidden = !s.dirty;
    $('[data-act=undo]').disabled = !s.can_undo; $('[data-act=redo]').disabled = !s.can_redo;
    $('#status-msg').textContent = s.undo_label ? 'last edit: ' + s.undo_label : '';
  } catch (e) { /* ignore */ }
}

// ---------------------------------------------------------------- boot
(async function boot() {
  try { S.settings = {...S.settings, ...JSON.parse(localStorage.getItem('rk-settings') || '{}')}; } catch (e) {}
  try { const srv = await api('/api/settings'); if (srv && !localStorage.getItem('rk-settings')) S.settings = {...S.settings, ...srv}; } catch (e) {}
  applySettings(); buildLeftTabs(); buildCenter();
  try {
    S.info = await api('/api/info');
  } catch (e) { document.body.innerHTML = `<div class="pad" style="color:#f66">Cannot reach the revkit API: ${esc(e.message)}.<br>Open the URL printed by <code>revkit serve</code> (it contains the access token).</div>`; return; }
  $('#file-name').textContent = S.info.path.split(/[\\/]/).pop() + `  ·  ${S.info.format}  ·  ${S.info.arch_key}`;
  document.title = 'revkit — ' + S.info.path.split(/[\\/]/).pop();
  await refreshNames(); renderLeft();
  const entry = (S.info.entry_points[0] || {}).addr ?? (S.funcs[0] || {}).addr;
  const main = S.funcs.find(f => /^_?main$|^wmain$|^WinMain$/.test(f.name));
  await gotoAddr(main ? main.addr : entry, {noHist: true});
  pollState(); setInterval(pollState, 4000);
  const dbgPoll = setInterval(async () => { if (S.dbg && S.dbg.active && S.dbg.state === 'running') debugRefresh(true).catch(() => {}); }, 1500);
})();
