'use strict';
// PrivGuard showcase: replays data/demo.json (real model output) and renders data/demo.json's metrics.

const $ = (s, el = document) => el.querySelector(s);
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
const hhmmss = (ms) => new Date(ms).toISOString().slice(11, 19);
const isAlert = (e) => e.severity !== 'low';
const SEVERITIES = ['low', 'medium', 'high', 'critical'];
const DETECTORS = [['Rules', 'Rules'], ['IsolationForest', 'Isolation Forest'], ['Autoencoder', 'Autoencoder'], ['Hybrid', 'Hybrid (served)']];
const ATTACKS = {
  checkout_burst: 'Checkout burst', lateral_movement: 'Lateral movement', new_source_host: 'New source host',
  off_hours_admin: 'Off-hours admin', privilege_escalation: 'Privilege escalation',
};
const TICK_MS = 100;

let D, events, compromised, t0, t1, attackSpan, clock, shown, timer, selected, steps;

// ---------- helpers ----------
const tip = $('#tip');
function showTip(html, ev) {
  tip.innerHTML = html;
  tip.style.opacity = 1;
  const x = Math.min(ev.pageX + 14, window.scrollX + document.documentElement.clientWidth - tip.offsetWidth - 8);
  tip.style.left = `${x}px`;
  tip.style.top = `${ev.pageY + 14}px`;
}
const hideTip = () => { tip.style.opacity = 0; };
const debounce = (fn, ms) => { let h; return () => { clearTimeout(h); h = setTimeout(fn, ms); }; };
const chip = (sev) => `<span class="chip ${sev}">${sev}</span>`;
const svgEl = (w, h) => `<svg viewBox="0 0 ${w} ${h}" width="${w}" height="${h}" role="img">`;
const fmt = (x, d = 2) => x.toFixed(d);

// ---------- theme ----------
$('#theme').addEventListener('click', () => {
  const root = document.documentElement;
  const dark = root.dataset.theme ? root.dataset.theme === 'dark' : matchMedia('(prefers-color-scheme: dark)').matches;
  root.dataset.theme = dark ? 'light' : 'dark';
  try { localStorage.setItem('privguard-theme', root.dataset.theme); } catch { /* storage unavailable */ }
});

// ---------- hero ----------
function renderStats() {
  const H = D.metrics.detectors.Hybrid;
  const attack = events.filter((e) => e.step);
  const others = events.filter((e) => !e.step && !compromised.has(e.user));
  const stats = [
    [`${H.incidents_detected}/${H.incidents}`, 'attack incidents detected on the 14-day test period'],
    [fmt(H.pr_auc), `PR-AUC of the served model (random: ${fmt(D.metrics.split.test_attack_events / D.metrics.split.test_events, 3)})`],
    [`${attack.filter(isAlert).length}/${attack.length}`, 'kill-chain events alerted in the replay below'],
    [`${others.filter(isAlert).length}`, `false alerts on ${others.length} benign events of other accounts in the replay`],
  ];
  $('#stats').innerHTML = stats.map(([v, l]) => `<div class="stat"><div class="v">${v}</div><div class="l">${l}</div></div>`).join('');
}

// ---------- replay ----------
function resetSteps() {
  steps = Object.entries(D.kill_chain).map(([key, label]) => ({ key, label, seen: 0, alerted: 0, first: null, max: 0 }));
}

function renderSteps() {
  $('#steps').innerHTML = steps.map((s, i) => {
    const [title, desc] = s.label.split(': ');
    const state = s.alerted ? 'detected' : s.seen ? 'active' : 'pending';
    const status = s.alerted
      ? `Detected at ${hhmmss(s.first)} · ${s.alerted}/${s.seen} alerted · max risk ${s.max.toFixed(1)}`
      : s.seen ? `${s.seen} events, not alerted yet` : 'Not started';
    return `<div class="step" data-state="${state}"><div class="n">Step ${i + 1} · ${esc(title)}</div>
      <div class="t">${esc(desc)}</div><div class="s"><span class="dot"></span>${status}</div></div>`;
  }).join('');
}

function feedRow(e) {
  const row = document.createElement('div');
  const target = `${esc(e.src)} → ${esc(e.dst)}`;
  const cmd = e.command ? ` <span class="mono">${esc(e.command)}</span>` : '';
  if (!isAlert(e)) {
    row.className = 'row benign';
    row.innerHTML = `<span class="time">${hhmmss(e.ms)}</span><span class="what">${esc(e.user)} ${e.type} ${target}${cmd}</span>`;
    return row;
  }
  const truth = e.step ? `<span class="truth attack">attack: ${esc(ATTACKS[e.step] || e.step)}</span>`
    : `<span class="truth">benign${compromised.has(e.user) ? ', on the compromised account' : ''}</span>`;
  row.className = 'row alert';
  row.innerHTML = `<span class="time">${hhmmss(e.ms)}</span>
    <span class="what">${chip(e.severity)} <b>${e.risk.toFixed(1)}</b> ${esc(e.user)} ${e.type} ${target}${cmd}</span>
    <span class="why">${esc(e.explanation)} ${truth}</span>`;
  row.addEventListener('click', () => select(e));
  return row;
}

function onEvents(list) {
  const feed = $('#feed');
  if (feed.querySelector('.empty')) feed.innerHTML = '';
  for (const e of list) {
    feed.prepend(feedRow(e));
    const s = steps.find((x) => x.key === e.step);
    if (s) {
      s.seen += 1;
      if (isAlert(e)) { s.alerted += 1; s.first ??= e.ms; s.max = Math.max(s.max, e.risk); }
    }
    if (!selected && e.severity === 'critical') select(e);
  }
  renderSteps();
  renderQueue();
}

function update() {
  const visible = events.slice(0, shown);
  $('#clock').textContent = hhmmss(clock);
  $('#progress').style.width = `${(100 * (clock - t0)) / (t1 - t0)}%`;
  $('#c-events').textContent = shown;
  $('#c-alerts').textContent = visible.filter(isAlert).length;
  $('#c-fp').textContent = visible.filter((e) => isAlert(e) && !e.step && !compromised.has(e.user)).length;
  drawTimeline();
}

function reveal() {
  const added = [];
  while (shown < events.length && events[shown].ms <= clock) added.push(events[shown++]);
  if (added.length) onEvents(added);
}

function tick() {
  clock = Math.min(t1, clock + TICK_MS * Number($('#speed').value));
  reveal();
  if (clock >= t1) stop();
  update();
}

function play() {
  if (clock >= t1) restart();
  timer = setInterval(tick, TICK_MS);
  $('#play').textContent = '❚❚ Pause';
}

function stop() {
  clearInterval(timer);
  timer = null;
  $('#play').textContent = clock >= t1 ? '▶ Replay' : '▶ Play';
}

function restart() {
  stop();
  clock = t0;
  shown = 0;
  selected = null;
  resetSteps();
  $('#feed').innerHTML = '<div class="empty">Press play to start the replay.</div>';
  $('#detail').innerHTML = '<div class="empty">Select an alert to see why it fired.</div>';
  renderSteps();
  renderQueue();
  update();
  $('#play').textContent = '▶ Play';
}

function skip() {
  stop();
  clock = t1;
  reveal();
  update();
  stop();
  const top = events.filter(isAlert).sort((a, b) => b.risk - a.risk)[0];
  if (top) select(top);
}

// ---------- queue + detail ----------
function renderQueue() {
  const alerts = events.slice(0, shown).filter(isAlert).sort((a, b) => b.risk - a.risk || b.ms - a.ms);
  $('#queue-empty').style.display = alerts.length ? 'none' : '';
  const body = $('#queue tbody');
  body.innerHTML = alerts.map((e) => `<tr data-i="${e.i}" class="${selected === e ? 'sel' : ''}">
      <td>${chip(e.severity)}</td><td class="num">${e.risk.toFixed(1)}</td><td class="mono">${hhmmss(e.ms)}</td>
      <td>${esc(e.user)}</td><td>${e.type}${e.command ? ` <span class="mono">${esc(e.command.slice(0, 28))}${e.command.length > 28 ? '…' : ''}</span>` : ''}</td>
      <td>${esc(e.dst)}</td></tr>`).join('');
  body.querySelectorAll('tr').forEach((tr) => tr.addEventListener('click', () => select(events[Number(tr.dataset.i)])));
}

function select(e) {
  selected = e;
  const truth = e.step ? `<span class="truth attack">Ground truth: ${esc(D.kill_chain[e.step] || e.step)}</span>`
    : `<span class="truth">Ground truth: benign${compromised.has(e.user) ? ' activity on the compromised account (its 1-hour window includes the attack)' : ''}</span>`;
  const maxC = Math.max(...e.top_features.map((f) => Math.abs(f.contribution)), 1e-9);
  const bars = e.top_features.map((f) => `<div class="bar"><span class="mono">${esc(f.feature)}</span>
      <div class="track"><div class="fill ${f.contribution < 0 ? 'neg' : ''}" style="width:${(100 * Math.abs(f.contribution)) / maxC}%"></div></div>
      <span class="mono">${f.contribution > 0 ? '+' : ''}${f.contribution.toFixed(2)}</span></div>`).join('');
  $('#detail').innerHTML = `
    <div>${chip(e.severity)} <b>risk ${e.risk.toFixed(1)}</b> &nbsp;${truth}</div>
    <p class="expl">${esc(e.explanation)}</p>
    ${e.reasons.length > 1 ? `<ul>${e.reasons.map((r) => `<li>${esc(r)}</li>`).join('')}</ul>` : ''}
    <div style="font-size:13px;margin-bottom:12px">Rules fired: ${e.rules.length ? e.rules.map((r) => `<span class="tag">${esc(r)}</span>`).join(' ') : '<span class="muted">none, flagged by the Isolation Forest alone</span>'}</div>
    ${bars ? `<div class="muted" style="font-size:12px;margin-bottom:4px">SHAP: features that raised the anomaly score</div><div class="bars">${bars}</div>` : ''}
    <dl class="kv">
      <dt>Time</dt><dd class="mono">${esc(e.t.replace('T', ' '))}</dd>
      <dt>Account</dt><dd>${esc(e.user)} (${esc(e.account_type)})</dd>
      <dt>Source → target</dt><dd>${esc(e.src)} → ${esc(e.dst)}</dd>
      <dt>Event</dt><dd>${esc(e.type)}${e.success ? '' : ' (failed)'}</dd>
      ${e.command ? `<dt>Command</dt><dd class="mono">${esc(e.command)}</dd>` : ''}
    </dl>`;
  renderQueue();
  drawTimeline();
}

// ---------- risk timeline (SVG) ----------
function drawTimeline() {
  const el = $('#timeline');
  const W = Math.max(320, el.clientWidth - 32);
  const H = W < 560 ? 240 : 300;
  const m = { l: 30, r: 74, t: 18, b: 26 };
  const x = (ms) => m.l + ((ms - t0) / (t1 - t0)) * (W - m.l - m.r);
  const y = (r) => m.t + (1 - r / 100) * (H - m.t - m.b);
  let s = svgEl(W, H);
  s += `<rect x="${x(attackSpan[0])}" y="${m.t}" width="${x(attackSpan[1]) - x(attackSpan[0])}" height="${H - m.t - m.b}" style="fill:var(--surface-2)"/>`;
  s += `<text x="${x(attackSpan[0]) + 4}" y="${m.t - 5}">kill chain</text>`;
  s += '<g class="grid">';
  for (let r = 0; r <= 100; r += 20) s += `<line x1="${m.l}" x2="${W - m.r}" y1="${y(r)}" y2="${y(r)}"/><text x="${m.l - 6}" y="${y(r) + 4}" text-anchor="end">${r}</text>`;
  s += '</g>';
  const step = 15 * 60e3;
  for (let ms = Math.ceil(t0 / step) * step; ms <= t1; ms += step) s += `<text x="${x(ms)}" y="${H - 6}" text-anchor="middle">${hhmmss(ms).slice(0, 5)}</text>`;
  for (const [sev, r] of [['medium', 40], ['high', 70], ['critical', 90]]) {
    s += `<line x1="${m.l}" x2="${W - m.r}" y1="${y(r)}" y2="${y(r)}" style="stroke:var(--sev-${sev})" stroke-dasharray="4 4" stroke-width="1.5"/>`;
    s += `<text x="${W - m.r + 6}" y="${y(r) + 4}">${sev} ≥ ${r}</text>`;
  }
  if (clock > t0) s += `<line x1="${x(clock)}" x2="${x(clock)}" y1="${m.t}" y2="${H - m.b}" style="stroke:var(--accent)" stroke-width="1"/>`;
  const visible = events.slice(0, shown);
  for (const e of visible) {
    const sel = e === selected;
    s += `<circle cx="${x(e.ms)}" cy="${y(e.risk)}" r="${sel ? 7 : 4.5}" style="fill:var(--sev-${e.severity});stroke:${sel ? 'var(--text)' : 'var(--card)'}" stroke-width="2"/>`;
  }
  el.innerHTML = `${s}</svg>`;
  const svg = el.querySelector('svg');
  const nearest = (ev) => {
    const rect = svg.getBoundingClientRect();
    const px = ((ev.clientX - rect.left) * W) / rect.width;
    const py = ((ev.clientY - rect.top) * H) / rect.height;
    let best = null; let bd = 14 * 14;
    for (const e of visible) {
      const d = (x(e.ms) - px) ** 2 + (y(e.risk) - py) ** 2;
      if (d < bd) { bd = d; best = e; }
    }
    return best;
  };
  svg.addEventListener('mousemove', (ev) => {
    const e = nearest(ev);
    svg.style.cursor = e && isAlert(e) ? 'pointer' : 'default';
    if (!e) return hideTip();
    const truth = e.step ? `attack: ${ATTACKS[e.step] || e.step}` : 'benign';
    showTip(`<b>${e.risk.toFixed(1)}</b> ${chip(e.severity)}<br>${hhmmss(e.ms)} · ${esc(e.user)} ${e.type}<br>${esc(e.src)} → ${esc(e.dst)}<br><span class="muted">${truth}</span>`, ev);
  });
  svg.addEventListener('mouseleave', hideTip);
  svg.addEventListener('click', (ev) => { const e = nearest(ev); if (e && isAlert(e)) select(e); });
}

function renderSevLegend() {
  $('#sev-legend').innerHTML = SEVERITIES.map((s) => `<span><i class="sw" style="background:var(--sev-${s})"></i>${s}</span>`).join('');
}

// ---------- results ----------
function renderMetrics() {
  const sp = D.metrics.split;
  $('#results-sub').textContent = `Trained on the clean baseline (${sp.train_events.toLocaleString()} events before ${sp.boundary.slice(0, 10)}), `
    + `evaluated on ${sp.test_events.toLocaleString()} events over ${sp.test_days} days with ${sp.test_attack_events} attack events from ${sp.test_incidents} incidents. `
    + 'Alert thresholds are set without labels: the 99th percentile of each model\'s own baseline scores.';
  const cols = [
    ['Precision', (d) => d.precision, (v) => fmt(v), 'max'], ['Recall', (d) => d.recall, (v) => fmt(v), 'max'],
    ['F1', (d) => d.f1, (v) => fmt(v), 'max'], ['PR-AUC', (d) => d.pr_auc, (v) => fmt(v), 'max'],
    ['FPR', (d) => d.fpr, (v) => `${(100 * v).toFixed(2)}%`, 'min'],
    ['Incidents', (d) => d.incident_recall, (v, d) => `${d.incidents_detected}/${d.incidents}`, 'max'],
    ['Benign alerts/day', (d) => d.benign_alerts_per_day, (v) => v.toFixed(1), 'min'],
  ];
  const rows = DETECTORS.map(([k]) => D.metrics.detectors[k]);
  const best = cols.map(([, get, , dir]) => (dir === 'max' ? Math.max : Math.min)(...rows.map(get)));
  $('#metrics').innerHTML = `<thead><tr><th>Detector</th>${cols.map(([c]) => `<th class="num">${c}</th>`).join('')}</tr></thead><tbody>${
    DETECTORS.map(([k, name], i) => `<tr class="${k === 'Hybrid' ? 'served' : ''}"><td>${name}</td>${
      cols.map(([, get, f], j) => `<td class="num"><span class="${get(rows[i]) === best[j] ? 'best' : ''}">${f(get(rows[i]), rows[i])}</span></td>`).join('')}</tr>`).join('')
  }</tbody>`;

  const rba = D.metrics.recall_by_attack;
  $('#recall-table').innerHTML = `<thead><tr><th>Attack type</th>${DETECTORS.map(([, n]) => `<th class="num">${n}</th>`).join('')}</tr></thead><tbody>${
    Object.entries(rba).map(([a, byDet]) => `<tr><td>${ATTACKS[a] || a}</td>${DETECTORS.map(([k]) => {
      const r = byDet[k];
      return `<td class="num">${fmt(r.event_recall)} (${r.incidents_detected}/${r.incidents})</td>`;
    }).join('')}</tr>`).join('')}</tbody>`;
  $('#det-legend').innerHTML = DETECTORS.map(([, n], i) => `<span><i class="sw" style="background:var(--series-${i + 1})"></i>${n}</span>`).join('');
}

function barPath(x, y, w, h, r) {
  r = Math.min(r, h, w / 2);
  return `M${x},${y + h}V${y + r}Q${x},${y} ${x + r},${y}H${x + w - r}Q${x + w},${y} ${x + w},${y + r}V${y + h}Z`;
}

function drawRecall() {
  const el = $('#recall-chart');
  const W = Math.max(300, el.clientWidth - 32);
  const H = 260;
  const m = { l: 30, r: 6, t: 8, b: 40 };
  const rba = Object.entries(D.metrics.recall_by_attack);
  const band = (W - m.l - m.r) / rba.length;
  const inner = band * 0.78;
  const gap = 2;
  const bw = (inner - gap * (DETECTORS.length - 1)) / DETECTORS.length;
  const y = (v) => m.t + (1 - v) * (H - m.t - m.b);
  let s = `${svgEl(W, H)}<g class="grid">`;
  for (let v = 0; v <= 1.0001; v += 0.25) s += `<line x1="${m.l}" x2="${W - m.r}" y1="${y(v)}" y2="${y(v)}"/><text x="${m.l - 6}" y="${y(v) + 4}" text-anchor="end">${v.toFixed(2).replace(/0$/, '')}</text>`;
  s += '</g>';
  const marks = [];
  rba.forEach(([attack, byDet], gi) => {
    const gx = m.l + gi * band + (band - inner) / 2;
    DETECTORS.forEach(([k, name], di) => {
      const r = byDet[k];
      const bx = gx + di * (bw + gap);
      const h = y(0) - y(r.event_recall);
      marks.push({ x: bx, w: bw, attack, name, r });
      s += h > 0
        ? `<path d="${barPath(bx, y(r.event_recall), bw, h, 4)}" style="fill:var(--series-${di + 1})"/>`
        : `<text x="${bx + bw / 2}" y="${y(0) - 4}" text-anchor="middle">0</text>`;
    });
    const words = (ATTACKS[attack] || attack).split(' ');
    s += `<text x="${gx + inner / 2}" y="${H - m.b + 16}" text-anchor="middle">${words.map((w, i) => `<tspan x="${gx + inner / 2}" dy="${i ? 13 : 0}">${esc(w)}</tspan>`).join('')}</text>`;
  });
  el.innerHTML = `${s}</svg>`;
  const svg = el.querySelector('svg');
  svg.addEventListener('mousemove', (ev) => {
    const rect = svg.getBoundingClientRect();
    const px = ((ev.clientX - rect.left) * W) / rect.width;
    const hit = marks.find((mk) => px >= mk.x - gap / 2 && px <= mk.x + mk.w + gap / 2);
    if (!hit) return hideTip();
    showTip(`<b>${hit.name}</b> · ${ATTACKS[hit.attack]}<br>event recall <b>${fmt(hit.r.event_recall)}</b><br>incidents detected <b>${hit.r.incidents_detected}/${hit.r.incidents}</b>`, ev);
  });
  svg.addEventListener('mouseleave', hideTip);
}

// ---------- boot ----------
async function init() {
  try {
    D = await (await fetch('data/demo.json')).json();
  } catch (err) {
    $('#replay .sub').textContent = 'Could not load data/demo.json. Run `make site` to generate it.';
    throw err;
  }
  events = D.events.map((e, i) => ({ ...e, i, ms: Date.parse(`${e.t}Z`) }));
  compromised = new Set(events.filter((e) => e.step).map((e) => e.user));
  const attackMs = events.filter((e) => e.step).map((e) => e.ms);
  attackSpan = [Math.min(...attackMs), Math.max(...attackMs)];
  t0 = events[0].ms - 60e3;
  t1 = events[events.length - 1].ms + 60e3;
  renderStats();
  renderSevLegend();
  renderMetrics();
  drawRecall();
  restart();
  $('#play').addEventListener('click', () => (timer ? stop() : play()));
  $('#restart').addEventListener('click', restart);
  $('#skip').addEventListener('click', skip);
  window.addEventListener('resize', debounce(() => { drawTimeline(); drawRecall(); }, 150));
}
init();
