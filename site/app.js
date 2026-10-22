/* tickcheck landing: a specimen drawer drawn from `tickcheck --demo --json`. */
(() => {
  const NS = 'http://www.w3.org/2000/svg';
  const reduce = matchMedia('(prefers-reduced-motion: reduce)').matches;
  const svg = document.getElementById('drawer');
  const slip = document.getElementById('sliptext');
  const replayBtn = document.getElementById('replay');
  const COL = { BAD: '#ff5f1f', SUSPECT: '#d8a31a', REVIEW: '#8592a8', OK: '#4f9d84', NONE: '#7d6f66' };
  const SHORT = {
    'setuptools distutils shim': 'setuptools shim', 'virtualenv / uv venv patch': 'venv patch',
    'editable install (PEP 660)': 'editable install', 'namespace package (-nspkg)': 'namespace pkg',
    'pywin32 bootstrap': 'pywin32', 'coverage subprocess measurement': 'coverage',
    'Debian/Ubuntu apport hook': 'Debian apport', 'Homebrew site path': 'Homebrew',
  };
  const el = (n, a = {}, kids = []) => {
    const e = document.createElementNS(NS, n);
    for (const k in a) e.setAttribute(k, a[k]);
    for (const c of [].concat(kids)) if (c) e.append(c);
    return e;
  };
  const txt = (s, a) => { const t = el('text', a); t.textContent = s; return t; };
  const mid = (s, n) => s.length <= n ? s : s.slice(0, Math.ceil(n / 2) - 1) + '…' + s.slice(s.length - Math.floor(n / 2));
  // paths: keep the head (~/) and as many trailing segments as fit
  const tailPath = (p, n) => {
    if (p.length <= n) return p;
    const parts = p.split('/'); const head = parts[0] === '~' ? '~/…/' : '…/';
    let out = parts.pop();
    while (parts.length && (head + parts[parts.length - 1] + '/' + out).length <= n) out = parts.pop() + '/' + out;
    return head + out;
  };
  // file names: keep the start and the extension-ish end
  const nameFit = (s, n) => {
    if (s.length <= n) return s;
    const m = s.match(/(-nspkg\.pth|\.pth|\.py)$/); const end = m ? m[1] : '';
    return s.slice(0, n - end.length - 1) + '…' + end;
  };
  let seed = 1;
  const rnd = () => (seed = (seed * 16807) % 2147483647) / 2147483647;
  const hash = s => { let h = 7; for (const c of s) h = (h * 31 + c.charCodeAt(0)) % 2147483647; return h || 1; };

  // A tick, dorsal view, in a 512 box centred on (256, 300). Scientific line style.
  function tick(name, verdict) {
    seed = hash(name);
    const eng = verdict === 'BAD' || verdict === 'SUSPECT';
    const g = el('g', { class: 'tick' });
    const legs = [[[206, 236], [162, 206], [134, 150], [120, 100]], [[200, 262], [144, 250], [100, 206], [78, 174]],
      [[200, 300], [142, 312], [98, 356], [82, 396]], [[208, 330], [164, 366], [142, 424], [140, 466]]];
    const lg = el('g', { stroke: '#1e1a17', 'stroke-linecap': 'round', fill: 'none' });
    const ws = [9, 7.5, 6];
    for (const side of [1, -1]) for (const L of legs) {
      const j = (rnd() - .5) * 14;
      const pts = L.map(([x, y], i) => [side === 1 ? x : 512 - x, y + (i ? j * i / 3 : 0)]);
      for (let i = 0; i < 3; i++) lg.append(el('line', { x1: pts[i][0], y1: pts[i][1], x2: pts[i + 1][0], y2: pts[i + 1][1], 'stroke-width': ws[i] }));
    }
    g.append(lg);
    g.append(el('path', { d: 'M241 194 L240 164 Q241 150 248 147 L250 194 Z M271 194 L272 164 Q271 150 264 147 L262 194 Z', fill: '#1e1a17' }));
    g.append(el('rect', { x: 230, y: 186, width: 52, height: 20, rx: 5, fill: '#1e1a17' }));
    const w = eng ? 104 : 86, h = eng ? 126 : 108, cy = eng ? 322 : 312;
    g.append(el('ellipse', { cx: 256, cy, rx: w, ry: h, fill: eng ? '#8a6a60' : '#9b5b3e', stroke: '#1e1a17', 'stroke-width': 7 }));
    const dots = el('g', { fill: '#1e1a17', opacity: .45 });
    for (let i = 0; i < 28; i++) {
      const a = rnd() * 6.283, r = .35 + rnd() * .55;
      const x = 256 + Math.cos(a) * r * w, y = cy + Math.sin(a) * r * h;
      if (y < cy - 20 && Math.abs(x - 256) < 44) continue;
      dots.append(el('circle', { cx: x.toFixed(1), cy: y.toFixed(1), r: (1.6 + rnd() * 1.4).toFixed(1) }));
    }
    g.append(dots);
    g.append(el('path', { d: 'M256 206 C292 206 310 236 306 270 C302 300 282 316 256 318 C230 316 210 300 206 270 C202 236 220 206 256 206 Z', fill: '#1e1a17' }));
    return g;
  }

  function pin(verdict) {
    const g = el('g', { class: 'pin' });
    g.append(el('line', { x1: 256, y1: 120, x2: 256, y2: 262, stroke: '#23302a', 'stroke-width': 7, 'stroke-linecap': 'round' }));
    g.append(el('circle', { cx: 256, cy: 262, r: 7, fill: '#c9b27c', stroke: '#23302a', 'stroke-width': 2 }));
    const head = el('circle', { cx: 256, cy: 112, r: 34, fill: COL[verdict] || COL.NONE, stroke: '#1e1a17', 'stroke-width': 6, class: 'head' });
    g.append(head);
    g.append(el('path', { d: 'M240 100 Q248 90 260 90', fill: 'none', stroke: '#fff', 'stroke-width': 7, 'stroke-linecap': 'round', opacity: .8 }));
    return g;
  }

  function det(h) {
    if (h.verdict === 'OK') return SHORT[h.known] || h.known || h.owner || 'known';
    if (h.owner) return h.owner;
    return 'no RECORD';
  }

  let specs = [], vial = null, lens = null, lensPos = { x: 600, y: 360 }, lensTarget = { x: 600, y: 360 }, follow = false, running = false, pulled = 0;
  let VB = { w: 1200, h: 720 };

  function build(data) {
    while (svg.lastChild && svg.lastChild.tagName !== 'title') svg.lastChild.remove();
    specs = []; pulled = 0;
    const narrow = innerWidth < 760;
    const cols = narrow ? 2 : 4;
    const envs = data.envs.slice(0, cols * 2 - 1 + (narrow ? 2 : 0));
    const more = data.envs.length - envs.length;
    const rows = Math.ceil((envs.length + 1) / cols);
    const pad = 22, gap = 16, cw = narrow ? 300 : 282, ch = 320;
    VB = { w: pad * 2 + cols * cw + (cols - 1) * gap, h: pad * 2 + rows * ch + (rows - 1) * gap };
    svg.setAttribute('viewBox', `0 0 ${VB.w} ${VB.h}`);
    const defs = el('defs');
    const pat = el('pattern', { id: 'foam', width: 46, height: 46, patternUnits: 'userSpaceOnUse' });
    pat.append(el('rect', { width: 46, height: 46, fill: '#e2e8dc' }));
    seed = 99;
    for (let i = 0; i < 9; i++) pat.append(el('circle', { cx: (rnd() * 46).toFixed(1), cy: (rnd() * 46).toFixed(1), r: (0.7 + rnd() * 1.3).toFixed(1), fill: '#cdd6c6' }));
    defs.append(pat);
    const clip = el('clipPath', { id: 'lensclip' }, el('circle', { id: 'lensc', cx: 600, cy: 360, r: narrow ? 120 : 104 }));
    defs.append(clip);
    svg.append(defs);
    const scene = el('g', { id: 'scene' });
    scene.append(el('rect', { width: VB.w, height: VB.h, fill: '#23302a' }));
    envs.forEach((e, i) => {
      const x = pad + (i % cols) * (cw + gap), y = pad + Math.floor(i / cols) * (ch + gap);
      const tray = el('g', { transform: `translate(${x} ${y})` });
      tray.append(el('rect', { width: cw, height: ch, fill: 'url(#foam)' }));
      tray.append(el('rect', { x: 8, y: 8, width: cw - 16, height: 46, fill: '#f1f4ee', stroke: '#b9c3b2' }));
      tray.append(txt(tailPath(e.root, 34), { x: 16, y: 28, 'font-family': 'Xanh Mono', 'font-size': 13.5, fill: '#1e1a17' }));
      tray.append(txt(`${e.kind}${e.python ? ' · py' + e.python : ''}`, { x: 16, y: 46, 'font-family': 'Xanh Mono', 'font-style': 'italic', 'font-size': 12.5, fill: '#5a4f47' }));
      const hs = e.hooks.slice(0, 4);
      if (!hs.length) {
        tray.append(txt('no specimens', { x: cw / 2, y: ch / 2 + 20, 'text-anchor': 'middle', 'font-family': 'Young Serif', 'font-size': 20, fill: '#7d8a76' }));
        tray.append(txt('no startup hooks in this env', { x: cw / 2, y: ch / 2 + 44, 'text-anchor': 'middle', 'font-family': 'Xanh Mono', 'font-size': 12.5, fill: '#7d8a76' }));
      }
      const slots = hs.length === 1 ? [[cw / 2, 190, .34]] : hs.length === 2 ? [[cw * .28, 190, .26], [cw * .72, 190, .26]] :
        [[cw * .27, 130, .19], [cw * .73, 130, .19], [cw * .27, 250, .19], [cw * .73, 250, .19]];
      hs.forEach((h, k) => {
        const [sx, sy, sc] = slots[k];
        const g = el('g', { class: 'spec', tabindex: -1, transform: `translate(${sx} ${sy})` });
        const body = el('g', { transform: `scale(${sc}) translate(-256 -300)` });
        const t = tick(h.name, h.verdict);
        body.append(t);
        const p = pin(h.verdict);
        body.append(p);
        g.append(body);
        const lblY = (hs.length > 2 ? 48 : 74);
        const nm = txt(nameFit(h.name, hs.length === 1 ? 30 : hs.length === 2 ? 17 : 16), { x: 0, y: lblY, 'text-anchor': 'middle', 'font-family': 'Xanh Mono', 'font-size': hs.length > 2 ? 12.5 : 13.5, fill: '#1e1a17' });
        const dt = txt('', { x: 0, y: lblY + 16, 'text-anchor': 'middle', 'font-family': 'Albert Sans', 'font-weight': 600, 'font-size': hs.length > 1 ? 11 : 12.5, fill: COL[h.verdict] === COL.OK ? '#2f6b59' : '#1e1a17' });
        g.append(nm, dt);
        tray.append(g);
        const head = p.querySelector('.head');
        head.setAttribute('fill', COL.NONE);
        specs.push({ h, env: e, g, body, tickEl: t, head, dt, x: x + sx, y: y + sy, sc, done: false });
      });
      scene.append(tray);
    });
    // the vial cell
    {
      const i = envs.length, x = pad + (i % cols) * (cw + gap), y = pad + Math.floor(i / cols) * (ch + gap);
      const g = el('g', { transform: `translate(${x} ${y})` });
      g.append(el('rect', { width: cw, height: ch, fill: '#2f3d36' }));
      const vx = cw / 2 - 38;
      g.append(el('rect', { x: vx, y: 70, width: 76, height: 190, rx: 30, fill: '#d8e6ee', opacity: .28, stroke: '#e2e8dc', 'stroke-width': 3 }));
      const liq = el('rect', { x: vx + 4, y: 140, width: 68, height: 116, rx: 26, fill: '#b7d4e8', opacity: .85 });
      g.append(liq);
      const rip = el('ellipse', { cx: cw / 2, cy: 142, rx: 0, ry: 0, fill: 'none', stroke: '#ffffff', 'stroke-width': 2, opacity: 0 });
      g.append(rip);
      g.append(el('rect', { x: vx + 6, y: 52, width: 64, height: 26, rx: 4, fill: '#9b5b3e', stroke: '#1e1a17', 'stroke-width': 2 }));
      const inside = el('g', {});
      g.append(inside);
      g.append(txt('~/.tickcheck/quarantine/', { x: cw / 2, y: 286, 'text-anchor': 'middle', 'font-family': 'Xanh Mono', 'font-size': 13.5, fill: '#e2e8dc' }));
      const cnt = txt(more > 0 ? `+${more} more envs not shown` : 'tickcheck pull', { x: cw / 2, y: 305, 'text-anchor': 'middle', 'font-family': 'Xanh Mono', 'font-style': 'italic', 'font-size': 12.5, fill: '#b9c3b2' });
      g.append(cnt);
      scene.append(g);
      vial = { x: x + cw / 2, y: y + 160, g, inside, rip, cnt, ox: x, oy: y, cw };
    }
    // tweezers (hidden until needed)
    const tw = el('g', { id: 'tweezers', opacity: 0 });
    tw.append(el('path', { d: 'M-6 -230 L-2 -8 L2 -8 L-1 -230 Z', fill: '#c4ccce', stroke: '#1e1a17', 'stroke-width': 1.5, class: 'tl' }));
    tw.append(el('path', { d: 'M6 -230 L2 -8 L-2 -8 L1 -230 Z', fill: '#aab3b5', stroke: '#1e1a17', 'stroke-width': 1.5, class: 'tr' }));
    tw.append(el('rect', { x: -9, y: -250, width: 18, height: 24, rx: 3, fill: '#7d8a8d', stroke: '#1e1a17', 'stroke-width': 1.5 }));
    scene.append(tw);
    svg.append(scene);
    // the hand lens: a magnified copy of the scene
    lens = el('g', { id: 'lens', 'pointer-events': 'none' });
    const mag = el('g', { 'clip-path': 'url(#lensclip)' });
    const use = el('use', { href: '#scene' });
    mag.append(el('circle', { id: 'lensbg', cx: 600, cy: 360, r: 130, fill: '#23302a' }), use);
    const rim = el('g', {});
    const r = narrow ? 120 : 104;
    rim.append(el('line', { class: 'handle', x1: 0, y1: 0, x2: 0, y2: 0, stroke: '#23302a', 'stroke-width': 26, 'stroke-linecap': 'round' }));
    rim.append(el('circle', { class: 'rim', r: r + 7, fill: 'none', stroke: '#c9b27c', 'stroke-width': 12 }));
    rim.append(el('circle', { class: 'rim2', r: r + 1, fill: 'none', stroke: '#8e7a4c', 'stroke-width': 2 }));
    rim.append(el('path', { class: 'glint', d: `M ${-r * .62} ${-r * .42} A ${r * .76} ${r * .76} 0 0 1 ${-r * .1} ${-r * .74}`, fill: 'none', stroke: '#fff', 'stroke-width': 5, 'stroke-linecap': 'round', opacity: .45 }));
    lens.append(mag, rim);
    svg.append(lens);
    lens._use = use; lens._rim = rim; lens._r = r; lens._zoom = narrow ? 1.9 : 2.2;
    placeLens(lensPos.x, lensPos.y);
  }

  function placeLens(x, y) {
    if (!lens) return;
    const z = lens._zoom, r = lens._r;
    document.getElementById('lensc').setAttribute('cx', x);
    document.getElementById('lensc').setAttribute('cy', y);
    const bg = document.getElementById('lensbg');
    bg.setAttribute('cx', x); bg.setAttribute('cy', y);
    lens._use.setAttribute('transform', `translate(${x} ${y}) scale(${z}) translate(${-x} ${-y})`);
    lens._rim.setAttribute('transform', `translate(${x} ${y})`);
    const hd = lens._rim.querySelector('.handle');
    hd.setAttribute('x1', (r + 10) * .7); hd.setAttribute('y1', (r + 10) * .7);
    hd.setAttribute('x2', (r + 120) * .7); hd.setAttribute('y2', (r + 120) * .7);
  }

  // lens motion: ease toward target every frame
  function loop() {
    lensPos.x += (lensTarget.x - lensPos.x) * .16;
    lensPos.y += (lensTarget.y - lensPos.y) * .16;
    placeLens(lensPos.x, lensPos.y);
    requestAnimationFrame(loop);
  }

  const sleep = ms => new Promise(r => setTimeout(r, ms));
  let token = 0;

  function reveal(s, instant) {
    s.done = true;
    s.head.setAttribute('fill', COL[s.h.verdict]);
    const words = (s.h.verdict + ' · ' + det(s.h)).split(' ');
    if (instant || reduce) { s.dt.textContent = fitDet(words.join(' '), s); return; }
    let i = 0;
    const step = () => { i++; s.dt.textContent = fitDet(words.slice(0, i).join(' '), s); if (i < words.length) setTimeout(step, 60); };
    step();
    if (s.h.verdict === 'BAD') s.head.animate([{ transform: 'translateY(0)' }, { transform: 'translateY(-18px)' }, { transform: 'translateY(0)' }], { duration: 380, iterations: 2 });
  }

  function fitDet(t, s) { const n = s.sc > .3 ? 34 : s.sc > .2 ? 19 : 20; return t.length <= n ? t : t.slice(0, n - 1) + '…'; }

  function say(s) {
    const h = s.h;
    const why = (h.reasons && h.reasons[0]) || '';
    slip.innerHTML = '';
    const v = document.createElement('span'); v.className = 'v v-' + h.verdict; v.textContent = h.verdict;
    const t = document.createElement('span');
    t.textContent = `${s.env.root} · ${h.name}${why ? ' · ' + why : ''}`;
    slip.append(v, ' ', t);
  }

  async function pull(s, my) {
    const tw = document.getElementById('tweezers');
    tw.setAttribute('opacity', 1);
    const tl = tw.querySelector('.tl'), tr = tw.querySelector('.tr');
    const at = (x, y) => tw.setAttribute('transform', `translate(${x} ${y})`);
    const top = s.y - 260;
    const anim = (from, to, ms, fn) => new Promise(res => {
      const t0 = performance.now();
      const f = now => {
        if (my !== token) return res();
        const k = Math.min(1, (now - t0) / ms), e = k < .5 ? 2 * k * k : 1 - Math.pow(-2 * k + 2, 2) / 2;
        fn(from + (to - from) * e);
        k < 1 ? requestAnimationFrame(f) : res();
      };
      requestAnimationFrame(f);
    });
    await anim(top, s.y - 8, 520, y => at(s.x, y));
    tl.setAttribute('transform', 'rotate(-2.5 0 -230)'); tr.setAttribute('transform', 'rotate(2.5 0 -230)');
    await sleep(160);
    // straight up: no twisting, no squeezing
    const lift = 150;
    await anim(0, lift, 520, d => { at(s.x, s.y - 8 - d); s.body.setAttribute('transform', `translate(0 ${-d}) scale(${s.sc}) translate(-256 -300)`); });
    s.g.querySelector('text').setAttribute('opacity', .45);
    const hole = el('circle', { cx: 0, cy: 0, r: 3, fill: '#1e1a17' });
    s.g.insertBefore(hole, s.g.firstChild);
    s.dt.textContent = 'pulled · in the vial';
    s.dt.setAttribute('fill', '#5a4f47');
    // carry to the vial
    const sx = s.x, sy = s.y - 8 - lift, vx = vial.x, vy = vial.y - 120;
    lensTarget = { x: vx, y: vial.y - 20 };
    await anim(0, 1, 760, k => {
      const x = sx + (vx - sx) * k, y = sy + (vy - sy) * k - Math.sin(k * Math.PI) * 60;
      at(x, y);
      s.body.setAttribute('transform', `translate(${x - s.x} ${y - s.y + 8}) scale(${s.sc}) translate(-256 -300)`);
    });
    tl.removeAttribute('transform'); tr.removeAttribute('transform');
    // drop
    const relY = vial.y - vial.oy;
    const clone = s.body.cloneNode(true);
    s.body.setAttribute('opacity', 0);
    clone.setAttribute('transform', `translate(${vial.cw / 2 + (pulled % 2 ? 12 : -12)} ${relY - 110}) scale(.085) translate(-256 -300)`);
    vial.inside.append(clone);
    await anim(0, 1, 420, k => { clone.setAttribute('transform', `translate(${vial.cw / 2 + (pulled % 2 ? 12 : -12)} ${relY - 110 + k * (150 - pulled * 26)}) scale(.085) translate(-256 -300)`); at(vx, vy - k * 90); });
    pulled++;
    vial.rip.setAttribute('opacity', .9);
    await anim(0, 1, 600, k => { vial.rip.setAttribute('rx', 8 + k * 26); vial.rip.setAttribute('ry', 2 + k * 5); vial.rip.setAttribute('opacity', .9 * (1 - k)); });
    vial.cnt.textContent = `${pulled} pulled · tickcheck restore puts back`;
    tw.setAttribute('opacity', 0);
  }

  function finalState() {
    specs.forEach(s => reveal(s, true));
    specs.filter(s => s.h.verdict === 'BAD').forEach((s, i) => {
      s.body.setAttribute('opacity', 0);
      const relY = vial.y - vial.oy;
      const c = s.body.cloneNode(true);
      c.setAttribute('opacity', 1);
      c.setAttribute('transform', `translate(${vial.cw / 2 + (i % 2 ? 12 : -12)} ${relY + 40 - i * 26}) scale(.085) translate(-256 -300)`);
      vial.inside.append(c);
      s.dt.textContent = 'pulled · in the vial';
      pulled++;
    });
    if (pulled) vial.cnt.textContent = `${pulled} pulled · tickcheck restore puts back`;
    // rest the lens over the vial so it frames the result instead of a tray seam
    lensTarget = { x: vial.x, y: vial.y - 20 };
    lensPos = { ...lensTarget }; placeLens(lensPos.x, lensPos.y);
    const bad = specs.find(s => s.h.verdict === 'BAD');
    if (bad) say(bad);
  }

  async function census() {
    const my = ++token;
    running = true; follow = false;
    replayBtn.classList.remove('on');
    if (reduce) { finalState(); running = false; replayBtn.classList.add('on'); return; }
    await sleep(500);
    for (const s of specs) {
      if (my !== token) return;
      lensTarget = { x: s.x, y: s.y };
      await sleep(s.h.verdict === 'OK' ? 330 : 460);
      reveal(s); say(s);
      await sleep(s.h.verdict === 'BAD' ? 900 : s.h.verdict === 'OK' ? 220 : 650);
    }
    const bad = specs.filter(s => s.h.verdict === 'BAD');
    if (bad.length) {
      slip.innerHTML = '';
      const v = document.createElement('span'); v.className = 'v v-BAD'; v.textContent = 'pull';
      slip.append(v, ' ', `$ tickcheck pull  ·  ${bad.length} BAD hook${bad.length > 1 ? 's' : ''} lifted straight out, Python never started`);
      for (const s of bad) { if (my !== token) return; lensTarget = { x: s.x, y: s.y - 60 }; await pull(s, my); }
    }
    running = false; follow = true;
    replayBtn.classList.add('on');
  }

  // pointer: the lens follows once you move it
  const toSvg = ev => {
    const pt = svg.createSVGPoint(); pt.x = ev.clientX; pt.y = ev.clientY;
    return pt.matrixTransform(svg.getScreenCTM().inverse());
  };
  svg.addEventListener('pointermove', ev => {
    if (ev.pointerType === 'touch') return;
    const p = toSvg(ev); lensTarget = { x: p.x, y: p.y };
    if (running) { token++; running = false; finalState(); replayBtn.classList.add('on'); }
    follow = true;
    const near = specs.reduce((b, s) => { const d = Math.hypot(s.x - p.x, s.y - p.y); return d < b.d ? { d, s } : b; }, { d: 90, s: null });
    if (near.s) say(near.s);
  });
  svg.addEventListener('click', ev => {
    const p = toSvg(ev); lensTarget = { x: p.x, y: p.y };
    if (running) { token++; running = false; finalState(); replayBtn.classList.add('on'); }
    const near = specs.reduce((b, s) => { const d = Math.hypot(s.x - p.x, s.y - p.y); return d < b.d ? { d, s } : b; }, { d: 120, s: null });
    if (near.s) say(near.s);
  });
  let kbd = -1;
  svg.addEventListener('keydown', ev => {
    if (!['ArrowRight', 'ArrowLeft', 'ArrowDown', 'ArrowUp'].includes(ev.key) || !specs.length) return;
    ev.preventDefault();
    if (running) { token++; running = false; finalState(); replayBtn.classList.add('on'); }
    kbd = (kbd + (ev.key === 'ArrowRight' || ev.key === 'ArrowDown' ? 1 : specs.length - 1)) % specs.length;
    const s = specs[kbd]; lensTarget = { x: s.x, y: s.y }; say(s);
  });
  replayBtn.addEventListener('click', () => { build(current); census(); });

  let current = null;
  fetch('demo.json').then(r => r.json()).then(d => {
    current = d; build(d); requestAnimationFrame(loop);
    const io = new IntersectionObserver(es => { if (es[0].isIntersecting) { io.disconnect(); census(); } }, { threshold: .3 });
    io.observe(svg);
  });
  let lastNarrow = innerWidth < 760;
  addEventListener('resize', () => { const n = innerWidth < 760; if (n !== lastNarrow && current) { lastNarrow = n; token++; build(current); finalState(); } });

  // copy buttons
  document.querySelectorAll('[data-copy]').forEach(b => b.addEventListener('click', async () => {
    const t = document.getElementById(b.dataset.copy).textContent;
    try { await navigator.clipboard.writeText(t); b.textContent = 'Copied'; } catch { b.textContent = 'Select + copy'; }
    setTimeout(() => (b.textContent = 'Copy'), 1600);
  }));

  // §1 race: light the two lanes when scrolled in
  const race = document.getElementById('race');
  if (race) {
    const lanes = [...race.querySelectorAll('.lane')];
    const run = () => lanes.forEach((l, li) => [...l.querySelectorAll('li')].forEach((x, i) => setTimeout(() => x.classList.add('lit'), reduce ? 0 : 300 + i * (li ? 260 : 520))));
    new IntersectionObserver((es, o) => { if (es[0].isIntersecting) { o.disconnect(); run(); } }, { threshold: .5 }).observe(race);
  }

  // §2 key: light a route
  const couplets = [...document.querySelectorAll('#couplets li')];
  const route = async (ids, my) => {
    couplets.forEach(c => c.classList.remove('on'));
    for (const id of ids) {
      if (my !== routeTok) return;
      couplets.find(c => c.dataset.c === id)?.classList.add('on');
      if (!reduce) await sleep(240);
    }
  };
  let routeTok = 0;
  document.querySelectorAll('[data-route]').forEach(b => b.addEventListener('click', () => {
    document.querySelectorAll('[data-route]').forEach(x => x.setAttribute('aria-pressed', x === b));
    route(b.dataset.route.split(' '), ++routeTok);
  }));
  const keyEl = document.getElementById('couplets');
  if (keyEl) new IntersectionObserver((es, o) => { if (es[0].isIntersecting) { o.disconnect(); route('1b 2a'.split(' '), ++routeTok); } }, { threshold: .4 }).observe(keyEl);

  // §6 drop your own drawer.json
  const drop = document.getElementById('drop'), file = document.getElementById('file'), err = document.getElementById('droperr');
  const load = async f => {
    err.textContent = '';
    try {
      const r = JSON.parse(await f.text());
      if (!Array.isArray(r.envs)) throw new Error('no "envs" array: is this `tickcheck --json` output?');
      const home = r.home || '';
      const t = p => home && p.startsWith(home) ? '~' + p.slice(home.length) : p;
      const envs = r.envs.map(e => ({ root: t(e.root), kind: e.kind, python: e.python || '', verdict: e.verdict,
        hooks: (e.hooks || []).map(h => ({ name: h.file.path.split(/[\\/]/).pop(), verdict: h.verdict, owner: h.file.owner ? `${h.file.owner.name} ${h.file.owner.version}` : '', reasons: h.reasons || [], known: h.known_as || '' })) }));
      if (!envs.length) throw new Error('that report has no Python environments in it');
      current = { envs }; build(current);
      document.querySelector('.cabinet').scrollIntoView({ behavior: reduce ? 'auto' : 'smooth' });
      setTimeout(census, reduce ? 0 : 600);
      slip.textContent = `Your drawer: ${envs.length} environments. Drawn in this tab only.`;
    } catch (e) { err.textContent = "Couldn't read that file: " + e.message; }
  };
  drop.addEventListener('click', () => file.click());
  drop.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); file.click(); } });
  file.addEventListener('change', () => file.files[0] && load(file.files[0]));
  drop.addEventListener('dragover', e => { e.preventDefault(); drop.classList.add('over'); });
  drop.addEventListener('dragleave', () => drop.classList.remove('over'));
  drop.addEventListener('drop', e => { e.preventDefault(); drop.classList.remove('over'); e.dataTransfer.files[0] && load(e.dataTransfer.files[0]); });
})();
