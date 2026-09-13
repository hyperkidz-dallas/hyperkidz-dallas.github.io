/* Hyper Kidz Dallas staff dashboard.
 *
 * data.json is written by publish_dashboard.py and is public, so it is encrypted: the dashboard
 * document is gzip-compressed and sealed with AES-256-GCM under a random data key, and that key is
 * wrapped once per account under a key derived from the account password (PBKDF2-HMAC-SHA256). This
 * script derives the same key from the password typed at sign-in, unwraps the data key and decrypts,
 * all inside the browser. The derived key (never the password) is kept for the tab, or on the device
 * when "Keep me signed in" is ticked, so a reload does not ask again.
 *
 * Views are tabs over one selected day (date picker, arrows, #tab=...&date=... in the address), built
 * from the document described in src/dashboard_data.py.
 *
 * Contract with Python: ACCOUNT_ID_PREFIX and SUPPORTED_ENVELOPE match src/dashboard.py, SUPPORTED_SCHEMA
 * matches src/dashboard_data.py DATA_SCHEMA_VERSION (pinned by tests/test_publish_dashboard.py).
 */
'use strict';

(() => {
  const DATA_URL = 'data.json';
  const ACCOUNT_ID_PREFIX = 'hyperkidz-dashboard:';
  const SUPPORTED_ENVELOPE = 1;
  const SUPPORTED_SCHEMA = 2;
  const SESSION_KEY = 'hyperkidz-dashboard-session';
  const STALE_AFTER_MINUTES = 90;
  const HOUR_WIDTH = 72;
  const PIT_HEIGHT = 196;
  const PIT_FLOOR = 136;
  const PIT_MIN_WIDTH_PER_HOUR = 58;
  const BALL_MAX_RADIUS = 32;
  const BALL_MIN_RADIUS = 5;
  const DROP_STAGGER_MS = 45;
  const ATTENTION_PREVIEW = 6;
  const ACCURACY_ROWS = 14;
  const BIAS_WORTH_MENTIONING = 5;
  const BIG_MISS_PCT = 25;
  const CALENDAR_DAYS = 7;
  const TINT_RGB = '240, 78, 152';
  const SKY_RGB = '41, 171, 226';
  const TIMELINE_PAST_DAYS = 14;
  const BAR_WIDTH = 46;
  const CHART_HEIGHT = 222;
  const CHART_TOP = 32;
  const CHART_FLOOR = 178;
  const WEEKDAY_NAMES = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
  const DASH = '–';
  const MINUS = '−';

  const TABS = [
    { id: 'overview', label: 'Overview' },
    { id: 'guests', label: 'Walk-ins' },
    { id: 'revenue', label: 'Revenue' },
    { id: 'staff', label: 'Staff' },
    { id: 'calendar', label: 'Calendar' },
    { id: 'forecasts', label: 'Forecasts' },
    { id: 'analysis', label: 'AI analysis' },
    { id: 'updates', label: 'Updates' },
  ];
  const MODE_NAMES = { morning: 'Morning report', midday: 'Mid-day check-in', eod: 'End of day' };
  const STATUS = {
    ok: { cls: 'ok', label: 'Within budget' },
    over: { cls: 'over', label: 'Over budget' },
  };
  const SEVERITY = {
    high: { rank: 0, label: 'Urgent' },
    medium: { rank: 1, label: 'Check' },
    low: { rank: 2, label: 'Note' },
  };
  const STAFF_STATUS = {
    on_clock: 'On the clock',
    worked: 'Worked',
    late: 'Late',
    no_show: 'No-show',
    scheduled: 'Scheduled',
    unscheduled: 'Not scheduled',
    open_shift: 'Open shift',
  };
  const SCHEDULE_STATUS = {
    ok: { cls: 'done', label: 'Ran, analysis written' },
    no_analysis: { cls: 'no_analysis', label: 'Ran, no analysis written' },
    missed: { cls: 'missed', label: 'Did not run' },
    pending: { cls: 'pending', label: 'Not due yet' },
  };
  const UPDATE_KINDS = {
    refresh: 'Dashboard refresh',
    publish: 'Dashboard update after a report',
    report: 'Report run',
  };
  const CATEGORY_LABELS = {
    admission: 'Admission',
    party: 'Parties',
    stock: 'Total stock',
    membership: 'Memberships',
    other: 'Fees and other',
  };
  /** Guest groups in display order; keys are src.config.GuestGroup values. */
  const GUEST_GROUPS = [
    { key: 'children', label: 'Children 3-13', cls: 'grp-children' },
    { key: 'toddlers', label: 'Toddlers 1-2', cls: 'grp-toddlers' },
    { key: 'infants', label: 'Infants under 1', cls: 'grp-infants' },
    { key: 'other_passes', label: 'Other kid passes', cls: 'grp-other' },
    { key: 'party_guests', label: 'Party kids', cls: 'grp-party' },
    { key: 'adults', label: 'Adults', cls: 'grp-adults' },
  ];

  const encoder = new TextEncoder();
  const $ = (selector, root = document) => root.querySelector(selector);
  const state = { data: null, focus: null, tab: 'overview', showAllAttention: false, metric: 'net_revenue' };
  let tipSerial = 0;

  /** Thrown when the username/password pair cannot unwrap the data key. */
  class LoginError extends Error {}

  // ------------------------------------------------------------------ session storage (best effort)

  function storages() {
    const found = [];
    for (const get of [() => window.sessionStorage, () => window.localStorage]) {
      try {
        const storage = get();
        if (storage) found.push(storage);
      } catch (_) {
        // Storage can be blocked (private mode, site settings); signing in still works for this page.
      }
    }
    return found;
  }

  function readSession() {
    for (const storage of storages()) {
      try {
        const raw = storage.getItem(SESSION_KEY);
        if (raw) return JSON.parse(raw);
      } catch (_) {
        // Unreadable entry: treat as signed out.
      }
    }
    return null;
  }

  function writeSession(value, remember) {
    try {
      (remember ? window.localStorage : window.sessionStorage).setItem(SESSION_KEY, JSON.stringify(value));
    } catch (_) {
      // Not remembered; the person signs in again next time.
    }
  }

  function clearSession() {
    for (const storage of storages()) {
      try {
        storage.removeItem(SESSION_KEY);
      } catch (_) {
        // Nothing stored.
      }
    }
  }

  // ------------------------------------------------------------------ crypto (mirror of src/dashboard.py)

  const fromB64 = (text) => Uint8Array.from(atob(text), (c) => c.charCodeAt(0));

  function toB64(bytes) {
    let text = '';
    for (const byte of bytes) text += String.fromCharCode(byte);
    return btoa(text);
  }

  const toHex = (buffer) => Array.from(new Uint8Array(buffer), (b) => b.toString(16).padStart(2, '0')).join('');

  async function accountId(username) {
    const digest = await crypto.subtle.digest('SHA-256', encoder.encode(ACCOUNT_ID_PREFIX + username.trim().toLowerCase()));
    return toHex(digest);
  }

  async function deriveKey(password, salt, iterations) {
    const base = await crypto.subtle.importKey('raw', encoder.encode(password.normalize('NFC')), 'PBKDF2', false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations }, base, 256);
    return new Uint8Array(bits);
  }

  async function fetchEnvelope() {
    const response = await fetch(`${DATA_URL}?t=${Date.now()}`, { cache: 'no-store' });
    if (!response.ok) throw new Error(`data.json returned ${response.status}`);
    const envelope = await response.json();
    if (envelope.v !== SUPPORTED_ENVELOPE) throw new Error('data.json has an unsupported format');
    return envelope;
  }

  async function unlock(envelope, id, keyBytes) {
    const entry = envelope.users[id];
    if (!entry) throw new LoginError();
    let dataKey;
    try {
      const wrapKey = await crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['decrypt']);
      const raw = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: fromB64(entry.iv), additionalData: encoder.encode(id) },
        wrapKey,
        fromB64(entry.key),
      );
      dataKey = await crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['decrypt']);
    } catch (_) {
      throw new LoginError();
    }
    const packed = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: fromB64(envelope.iv), additionalData: encoder.encode(envelope.aad) },
      dataKey,
      fromB64(envelope.data),
    );
    const stream = new Blob([packed]).stream().pipeThrough(new DecompressionStream('gzip'));
    const data = JSON.parse(await new Response(stream).text());
    if (data.schema !== SUPPORTED_SCHEMA) throw new Error('data.json has an unsupported layout');
    return data;
  }

  // ------------------------------------------------------------------ views and sign-in

  function show(view) {
    for (const id of ['boot-view', 'login-view', 'app']) $(`#${id}`).hidden = id !== view;
  }

  function setLoginError(message) {
    const el = $('#login-error');
    el.textContent = message || '';
    el.hidden = !message;
  }

  function showLogin(message) {
    show('login-view');
    setLoginError(message);
    $('#username').focus();
  }

  async function boot() {
    const saved = readSession();
    if (saved && saved.id && saved.key) {
      try {
        openDashboard(await unlock(await fetchEnvelope(), saved.id, fromB64(saved.key)));
        return;
      } catch (err) {
        if (!(err instanceof LoginError)) {
          showLogin('The numbers could not be loaded. Check your connection, then sign in again.');
          return;
        }
        clearSession();
      }
    }
    showLogin();
  }

  async function onLogin(event) {
    event.preventDefault();
    const username = $('#username').value;
    const password = $('#password').value;
    if (!username.trim() || !password) {
      setLoginError('Enter your username and password.');
      return;
    }
    const button = $('#login-button');
    button.disabled = true;
    button.textContent = 'Signing in…';
    setLoginError('');
    try {
      const envelope = await fetchEnvelope();
      const id = await accountId(username);
      const entry = envelope.users[id];
      // Unknown accounts still pay for a key derivation, so timing does not reveal which names exist.
      const salt = entry ? fromB64(entry.salt) : new Uint8Array(16);
      const iterations = entry ? entry.iterations : envelope.kdf.iterations;
      const key = await deriveKey(password, salt, iterations);
      const data = await unlock(envelope, id, key);
      writeSession({ id, key: toB64(key) }, $('#remember').checked);
      $('#password').value = '';
      openDashboard(data);
    } catch (err) {
      setLoginError(
        err instanceof LoginError
          ? "That username and password don't match an account. Check both and try again."
          : 'The numbers could not be loaded. Check your connection and try again.',
      );
    } finally {
      button.disabled = false;
      button.textContent = 'Sign in';
    }
  }

  function signOut() {
    clearSession();
    state.data = null;
    $('#app').innerHTML = '';
    $('#login-form').reset();
    try {
      window.history.replaceState(null, '', window.location.pathname);
    } catch (_) {
      // Address stays as it was.
    }
    showLogin();
  }

  function firstDate(data) {
    return data.days.length ? data.days[0].date : data.focus_date;
  }

  function lastDate(data) {
    return data.calendar && data.calendar.end > data.focus_date ? data.calendar.end : data.focus_date;
  }

  function readHash() {
    const params = new URLSearchParams(window.location.hash.slice(1));
    return { tab: params.get('tab'), date: params.get('date') };
  }

  function writeHash() {
    try {
      window.history.replaceState(null, '', `#tab=${state.tab}&date=${state.focus}`);
    } catch (_) {
      // Address stays as it was.
    }
  }

  function openDashboard(data) {
    state.data = data;
    const wanted = readHash();
    state.tab = TABS.some((t) => t.id === wanted.tab) ? wanted.tab : 'overview';
    const date = wanted.date && /^\d{4}-\d{2}-\d{2}$/.test(wanted.date) ? wanted.date : null;
    state.focus = date && date >= firstDate(data) && date <= lastDate(data) ? date : data.focus_date;
    state.showAllAttention = false;
    show('app');
    render(true);
  }

  // ------------------------------------------------------------------ formatting

  const isNum = (v) => typeof v === 'number' && Number.isFinite(v);
  const fmtInt = (v) => (isNum(v) ? Math.round(v).toLocaleString('en-US') : DASH);
  const fmtMoney = (v) => (isNum(v) ? `${v < 0 ? MINUS : ''}$${Math.abs(Math.round(v)).toLocaleString('en-US')}` : DASH);
  const fmtCents = (v) => (isNum(v) ? `${v < 0 ? MINUS : ''}$${Math.abs(v).toFixed(2)}` : DASH);
  const fmtMoneyShort = (v) => {
    if (!isNum(v)) return DASH;
    return Math.abs(v) >= 1000 ? `$${(v / 1000).toFixed(1)}k` : `$${Math.round(v)}`;
  };
  const fmtPct = (v) => (isNum(v) ? `${v.toFixed(1)}%` : DASH);
  const fmtHours = (v) => (isNum(v) ? `${v.toFixed(1)} h` : DASH);
  const fmtSigned = (v, format) => (isNum(v) ? `${v > 0 ? '+' : v < 0 ? MINUS : ''}${format(Math.abs(v))}` : DASH);
  const esc = (v) => String(v ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
  const groupLabel = (key) => (GUEST_GROUPS.find((g) => g.key === key) || { label: key }).label;
  const categoryLabel = (key) => ((state.data && state.data.category_labels) || {})[key] || CATEGORY_LABELS[key] || key;

  /** Calendar dates travel as YYYY-MM-DD; format them at noon UTC so no timezone shifts the day. */
  function dateOf(iso) {
    const [y, m, d] = iso.split('-').map(Number);
    return new Date(Date.UTC(y, m - 1, d, 12));
  }
  const fmtDay = (iso, options) => dateOf(iso).toLocaleDateString('en-US', { timeZone: 'UTC', ...options });
  const fmtDayLong = (iso) => fmtDay(iso, { weekday: 'long', month: 'long', day: 'numeric' });
  const fmtDayShort = (iso) => fmtDay(iso, { weekday: 'short', month: 'short', day: 'numeric' });
  const fmtMDY = (iso) => {
    const [y, m, d] = iso.split('-');
    return `${m}/${d}/${y}`;
  };
  const isoAdd = (iso, days) => {
    const d = dateOf(iso);
    d.setUTCDate(d.getUTCDate() + days);
    return d.toISOString().slice(0, 10);
  };
  const mondayIndex = (iso) => (dateOf(iso).getUTCDay() + 6) % 7;

  function fmtHour(hour) {
    const h = ((hour % 24) + 24) % 24;
    return `${h % 12 === 0 ? 12 : h % 12}${h < 12 ? 'am' : 'pm'}`;
  }

  function fmtClockText(text) {
    const [h, m] = String(text).split(':').map(Number);
    if (!isNum(h)) return String(text ?? '');
    const hour = ((h % 24) + 24) % 24;
    const minutes = isNum(m) && m ? `:${String(m).padStart(2, '0')}` : '';
    return `${hour % 12 === 0 ? 12 : hour % 12}${minutes}${hour < 12 ? 'am' : 'pm'}`;
  }

  /** "8:01 PM" becomes "8:01pm", matching the hour labels elsewhere on the page. */
  const compactMeridiem = (text) => text.replace(/\s?([AP])M/g, (_, letter) => `${letter.toLowerCase()}m`);
  const fmtStamp = (iso, timeZone) => compactMeridiem(
    new Date(iso).toLocaleString('en-US', { timeZone, weekday: 'short', month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' }),
  );
  const fmtClock = (iso, timeZone) => (iso
    ? compactMeridiem(new Date(iso).toLocaleTimeString('en-US', { timeZone, hour: 'numeric', minute: '2-digit' }))
    : DASH);
  const prefersReducedMotion = () => window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const safeLink = (url) => (typeof url === 'string' && url.startsWith('https://') ? url : null);

  // ------------------------------------------------------------------ page frame

  function render(animate) {
    const { data } = state;
    const app = $('#app');
    const day = data.days.find((d) => d.date === state.focus) || null;
    const renderer = TAB_RENDERERS[state.tab] || TAB_RENDERERS.overview;
    app.innerHTML = [
      topbar(data),
      controls(data),
      `<div id="panel" class="panel" role="tabpanel" aria-labelledby="tab-${state.tab}" tabindex="-1">${renderer(data, day, state.focus)}</div>`,
      footer(data),
    ].join('');
    applyDynamicStyles(app, animate);
    writeHash();
  }

  /** The page's CSP forbids inline style attributes, so sizes and tints are applied through the CSSOM. */
  function applyDynamicStyles(root, animate) {
    root.querySelectorAll('[data-delay]').forEach((el) => {
      if (animate) el.style.animationDelay = `${el.dataset.delay}ms`;
      else el.classList.remove('pit-drop');
    });
    root.querySelectorAll('[data-tint]').forEach((el) => {
      const rgb = el.dataset.tone === 'sky' ? SKY_RGB : TINT_RGB;
      el.style.backgroundColor = `rgba(${rgb}, ${(0.08 + Number(el.dataset.tint) * 0.42).toFixed(3)})`;
    });
    root.querySelectorAll('[data-cols]').forEach((el) => {
      el.style.gridTemplateColumns = `8rem repeat(${el.dataset.cols}, minmax(42px, 1fr))`;
    });
    root.querySelectorAll('[data-height]').forEach((el) => {
      el.style.height = `${Math.max(4, Number(el.dataset.height) * 100).toFixed(1)}%`;
    });
    root.querySelectorAll('[data-width]').forEach((el) => {
      el.style.width = `${(Number(el.dataset.width) * 100).toFixed(2)}%`;
    });
    root.querySelectorAll('[data-min-width]').forEach((el) => {
      el.style.minWidth = `${el.dataset.minWidth}px`;
    });
  }

  function updatedBy(refresh) {
    if (refresh.kind === 'refresh') return refresh.trigger === 'manual' ? 'by a refresh started by hand' : 'by the hourly refresh';
    if (refresh.mode && MODE_NAMES[refresh.mode]) return `after the ${MODE_NAMES[refresh.mode].toLowerCase()}`;
    return '';
  }

  function topbar(data) {
    const refresh = data.refresh || {};
    const minutes = (Date.now() - Date.parse(data.generated_at)) / 60000;
    const stale = minutes > STALE_AFTER_MINUTES
      ? `<span class="stale">${esc(minutes >= 120 ? `${Math.floor(minutes / 60)} hours old` : `${Math.round(minutes)} minutes old`)}</span>`
      : '';
    return `<header class="topbar wrap">
      <img class="topbar-logo" src="hyperkidz-logo.png" alt="Hyper Kidz" width="192" height="40">
      <div class="topbar-meta">
        ${stale}
        <span>Last updated ${esc(fmtStamp(data.generated_at, data.timezone))} ${esc(updatedBy(refresh))}.</span>
        <button type="button" class="btn-quiet" data-action="sign-out">Sign out</button>
      </div>
    </header>`;
  }

  function controls(data) {
    const min = firstDate(data);
    const max = lastDate(data);
    const tabs = TABS.map((t) => `<button type="button" class="tab" role="tab" id="tab-${t.id}" data-tab="${t.id}"
      aria-selected="${t.id === state.tab}" aria-controls="panel" tabindex="${t.id === state.tab ? 0 : -1}">${esc(t.label)}</button>`).join('');
    return `<div class="controls"><div class="wrap controls-row">
      <nav class="tabs" role="tablist" aria-label="Dashboard views">${tabs}</nav>
      <div class="picker">
        <button type="button" class="nav-btn" data-shift="-1" aria-label="Previous day" ${state.focus <= min ? 'disabled' : ''}>‹</button>
        <label class="visually-hidden" for="pick-date">Day</label>
        <input id="pick-date" type="date" min="${min}" max="${max}" value="${state.focus}">
        <button type="button" class="nav-btn" data-shift="1" aria-label="Next day" ${state.focus >= max ? 'disabled' : ''}>›</button>
        <button type="button" class="btn-quiet" data-action="latest">Latest</button>
      </div>
    </div></div>`;
  }

  /** An "i" button by a label that opens where the number comes from (``data.terms``, from src/terms.py). */
  function infoTip(term, extra = '') {
    const entry = term && ((state.data && state.data.terms) || {})[term];
    if (!entry) return '';
    const id = `tip-${term}-${++tipSerial}`;
    return `<button type="button" class="info-btn" data-action="info" aria-expanded="false" aria-controls="${id}" aria-label="${esc(`Where ${entry.label} comes from`)}">i</button>`
      + `<span class="info-tip" id="${id}" role="note" hidden>${esc(entry.info)}${extra ? ` ${esc(extra)}` : ''}</span>`;
  }

  /** Total stock's popover detail: the day's food and drink and retail amounts, and the ROLLER product groups. */
  function stockDetail(data, day) {
    const split = (day && day.stock_split) || {};
    const amounts = isNum(split.food) || isNum(split.retail)
      ? `This day: food and drink ${fmtCents(split.food || 0)}, retail ${fmtCents(split.retail || 0)}.` : '';
    const groups = ((data && data.category_groups) || {}).stock || [];
    return [amounts, groups.length ? `ROLLER product groups: ${groups.join(', ')}.` : ''].filter(Boolean).join(' ');
  }

  function closeInfo(except) {
    document.querySelectorAll('.info-btn[aria-expanded="true"]').forEach((button) => {
      if (button === except) return;
      button.setAttribute('aria-expanded', 'false');
      const tip = document.getElementById(button.getAttribute('aria-controls'));
      if (tip) tip.hidden = true;
    });
  }

  function toggleInfo(button) {
    const tip = document.getElementById(button.getAttribute('aria-controls'));
    if (!tip) return;
    const open = button.getAttribute('aria-expanded') !== 'true';
    closeInfo(button);
    button.setAttribute('aria-expanded', String(open));
    tip.hidden = !open;
  }

  function section(title, lede, body, band) {
    const id = `s-${title.toLowerCase().replace(/[^a-z0-9]+/g, '-')}`;
    return `<section class="${band ? `band ${band}` : 'plain'}" aria-labelledby="${id}"><div class="wrap">
      <h2 class="section-title" id="${id}">${esc(title)}</h2>
      ${lede ? `<p class="section-lede">${esc(lede)}</p>` : ''}
      ${body}
    </div></section>`;
  }

  function noNumbers(data, date) {
    const ahead = (data.next_days || []).find((d) => d.date === date);
    const future = date > data.focus_date;
    const forecast = ahead
      ? `<p>Expected: ${fmtInt(ahead.expected_guests)} walk-ins and ${fmtMoney(ahead.expected_revenue)} in net revenue, with labor at ${fmtPct(ahead.expected_labor_pct)} of revenue.</p>`
      : '';
    return `<div class="wrap empty">
      <h1 class="day-title">${esc(fmtDayLong(date))}</h1>
      <p>${future ? 'This day has not happened yet.' : 'No numbers were reported for this day.'} See the calendar for its parties and shifts.</p>
      ${forecast}
      <button type="button" class="btn-quiet" data-tab="calendar">Open the calendar</button>
      <button type="button" class="btn-quiet" data-tab="forecasts">Open forecasts</button>
    </div>`;
  }

  function footer(data) {
    const notes = (data.notes || []).map(esc).join(' ');
    return `<footer class="foot wrap">
      <p>${notes}</p>
      <p>Opening hours: ${esc(data.opening_hours)}. Labor target: ${fmtPct(data.targets.labor_pct)} of net revenue.</p>
    </footer>`;
  }

  // ------------------------------------------------------------------ overview

  function navDayTitle(data, day) {
    const tags = [];
    if (day.in_progress) {
      const label = day.after_close ? 'Closed, end-of-day report not in yet' : 'Open now, numbers so far';
      tags.push(`<span class="tag tag-live">${label}</span>`);
    }
    if (day.holiday_note) tags.push(`<span class="tag tag-holiday">${esc(day.holiday_note)}</span>`);
    return `<h1 class="day-title" id="day-title" tabindex="-1">${esc(fmtDayLong(day.date))}</h1>
      ${tags.length ? `<div class="day-tags">${tags.join('')}</div>` : ''}`;
  }

  function daySentence(data, day) {
    const soFar = day.so_far;
    if (day.in_progress && soFar && day.after_close) {
      const base = `By close: ${fmtInt(soFar.guests_so_far)} walk-ins and ${fmtMoney(soFar.revenue_so_far)} in net revenue, pulled at ${fmtClock(soFar.as_of, data.timezone)}. The end-of-day report adds funds received and the AI analysis.`;
      return day.forecast ? `${base} ${compareToForecast(day, day.forecast)}` : base;
    }
    if (day.in_progress && soFar) {
      let text = `So far today: ${fmtInt(soFar.guests_so_far)} walk-ins and ${fmtMoney(soFar.revenue_so_far)} in net revenue by ${fmtClock(soFar.as_of, data.timezone)}.`;
      if (isNum(soFar.projected_guests_so_far)) {
        text += ` The forecast for these hours was ${fmtInt(soFar.projected_guests_so_far)} walk-ins and ${fmtMoney(soFar.projected_revenue_so_far)}.`;
      }
      if (isNum(soFar.expected_total_guests)) {
        text += ` Expected at close: ${fmtInt(soFar.expected_total_guests)} walk-ins and ${fmtMoney(soFar.expected_total_revenue)}, with labor at ${fmtPct(soFar.expected_close_labor_pct)} of revenue.`;
      }
      return text;
    }
    const base = `${fmtInt(day.guests)} walk-ins and ${fmtMoney(day.net_revenue)} in net revenue.`;
    return day.forecast ? `${base} ${compareToForecast(day, day.forecast)}` : base;
  }

  function compareToForecast(day, forecast) {
    const parts = [];
    if (isNum(forecast.guests) && isNum(day.guests)) {
      const diff = Math.round(day.guests - forecast.guests);
      parts.push(diff === 0
        ? `walk-ins matched the forecast of ${fmtInt(forecast.guests)}`
        : `${fmtInt(Math.abs(diff))} ${diff > 0 ? 'more' : 'fewer'} walk-ins than the forecast of ${fmtInt(forecast.guests)}`);
    }
    if (isNum(forecast.revenue) && isNum(day.net_revenue)) {
      const diff = day.net_revenue - forecast.revenue;
      parts.push(Math.abs(diff) < 1
        ? `revenue matched the forecast of ${fmtMoney(forecast.revenue)}`
        : `revenue ${fmtMoney(Math.abs(diff))} ${diff > 0 ? 'above' : 'below'} the forecast of ${fmtMoney(forecast.revenue)}`);
    }
    if (!parts.length) return '';
    const sentence = parts.join(', and ');
    return `${sentence.charAt(0).toUpperCase()}${sentence.slice(1)}.`;
  }

  function keyNumbers(data, day) {
    const forecast = day.forecast;
    const soFar = day.in_progress && !day.after_close ? day.so_far : null;
    const guestsNote = soFar
      ? `Expected at close ${fmtInt(soFar.expected_total_guests)}`
      : forecast ? `Forecast ${fmtInt(forecast.guests)}` : `${fmtInt(day.walk_ins)} same-day bookings`;
    const revenueNote = soFar
      ? `Expected at close ${fmtMoney(soFar.expected_total_revenue)}`
      : forecast ? `Forecast ${fmtMoney(forecast.revenue)}` : `After ${fmtMoney(day.refunds)} in refunds`;
    const rows = [
      ['Walk-ins', fmtInt(day.guests), guestsNote, 'walk_ins'],
      ['Total guests', fmtInt(day.passes), 'Every pass, adults and memberships included', 'total_guests'],
      ['Net revenue', fmtMoney(day.net_revenue), revenueNote, 'net_revenue'],
      ['Funds received', fmtMoney(day.funds_received), isNum(day.funds_received) ? `Payments taken, ${fmtMoney(day.tips)} in tips left out` : 'Known after close', 'funds_received'],
      ['Labor cost', fmtMoney(day.actual_labor), `${fmtPct(day.labor_pct)} of revenue, target ${fmtPct(data.targets.labor_pct)}`, 'labor_cost'],
      ['Labor hours', fmtHours(day.actual_hours), `${fmtHours(day.scheduled_hours)} scheduled`, 'labor_hours'],
    ];
    return `<dl class="numbers">${rows.map(([label, value, sub, term]) => `<div class="number"><dt>${esc(label)}${infoTip(term)}</dt><dd>${esc(value)}<span class="sub">${esc(sub)}</span></dd></div>`).join('')}</dl>`;
  }

  function changeChip(value, label, { points = false, lowerIsBetter = false } = {}) {
    if (!isNum(value)) return '';
    const flat = Math.abs(value) < 0.5;
    const good = lowerIsBetter ? value < 0 : value > 0;
    const cls = flat ? 'flat' : good ? 'up' : 'down';
    const text = `${value > 0 ? '+' : value < 0 ? MINUS : ''}${Math.abs(value).toFixed(1)}${points ? ' pts' : '%'}`;
    return `<span class="chip ${cls}">${esc(label)} ${text}</span>`;
  }

  function growthBlock(day) {
    const growth = day.growth;
    if (!growth) return '';
    const rows = [
      ['Against the day before', growth.vs_previous_day, growth.previous_day],
      ['Against the same day last week', growth.vs_last_week, growth.last_week_date],
      ['Against the 4-week average', growth.vs_four_week_avg, null],
    ].filter(([, change]) => change && (isNum(change.guests) || isNum(change.net_revenue)));
    if (!rows.length) return '';
    const lines = rows.map(([label, change, ref]) => `<p class="growth">
      <span class="growth-label">${esc(label)}${ref ? `, ${esc(fmtDayShort(ref))}` : ''}</span>
      ${changeChip(change.guests, 'Walk-ins')}${changeChip(change.passes, 'Total guests')}${changeChip(change.net_revenue, 'Revenue')}
      ${changeChip(change.labor_pct, 'Labor', { points: true, lowerIsBetter: true })}
    </p>`).join('');
    return `<div class="wrap growth-wrap"><h2 class="section-title small">Growth</h2>${lines}${declineCallout(day)}</div>`;
  }

  function declineCallout(day) {
    const decline = day.growth && day.growth.decline;
    if (!decline) return '';
    const change = day.growth.vs_last_week;
    const fell = decline.metrics.map((m) => `${m === 'guests' ? 'walk-ins' : 'revenue'} ${Math.abs(change[m]).toFixed(0)}%`).join(' and ');
    const drivers = decline.drivers || {};
    const parts = [
      ...(drivers.guest_groups || []).slice(0, 3).map((r) => `${groupLabel(r.name).toLowerCase()} ${fmtSigned(r.change, fmtInt)}`),
      ...(drivers.revenue_categories || []).slice(0, 3).map((r) => `${categoryLabel(r.name).toLowerCase()} ${fmtSigned(r.change, fmtMoney)}`),
      ...(drivers.hours || []).slice(0, 3).map((r) => `${fmtHour(Number(r.name))} arrivals ${fmtSigned(r.change, fmtInt)}`),
      ...(drivers.bookings || []).map((r) => `${r.name === 'walk_ins' ? 'same-day bookings' : 'advance bookings'} ${fmtSigned(r.change, fmtInt)}`),
    ];
    return `<div class="callout" role="note"><strong>Down against ${esc(fmtDayLong(decline.baseline_date))}:</strong>
      ${esc(fell)} lower. Biggest drops: ${esc(parts.join('; ') || 'spread evenly across the day')}.</div>`;
  }

  function pitBlock(rows) {
    return `<div class="pit">${ballPit(rows)}</div>
      <p class="pit-legend">
        <span class="key"><span class="dot ok"></span>Within the labor budget</span>
        <span class="key"><span class="dot over"></span>Over the labor budget</span>
        <span class="key"><span class="ring"></span>Forecast</span>
        <span>Ball size is the walk-ins arriving in that hour.</span>
      </p>`;
  }

  /** The signature element: one ball per open hour, sized by arrivals, sitting on the floor line. */
  function ballPit(rows) {
    const peak = Math.max(1, ...rows.map((r) => Math.max(isNum(r.arrivals) ? r.arrivals : 0, isNum(r.forecast_arrivals) ? r.forecast_arrivals : 0)));
    const radius = (v) => (isNum(v) && v > 0 ? Math.max(BALL_MIN_RADIUS, Math.sqrt(v / peak) * BALL_MAX_RADIUS) : 0);
    const width = rows.length * HOUR_WIDTH;
    const parts = [
      `<svg class="pit-svg" viewBox="0 0 ${width} ${PIT_HEIGHT}" data-min-width="${rows.length * PIT_MIN_WIDTH_PER_HOUR}" role="img" aria-label="${esc(pitLabel(rows))}">`,
      `<line class="pit-floor" x1="0" x2="${width}" y1="${PIT_FLOOR}" y2="${PIT_FLOOR}"></line>`,
    ];
    rows.forEach((row, i) => {
      const cx = i * HOUR_WIDTH + HOUR_WIDTH / 2;
      const ball = radius(row.arrivals);
      const ring = radius(row.forecast_arrivals);
      const status = (STATUS[row.status] || STATUS.ok).cls;
      const staff = row.expected ? row.staff_scheduled : row.staff_actual;
      const labelY = PIT_FLOOR - 2 * Math.max(ball, ring, BALL_MIN_RADIUS) - 8;
      parts.push(`<g><title>${esc(hourTitle(row))}</title>`);
      if (ring) parts.push(`<circle class="pit-forecast" cx="${cx}" cy="${PIT_FLOOR - ring}" r="${ring.toFixed(1)}"></circle>`);
      if (ball) {
        parts.push(`<g class="pit-drop" data-delay="${i * DROP_STAGGER_MS}">`
          + `<circle class="pit-ball ${status}" cx="${cx}" cy="${(PIT_FLOOR - ball).toFixed(1)}" r="${ball.toFixed(1)}"></circle>`
          + `<ellipse class="pit-gloss" cx="${(cx - ball * 0.35).toFixed(1)}" cy="${(PIT_FLOOR - ball * 1.45).toFixed(1)}" rx="${(ball * 0.28).toFixed(1)}" ry="${(ball * 0.18).toFixed(1)}"></ellipse></g>`);
      }
      if (isNum(row.arrivals)) parts.push(`<text class="pit-count" x="${cx}" y="${labelY.toFixed(1)}">${fmtInt(row.arrivals)}</text>`);
      else if (isNum(row.forecast_arrivals)) parts.push(`<text class="pit-count is-forecast" x="${cx}" y="${labelY.toFixed(1)}">about ${fmtInt(row.forecast_arrivals)}</text>`);
      parts.push(`<text class="pit-hour" x="${cx}" y="${PIT_FLOOR + 22}">${fmtHour(row.hour)}</text>`);
      if (isNum(staff)) parts.push(`<text class="pit-staff" x="${cx}" y="${PIT_FLOOR + 40}">${staff} staff</text>`);
      parts.push('</g>');
    });
    parts.push('</svg>');
    return parts.join('');
  }

  function pitLabel(rows) {
    const actual = rows.filter((r) => isNum(r.arrivals));
    const span = `from ${fmtHour(rows[0].hour)} to ${fmtHour(rows[rows.length - 1].hour + 1)}`;
    if (!actual.length) return `Walk-ins by hour ${span}`;
    const busiest = actual.reduce((a, b) => (b.arrivals > a.arrivals ? b : a));
    return `Walk-ins arriving each hour ${span}. Busiest was ${fmtHour(busiest.hour)} with ${fmtInt(busiest.arrivals)} walk-ins.`;
  }

  function hourTitle(row) {
    const parts = [fmtHour(row.hour)];
    if (isNum(row.arrivals)) parts.push(`${fmtInt(row.arrivals)} walk-ins arrived`);
    if (isNum(row.forecast_arrivals)) parts.push(`forecast ${fmtInt(row.forecast_arrivals)}`);
    const staff = row.expected ? row.staff_scheduled : row.staff_actual;
    if (isNum(staff)) parts.push(`${staff} staff ${row.expected ? 'scheduled' : 'on the clock'}`);
    if (STATUS[row.status]) parts.push(STATUS[row.status].label.toLowerCase());
    return parts.join(', ');
  }

  function analysisTeaser(data, date) {
    const runs = (data.analyses || {})[date] || [];
    const latest = runs.filter((a) => a.has_analysis).pop();
    if (!latest) return '';
    return section(
      `The read on ${fmtDayLong(date)}`,
      '',
      `<p class="read-summary">${esc(latest.summary)}</p>
       <button type="button" class="btn-quiet" data-tab="analysis">Read the full AI analysis</button>`,
      'band-lilac',
    );
  }

  function overviewTab(data, day, date) {
    if (!day) return noNumbers(data, date);
    const hours = data.hourly[day.date] || [];
    return [
      `<section class="day wrap" id="day" aria-labelledby="day-title">
        ${navDayTitle(data, day)}
        <p class="day-sentence">${esc(daySentence(data, day))}</p>
        ${hours.length ? pitBlock(hours) : '<p class="pit-missing">Hour-by-hour detail is kept for the last 14 days.</p>'}
        ${keyNumbers(data, day)}
      </section>`,
      whyTeaser(data, day),
      growthBlock(day),
      figuresSection(data, day),
      timelineSection(data),
      analysisTeaser(data, date),
      attentionSection(data, date, ATTENTION_PREVIEW),
      aheadSection(data),
      aheadHeatmap(data),
      usualWeekSection(data),
    ].join('');
  }

  // ------------------------------------------------------------------ guests

  function guestMix(day) {
    const groups = day.guests_by_group || {};
    const rows = GUEST_GROUPS.map((g) => ({ ...g, count: groups[g.key] || 0 })).filter((g) => g.count > 0);
    if (!rows.length) return '<p class="muted">No pass breakdown was stored for this day.</p>';
    const people = rows.reduce((sum, g) => sum + g.count, 0);
    const adults = groups.adults || 0;
    const underThree = (groups.infants || 0) + (groups.toddlers || 0);
    const bar = rows
      .map((g) => `<span class="mix-seg ${g.cls}" data-width="${(g.count / people).toFixed(4)}" title="${esc(`${g.label}: ${fmtInt(g.count)}`)}"></span>`)
      .join('');
    const legend = rows
      .map((g) => `<li><span class="mix-dot ${g.cls}"></span><strong>${fmtInt(g.count)}</strong> ${esc(g.label)}</li>`)
      .join('');
    const label = rows.map((g) => `${fmtInt(g.count)} ${g.label}`).join(', ');
    return `<div class="mix">
      <p class="mix-summary">${fmtInt(people - adults)} kids and ${fmtInt(adults)} adults, ${fmtInt(people)} people in all. ${fmtInt(underThree)} of the kids were under 3.</p>
      <div class="mix-bar" role="img" aria-label="${esc(label)}">${bar}</div>
      <ul class="mix-legend">${legend}</ul>
    </div>`;
  }

  function dayBefore(data, iso) {
    return iso ? data.days.find((d) => d.date === iso) || null : null;
  }

  function guestsTab(data, day, date) {
    if (!day) return noNumbers(data, date);
    const lastWeek = dayBefore(data, day.growth && day.growth.last_week_date);
    const groups = day.guests_by_group || {};
    const before = (lastWeek && lastWeek.guests_by_group) || {};
    const groupRows = GUEST_GROUPS.filter((g) => groups[g.key] || before[g.key]).map((g) => `<tr>
        <td>${esc(g.label)}</td><td>${fmtInt(groups[g.key] || 0)}</td>
        <td>${lastWeek ? fmtInt(before[g.key] || 0) : DASH}</td>
        <td>${lastWeek ? fmtSigned((groups[g.key] || 0) - (before[g.key] || 0), fmtInt) : DASH}</td></tr>`).join('');
    const numbers = [
      ['Walk-ins', fmtInt(day.guests), 'walk_ins'],
      ['Total guests', fmtInt(day.passes), 'total_guests'],
      ['Same-day bookings', fmtInt(day.walk_ins), 'same_day_bookings'],
      ['Advance bookings', fmtInt(day.advance_bookings), 'advance_bookings'],
      ['Memberships sold', fmtInt(day.memberships_sold), 'memberships_sold'],
    ];
    const hours = data.hourly[day.date] || [];
    const hourRows = hours.map((r) => `<tr class="${r.expected ? 'is-expected' : ''}"><td>${fmtHour(r.hour)}${r.expected ? ' <span class="muted">expected</span>' : ''}</td>
      <td>${fmtInt(r.arrivals)}</td><td>${fmtInt(r.forecast_arrivals)}</td><td>${fmtInt(r.on_floor)}</td></tr>`).join('');
    return [
      `<section class="day wrap" aria-labelledby="day-title">${navDayTitle(data, day)}
        <dl class="kv">${numbers.map(([k, v, term]) => `<div><dt>${esc(k)}${infoTip(term)}</dt><dd>${esc(v)}</dd></div>`).join('')}</dl>
      </section>`,
      section('Who came', 'People by pass type, read from the ROLLER pass names. Adults are not counted as walk-ins.', `${guestMix(day)}
        ${groupRows ? `<div class="table-wrap"><table><thead><tr><th scope="col">Group</th><th scope="col">This day</th>
        <th scope="col">${lastWeek ? esc(fmtDayShort(lastWeek.date)) : 'Last week'}</th><th scope="col">Change</th></tr></thead>
        <tbody>${groupRows}</tbody></table></div>` : ''}`),
      hours.length ? section('Walk-ins by hour', 'Arrivals each hour against the forecast, and how many were on the floor.', `<div class="table-wrap"><table>
        <thead><tr><th scope="col">Hour</th><th scope="col">Arrived</th><th scope="col">Forecast</th><th scope="col">On the floor</th></tr></thead>
        <tbody>${hourRows}</tbody></table></div>`) : '',
      usualWeekSection(data),
      weeksSection(data, day.date, 'guests'),
    ].join('');
  }

  // ------------------------------------------------------------------ revenue

  function revenueTab(data, day, date) {
    if (!day) return noNumbers(data, date);
    const lastWeek = dayBefore(data, day.growth && day.growth.last_week_date);
    const categories = day.revenue_by_category || {};
    const before = (lastWeek && lastWeek.revenue_by_category) || {};
    const gross = Object.values(categories).reduce((sum, v) => sum + (v || 0), 0);
    const names = Object.keys({ ...categories, ...before }).sort((a, b) => (categories[b] || 0) - (categories[a] || 0));
    const categoryRows = names.map((name) => `<tr><td>${esc(categoryLabel(name))}${name === 'stock' ? infoTip('total_stock', stockDetail(data, day)) : ''}</td><td>${fmtMoney(categories[name] || 0)}</td>
      <td>${gross ? fmtPct(((categories[name] || 0) / gross) * 100) : DASH}</td>
      <td>${lastWeek ? fmtMoney(before[name] || 0) : DASH}</td>
      <td>${lastWeek ? fmtSigned((categories[name] || 0) - (before[name] || 0), fmtMoney) : DASH}</td></tr>`).join('');
    const methods = Object.entries(day.payments_by_method || {});
    const numbers = [
      ['Net revenue', fmtMoney(day.net_revenue), 'net_revenue'],
      ['Gross revenue', fmtMoney(day.gross_revenue)],
      ['Refunds', fmtMoney(day.refunds)],
      ['Funds received', fmtMoney(day.funds_received), 'funds_received'],
      ['Tips', fmtMoney(day.tips)],
    ];
    const roller = safeLink(data.links && data.links.roller);
    return [
      `<section class="day wrap" aria-labelledby="day-title">${navDayTitle(data, day)}
        <dl class="kv">${numbers.map(([k, v, term]) => `<div><dt>${esc(k)}${infoTip(term)}</dt><dd>${esc(v)}</dd></div>`).join('')}</dl>
      </section>`,
      section('Revenue by category', 'Before sales tax, counted on the day of the visit, against the same day last week.', `<div class="table-wrap"><table>
        <thead><tr><th scope="col">Category</th><th scope="col">Amount</th><th scope="col">Share</th>
        <th scope="col">${lastWeek ? esc(fmtDayShort(lastWeek.date)) : 'Last week'}</th><th scope="col">Change</th></tr></thead>
        <tbody>${categoryRows}</tbody></table></div>`),
      section('Payments taken', isNum(day.funds_received)
        ? 'Every payment taken this day minus tips, whatever day the booking is for. It matches ROLLER\'s Funds received.'
        : 'Payments are added up after close.', methods.length
        ? `<ul class="list-plain">${methods.map(([method, amount]) => `<li><span class="list-when">${esc(method)}</span><span class="list-detail">${fmtCents(amount)}</span></li>`).join('')}</ul>`
        : '', ''),
      section('Figures only ROLLER shows', '', `<p class="section-lede">Check-ins and ROLLER's attendance-based revenue are not available from ROLLER's API.${roller ? ` <a href="${esc(roller)}" target="_blank" rel="noopener noreferrer">Open ROLLER's dashboard</a>.` : ''}</p>`),
      weeksSection(data, day.date, 'net_revenue'),
    ].join('');
  }

  // ------------------------------------------------------------------ staff

  function staffTab(data, day, date) {
    const rows = (data.staff || {})[date] || [];
    const title = `<section class="day wrap" aria-labelledby="day-title"><h1 class="day-title" id="day-title" tabindex="-1">${esc(fmtDayLong(date))}</h1>
      ${day ? `<dl class="kv">
        <div><dt>Labor cost</dt><dd>${esc(fmtMoney(day.actual_labor))}</dd></div>
        <div><dt>Labor % of revenue</dt><dd>${esc(fmtPct(day.labor_pct))}</dd></div>
        <div><dt>Hours worked</dt><dd>${esc(fmtHours(day.actual_hours))}</dd></div>
        <div><dt>Hours scheduled</dt><dd>${esc(fmtHours(day.scheduled_hours))}</dd></div>
      </dl>` : ''}</section>`;
    if (!rows.length) {
      return `${title}<div class="wrap empty"><p>No staff records for this day. The staff view covers the last 14 days; later days are on the calendar.</p></div>`;
    }
    const tz = data.timezone;
    const total = rows.reduce((t, r) => ({ scheduled: t.scheduled + (r.scheduled_hours || 0), worked: t.worked + (r.worked_hours || 0), cost: t.cost + (r.worked_cost || 0) }), { scheduled: 0, worked: 0, cost: 0 });
    const body = rows.map((r) => `<tr>
      <td>${esc(r.name)}</td><td class="text">${esc((r.roles || []).join(', ') || DASH)}</td>
      <td class="text">${r.scheduled_start ? `${fmtClock(r.scheduled_start, tz)} to ${fmtClock(r.scheduled_end, tz)}<span class="cell-sub">${fmtHours(r.scheduled_hours)}</span>` : DASH}</td>
      <td class="text">${r.clocked_in ? `${fmtClock(r.clocked_in, tz)} to ${r.clocked_out ? fmtClock(r.clocked_out, tz) : 'now'}<span class="cell-sub">${fmtHours(r.worked_hours)}</span>` : DASH}</td>
      <td>${isNum(r.variance_hours) ? fmtSigned(r.variance_hours, (v) => `${v.toFixed(1)} h`) : DASH}</td>
      <td>${isNum(r.late_minutes) && r.late_minutes > 0 ? `${r.late_minutes} min` : DASH}</td>
      <td>${fmtMoney(r.worked_cost)}</td>
      <td>${fmtHours(r.week_hours)}${r.overtime ? ' <span class="chip overtime">Overtime</span>' : ''}</td>
      <td class="text"><span class="chip ${esc(r.status)}">${esc(STAFF_STATUS[r.status] || r.status)}</span></td>
    </tr>`).join('');
    const hours = data.hourly[date] || [];
    const hourRows = hours.map((r) => {
      const status = STATUS[r.status];
      return `<tr class="${r.expected ? 'is-expected' : ''}"><td>${fmtHour(r.hour)}</td><td>${fmtInt(r.on_floor)}</td><td>${fmtInt(r.staff_scheduled)}</td>
        <td>${r.expected ? DASH : fmtInt(r.staff_actual)}</td><td>${fmtInt(r.recommended)}</td>
        <td>${status ? `<span class="chip ${status.cls}">${status.label}</span>` : DASH}</td></tr>`;
    }).join('');
    return [
      title,
      section('Team', 'Each person\'s scheduled shift from 7shifts against their clock-ins, with the cost of the hours worked and their hours so far this week.', `<div class="table-wrap"><table>
        <thead><tr><th scope="col">Name</th><th scope="col" class="text">Role</th><th scope="col" class="text">Scheduled</th><th scope="col" class="text">Clocked</th>
        <th scope="col">Difference</th><th scope="col">Late</th><th scope="col">Cost</th><th scope="col">This week</th><th scope="col" class="text">Status</th></tr></thead>
        <tbody>${body}<tr class="total"><td>Total</td><td></td><td class="text">${fmtHours(total.scheduled)} scheduled</td><td class="text">${fmtHours(total.worked)} worked</td>
        <td></td><td></td><td>${fmtMoney(total.cost)}</td><td></td><td></td></tr></tbody></table></div>`),
      hours.length ? section('Staffing by hour', 'Staff scheduled, on the clock, and how many of them the labor budget for that hour pays for (never more than scheduled).', `<div class="table-wrap"><table>
        <thead><tr><th scope="col">Hour</th><th scope="col">On the floor</th><th scope="col">Scheduled</th><th scope="col">On the clock</th>
        <th scope="col">Budget allows</th><th scope="col">Labor budget</th></tr></thead><tbody>${hourRows}</tbody></table></div>`) : '',
    ].join('');
  }

  // ------------------------------------------------------------------ calendar

  function partyLine(p) {
    const hosts = p.hosts_scheduled === 0
      ? '<span class="chip under">No party host</span>'
      : isNum(p.hosts_scheduled) ? `${p.hosts_scheduled} host${p.hosts_scheduled === 1 ? '' : 's'}` : '';
    const people = isNum(p.kids)
      ? `${fmtInt(p.kids)} kids${p.adults ? `, ${fmtInt(p.adults)} adults` : ''}`
      : `${fmtInt(p.guests)} kids`;
    const rooms = (p.rooms || []).length ? p.rooms.join(' and ') : 'Room not noted';
    const money = isNum(p.total)
      ? `${fmtCents(p.paid)} paid of ${fmtCents(p.total)}${p.owing > 0.005 ? `, <span class="chip under">${esc(fmtCents(p.owing))} owing</span>` : ''}`
      : '';
    return `<div class="agenda-row"><strong>${esc(fmtClockText(p.start))}${p.end ? ` to ${esc(fmtClockText(p.end))}` : ''}</strong>
      <span>${esc(p.product)}: ${esc(people)}. ${esc(rooms)}. ${hosts}</span>
      ${money ? `<span class="muted">${money}</span>` : ''}</div>`;
  }

  function calendarTab(data, day, date) {
    const tz = data.timezone;
    const start = date < data.calendar.start ? data.calendar.start : date;
    const days = Array.from({ length: CALENDAR_DAYS }, (_, i) => isoAdd(start, i)).filter((d) => d <= data.calendar.end);
    const blocks = days.map((d) => {
      const parties = (data.parties || {})[d] || [];
      const shifts = (data.shifts || {})[d] || [];
      const ahead = (data.next_days || []).find((n) => n.date === d);
      const actual = data.days.find((n) => n.date === d);
      const expected = actual
        ? `${fmtInt(actual.guests)} walk-ins, ${fmtMoney(actual.net_revenue)}${actual.in_progress ? ' so far' : ''}`
        : ahead ? `Expected ${fmtInt(ahead.expected_guests)} walk-ins, ${fmtMoney(ahead.expected_revenue)}` : '';
      return `<div class="agenda-day">
        <h3>${esc(fmtDayLong(d))}</h3>
        ${expected ? `<p class="section-lede">${esc(expected)}</p>` : ''}
        <div class="agenda-cols">
          <div><h4>Parties</h4>${parties.length ? parties.map(partyLine).join('') : '<p class="muted">No parties booked.</p>'}</div>
          <div><h4>Shifts</h4>${shifts.length ? shifts.map((s) => `<div class="agenda-row"><strong>${esc(fmtClock(s.start, tz))} to ${esc(fmtClock(s.end, tz))}</strong>
            <span>${esc(s.name)}, ${esc(s.role || 'no role')}</span></div>`).join('') : '<p class="muted">No shifts published.</p>'}</div>
        </div>
      </div>`;
    }).join('');
    return `<div class="wrap day"><h1 class="day-title" id="day-title" tabindex="-1">Calendar</h1>
      <p class="section-lede">Seven days from ${esc(fmtDayLong(start))}: parties with their rooms, kids and payments from ROLLER, and the shifts published in 7shifts. Rooms come from the booking notes.</p>
      ${blocks}</div>`;
  }

  // ------------------------------------------------------------------ forecasts

  /** A day ahead against its labor budget: how many walk-ins one staff member covers, and the cuts that keep labor within it. */
  function laborBudgetText(budget, target) {
    if (!budget) return '';
    const parts = [];
    if (isNum(budget.guests_per_staff_at_budget)) {
      const scheduled = isNum(budget.guests_per_staff_scheduled) ? `, 1 per ${fmtInt(budget.guests_per_staff_scheduled)} as scheduled` : '';
      parts.push(`<span class="ahead-meta">${esc(`Budget pays for 1 staff per ${fmtInt(budget.guests_per_staff_at_budget)} walk-ins${scheduled}`)}</span>`);
    }
    const cuts = (budget.cuts || []).map((c) => `${c.cut} at ${fmtHour(c.hour)}`);
    const tail = cuts.length ? `: cut ${cuts.join(', ')} (saves ${fmtMoney(budget.cuts_save)})` : '';
    if (budget.over_by > 0) {
      parts.push(`<span class="ahead-gap">${esc(`Labor ${fmtMoney(budget.over_by)} over the ${fmtPct(target)} budget${tail}`)}</span>`);
    } else if (cuts.length) {
      parts.push(`<span class="ahead-gap">${esc(`Within the ${fmtPct(target)} budget${tail}`)}</span>`);
    }
    return parts.join('');
  }

  function aheadSection(data) {
    const rows = data.next_days || [];
    if (!rows.length) return '';
    const peak = Math.max(1, ...rows.map((r) => r.expected_revenue || 0));
    const totals = rows.reduce(
      (t, r) => ({ guests: t.guests + (r.expected_guests || 0), revenue: t.revenue + (r.expected_revenue || 0), labor: t.labor + (r.scheduled_labor || 0) }),
      { guests: 0, revenue: 0, labor: 0 },
    );
    const laborPct = totals.revenue ? (totals.labor / totals.revenue) * 100 : null;
    const items = rows.map((r) => `<li class="ahead-day">
        <span class="ahead-name">${esc(fmtDay(r.date, { weekday: 'short' }))}</span>
        <span class="ahead-date">${esc(fmtDay(r.date, { month: 'short', day: 'numeric' }))}</span>
        <span class="ahead-bar" aria-hidden="true"><span data-height="${((r.expected_revenue || 0) / peak).toFixed(3)}"></span></span>
        <strong class="ahead-rev">${fmtMoney(r.expected_revenue)}</strong>
        <span class="ahead-meta">${fmtInt(r.expected_guests)} walk-ins</span>
        ${isNum(r.booked_guests) ? `<span class="ahead-meta">${fmtInt(r.booked_guests)} already booked</span>` : ''}
        ${isNum(r.revenue_change_pct) ? `<span class="ahead-meta">${esc(fmtSigned(r.revenue_change_pct, (v) => `${v.toFixed(0)}%`))} revenue vs last week</span>` : ''}
        ${isNum(r.revenue_vs_four_week_pct) ? `<span class="ahead-meta">${esc(fmtSigned(r.revenue_vs_four_week_pct, (v) => `${v.toFixed(0)}%`))} vs the 4-week average</span>` : ''}
        <span class="ahead-meta">Labor ${fmtPct(r.expected_labor_pct)}, ${fmtHours(r.scheduled_hours)} scheduled</span>
        ${r.holiday_note ? `<span class="ahead-holiday">${esc(r.holiday_note)}</span>` : ''}
        ${laborBudgetText(r.labor_budget, data.targets.labor_pct)}
        <button type="button" class="btn-link" data-goto="forecasts" data-date="${r.date}">Why this forecast</button>
      </li>`).join('');
    return section('Next 7 days', 'Expected from the bookings already made plus the usual same-day arrivals for each weekday, against the staff scheduled in 7shifts.', `
      <div class="ahead-scroll"><ol class="ahead">${items}</ol></div>
      <p class="ahead-total">${fmtInt(totals.guests)} walk-ins and ${fmtMoney(totals.revenue)} in net revenue expected, with scheduled labor at ${fmtPct(laborPct)} of revenue.</p>`, 'band-sky');
  }

  function weekToDateSection(data) {
    const week = data.week_to_date;
    if (!week || !week.this_week || !week.this_week.days) return '';
    const change = week.change_pct || {};
    const rows = [['Walk-ins', 'guests', fmtInt], ['Total guests', 'passes', fmtInt], ['Net revenue', 'net_revenue', fmtMoney], ['Labor cost', 'actual_labor', fmtMoney]]
      .map(([label, key, format]) => `<tr><td>${label}</td><td>${format(week.this_week[key])}</td><td>${format(week.last_week[key])}</td>
        <td>${isNum(change[key]) ? esc(fmtSigned(change[key], (v) => `${v.toFixed(1)}%`)) : DASH}</td></tr>`).join('');
    return section('Week to date', `Monday to ${fmtDayLong(week.through)} (${week.this_week.days} days) against the same days last week.`, `<div class="table-wrap"><table>
      <thead><tr><th scope="col">Measure</th><th scope="col">This week</th><th scope="col">Last week</th><th scope="col">Change</th></tr></thead>
      <tbody>${rows}</tbody></table></div>`);
  }

  function missText(pct) {
    if (!isNum(pct)) return DASH;
    const size = Math.abs(pct);
    if (size < 0.5) return 'On the mark';
    return `${size.toFixed(0)}% ${pct > 0 ? 'high' : 'low'}`;
  }

  function accuracySection(data) {
    const accuracy = data.accuracy;
    if (!accuracy || !accuracy.days) return '';
    let sentence = `Over the last ${accuracy.days} days with a forecast, walk-in forecasts were off by ${fmtPct(accuracy.mape_guests)} on average and revenue forecasts by ${fmtPct(accuracy.mape_revenue)}.`;
    const bias = accuracy.bias_guests_pct;
    if (isNum(bias) && Math.abs(bias) >= BIAS_WORTH_MENTIONING) {
      sentence += ` Walk-in forecasts have run ${bias < 0 ? 'low' : 'high'} by ${Math.abs(bias).toFixed(0)}%, so plan for ${bias < 0 ? 'more' : 'fewer'} walk-ins than forecast.`;
    }
    const rows = data.days
      .filter((d) => d.forecast && !d.in_progress)
      .slice(-ACCURACY_ROWS)
      .reverse()
      .map((d) => {
        const f = d.forecast;
        const cls = (pct) => (isNum(pct) && Math.abs(pct) >= BIG_MISS_PCT ? ' class="off-big"' : '');
        return `<tr><td>${esc(fmtDayShort(d.date))}</td>
          <td>${fmtInt(f.guests)}</td><td>${fmtInt(d.guests)}</td><td${cls(f.guests_error_pct)}>${missText(f.guests_error_pct)}</td>
          <td>${fmtMoney(f.revenue)}</td><td>${fmtMoney(d.net_revenue)}</td><td${cls(f.revenue_error_pct)}>${missText(f.revenue_error_pct)}</td>
          <td><button type="button" class="btn-link" data-goto="forecasts" data-date="${d.date}">Why</button></td></tr>`;
      }).join('');
    return section('How good the forecasts have been', `${sentence} Each forecast is the last one made before the venue opened.`, rows ? `<div class="table-wrap"><table>
        <thead><tr><th scope="col">Day</th><th scope="col">Walk-ins forecast</th><th scope="col">Walk-ins actual</th><th scope="col">Walk-in forecast was</th><th scope="col">Revenue forecast</th><th scope="col">Revenue actual</th><th scope="col">Revenue forecast was</th><th scope="col"><span class="visually-hidden">Explanation</span></th></tr></thead>
        <tbody>${rows}</tbody>
      </table></div>` : '');
  }

  function forecastsTab(data, day, date) {
    const ahead = (data.next_days || []).find((d) => d.date === date) || null;
    let lead = 'Pick a day with a forecast to see why it said what it did.';
    if (day) lead = daySentence(data, day);
    else if (ahead) lead = `Expected: ${fmtInt(ahead.expected_guests)} walk-ins and ${fmtMoney(ahead.expected_revenue)} in net revenue.`;
    return [
      `<section class="day wrap" aria-labelledby="day-title"><h1 class="day-title" id="day-title" tabindex="-1">Forecasts</h1>
        <p class="day-sentence">${esc(fmtDayLong(date))}. ${esc(lead)}</p></section>`,
      whySection(data, date, day, ahead),
      outcomeSection(data, day),
      timelineSection(data),
      aheadSection(data),
      aheadHeatmap(data),
      weekToDateSection(data),
      accuracySection(data),
    ].join('');
  }

  // ------------------------------------------------------------------ analysis and updates

  function analysisTab(data, day, date) {
    const schedule = (data.schedule || {})[date] || [];
    const runs = ((data.analyses || {})[date] || []).slice().reverse();
    const list = (title, items) => (items && items.length
      ? `<div><h3>${esc(title)}</h3><ul>${items.map((item) => `<li>${esc(item)}</li>`).join('')}</ul></div>`
      : '');
    const statusItems = schedule.map((s) => {
      const status = SCHEDULE_STATUS[s.status] || SCHEDULE_STATUS.pending;
      return `<li><span class="chip ${status.cls}">${esc(s.label)}: ${esc(status.label)}</span></li>`;
    }).join('');
    const cards = runs.map((a) => `<div class="analysis-card">
      <h3>${esc(MODE_NAMES[a.mode] || a.mode)}, ${esc(fmtStamp(a.run_at, data.timezone))}</h3>
      <p class="muted">${a.trigger === 'manual' ? 'Started by hand' : 'Scheduled'}. E-mail ${a.email_sent ? 'sent' : 'not sent'}; dashboard ${a.dashboard_published ? 'updated' : 'not updated'}.</p>
      ${a.has_analysis ? `<p class="read-summary">${esc(a.summary)}</p>
        <div class="read-lists">${list('Staffing moves', a.staffing_actions)}${a.mode === 'eod' ? '' : list('Coming up', a.predictions)}${list('What stood out', a.insights)}${list('Watch for', a.risks)}</div>
        <p class="read-by">Written by AI from that run's numbers.</p>`
        : '<p>The run produced its numbers, but no AI analysis was written.</p>'}
    </div>`).join('');
    return `<div class="wrap day"><h1 class="day-title" id="day-title" tabindex="-1">AI analysis</h1>
      <p class="day-sentence">${esc(fmtDayLong(date))}</p>
      ${statusItems ? `<ul class="status-list" aria-label="Scheduled reports">${statusItems}</ul>` : '<p class="section-lede">No scheduled reports for this day.</p>'}
      ${cards || `<p class="empty">No analysis was written for this day. The AI writes one with the 7am morning report, at the 1pm check-in and after the 9:45pm report, from the same numbers as the e-mail; the statuses above say whether those runs happened. Until one is written, the <button type="button" class="btn-link" data-goto="forecasts" data-date="${date}">Forecasts tab</button> explains each forecast from the numbers.</p>`}
    </div>`;
  }

  function updatesTab(data) {
    const refresh = data.refresh || {};
    const failures = refresh.failures || [];
    const usage = data.api_usage;
    const usageLine = usage
      ? `<p class="section-lede">ROLLER API calls: ${fmtInt(usage.today)} today, ${fmtInt(usage.last_7_days)} in the last 7 days and ${fmtInt(usage.month_to_date)} this month, of ${fmtInt(usage.monthly_allowance)} included each month.</p>`
      : '';
    const rows = (data.updates || []).map((u) => `<tr>
      <td>${esc(fmtStamp(u.run_at, data.timezone))}</td>
      <td class="text">${esc(UPDATE_KINDS[u.kind] || u.kind)}</td>
      <td class="text">${u.trigger ? esc(u.trigger === 'manual' ? 'By hand' : 'Scheduled') : DASH}</td>
      <td class="text"><span class="chip ${u.ok ? 'done' : 'failed'}">${u.ok ? 'Worked' : 'Failed'}</span></td>
      <td class="notes">${esc(u.notes)}</td></tr>`).join('');
    return `<div class="wrap day"><h1 class="day-title" id="day-title" tabindex="-1">Updates</h1>
      <p class="day-sentence">Last updated ${esc(fmtStamp(data.generated_at, data.timezone))} ${esc(updatedBy(refresh))}. The dashboard refreshes every hour while the venue is open, and after the mid-day and end-of-day reports.</p>
      ${usageLine}
      ${failures.length ? `<div class="callout" role="note"><strong>Some data could not be pulled in this update:</strong> ${esc(failures.join('; '))}</div>` : ''}
    </div>${section('Update log', 'Every refresh and report run, newest first.', rows ? `<div class="table-wrap"><table>
      <thead><tr><th scope="col">When</th><th scope="col" class="text">What</th><th scope="col" class="text">Started</th><th scope="col" class="text">Result</th><th scope="col" class="text">Details</th></tr></thead>
      <tbody>${rows}</tbody></table></div>` : '<p class="muted">No updates recorded yet.</p>')}`;
  }

  // ------------------------------------------------------------------ shared sections

  function weeksSection(data, focusDate, metric) {
    const days = data.days;
    if (!days.length) return '';
    const byDate = new Map(days.map((d) => [d.date, d]));
    const firstMonday = isoAdd(days[0].date, -mondayIndex(days[0].date));
    const lastDay = days[days.length - 1].date;
    const peak = Math.max(1, ...days.map((d) => d[metric] || 0));
    const show = (value) => (metric === 'guests' ? fmtInt(value) : fmtMoneyShort(value));
    const heads = ['Week', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun', 'Week total']
      .map((label, i) => `<div class="weeks-head${i === 0 ? ' col-label' : ''}${i === 8 ? ' col-total' : ''}">${label}</div>`)
      .join('');
    const rows = [];
    for (let monday = isoAdd(lastDay, -mondayIndex(lastDay)); monday >= firstMonday; monday = isoAdd(monday, -7)) {
      const dates = Array.from({ length: 7 }, (_, i) => isoAdd(monday, i));
      const present = dates.map((date) => byDate.get(date)).filter(Boolean);
      const totals = present.reduce(
        (t, d) => ({ guests: t.guests + (d.guests || 0), revenue: t.revenue + (d.net_revenue || 0), labor: t.labor + (d.actual_labor || 0) }),
        { guests: 0, revenue: 0, labor: 0 },
      );
      const cells = dates.map((date) => {
        const d = byDate.get(date);
        const dayNumber = Number(date.slice(8));
        if (!d) return `<div class="cell cell-empty" aria-hidden="true"><span class="cell-day">${dayNumber}</span></div>`;
        const focused = date === focusDate;
        const label = `${fmtDayLong(date)}: ${fmtInt(d.guests)} walk-ins, ${fmtMoney(d.net_revenue)} net revenue${d.in_progress ? ' so far' : ''}`;
        return `<button type="button" class="cell${focused ? ' is-focus' : ''}" data-focus="${date}" data-tint="${((d[metric] || 0) / peak).toFixed(3)}" aria-pressed="${focused}" aria-label="${esc(label)}">
          <span class="cell-day">${dayNumber}</span>
          <span class="cell-rev">${show(d[metric])}</span>
          <span class="cell-guests">${metric === 'guests' ? fmtMoneyShort(d.net_revenue) : `${fmtInt(d.guests)} walk-ins`}</span>
          ${d.holiday ? `<span class="cell-holiday">${esc(d.holiday)}</span>` : ''}
        </button>`;
      }).join('');
      const laborPct = totals.revenue ? (totals.labor / totals.revenue) * 100 : null;
      const partial = present.length < 7 ? `, ${present.length} of 7 days` : '';
      rows.push(`<div class="week-label">${fmtMDY(monday)} – ${fmtMDY(isoAdd(monday, 6))}</div>${cells}
        <div class="week-total">${fmtMoney(totals.revenue)}, ${fmtInt(totals.guests)} walk-ins<br>Labor ${fmtPct(laborPct)}${partial}</div>`);
    }
    return section('Week by week', `Each square is one day, shaded by ${metric === 'guests' ? 'walk-ins' : 'net revenue'}, so the same weekday lines up down each column. Pick a day to open it.`,
      `<div class="weeks">${heads}${rows.join('')}</div>`);
  }

  function attentionSection(data, date, preview) {
    const rank = (a) => (SEVERITY[a.severity] ? SEVERITY[a.severity].rank : 9);
    const list = ((data.anomalies || {})[date] || []).slice().sort((a, b) => rank(a) - rank(b));
    if (!list.length) return '';
    const shown = state.showAllAttention ? list : list.slice(0, preview);
    const items = shown.map((a) => {
      const severity = SEVERITY[a.severity] || SEVERITY.low;
      const at = isNum(a.hour) ? ` at ${fmtHour(a.hour)}` : '';
      return `<li><span class="chip sev ${esc(a.severity)}">${severity.label}${at}</span><span class="list-detail">${esc(a.description)}</span><span class="list-action">${esc(a.action)}</span></li>`;
    }).join('');
    const more = list.length > shown.length
      ? `<button type="button" class="btn-quiet more" data-action="show-all-attention">Show all ${list.length}</button>`
      : '';
    return section('Needs attention', `What the report flagged for ${fmtDayLong(date)}, most urgent first.`, `<ul class="list-plain">${items}</ul>${more}`);
  }

  // ------------------------------------------------------------------ projections: chart and heatmaps

  function barTitle(bar, fmt) {
    const parts = [fmtDayShort(bar.date)];
    parts.push(bar.kind === 'projected' ? `expected ${fmt(bar.value)}` : `${fmt(bar.value)}${bar.kind === 'live' ? ' so far' : ''}`);
    if (isNum(bar.forecast)) parts.push(`forecast ${fmt(bar.forecast)}`);
    if (isNum(bar.booked)) parts.push(`${fmtInt(bar.booked)} already booked`);
    return parts.join(', ');
  }

  /** Two weeks of actual bars with the forecast made before each day, then the next 7 days as expected. */
  function timelineChart(data, metric) {
    const guests = metric === 'guests';
    const past = data.days.slice(-TIMELINE_PAST_DAYS).map((d) => ({
      date: d.date,
      kind: d.in_progress ? 'live' : 'actual',
      value: guests ? d.guests : d.net_revenue,
      forecast: d.forecast ? (guests ? d.forecast.guests : d.forecast.revenue) : null,
      booked: null,
    }));
    const seen = new Set(past.map((b) => b.date));
    const ahead = (data.next_days || []).filter((n) => !seen.has(n.date)).map((n) => ({
      date: n.date,
      kind: 'projected',
      value: guests ? n.expected_guests : n.expected_revenue,
      forecast: null,
      booked: guests ? n.booked_guests : null,
    }));
    const bars = [...past, ...ahead];
    if (!bars.length) return '';
    const fmt = guests ? fmtInt : fmtMoneyShort;
    const peak = Math.max(1, ...bars.map((b) => Math.max(b.value || 0, b.forecast || 0)));
    const height = (v) => (Math.max(0, v || 0) / peak) * (CHART_FLOOR - CHART_TOP);
    const width = bars.length * BAR_WIDTH;
    const label = `${guests ? 'Walk-ins' : 'Net revenue'} for the last ${past.length} days and expected for the next ${ahead.length}`;
    const parts = [
      `<svg class="tl-svg" viewBox="0 0 ${width} ${CHART_HEIGHT}" data-min-width="${bars.length * 36}" role="img" aria-label="${esc(label)}">`,
      `<line class="pit-floor" x1="0" x2="${width}" y1="${CHART_FLOOR}" y2="${CHART_FLOOR}"></line>`,
    ];
    if (past.length && ahead.length) {
      const x = past.length * BAR_WIDTH;
      parts.push(`<line class="tl-divide" x1="${x}" x2="${x}" y1="4" y2="${CHART_FLOOR}"></line>`);
      parts.push(`<text class="tl-divide-label" x="${x + 6}" y="14">Expected</text>`);
    }
    bars.forEach((b, i) => {
      const x = i * BAR_WIDTH + 8;
      const w = BAR_WIDTH - 16;
      const cx = x + w / 2;
      const h = height(b.value);
      const top = CHART_FLOOR - Math.max(h, height(b.forecast));
      parts.push(`<g><title>${esc(barTitle(b, fmt))}</title>`);
      parts.push(`<rect class="tl-bar ${b.kind}" x="${x}" y="${(CHART_FLOOR - Math.max(h, 1)).toFixed(1)}" width="${w}" height="${Math.max(h, 1).toFixed(1)}" rx="6"></rect>`);
      if (isNum(b.booked) && b.booked > 0) {
        const hb = Math.min(height(b.booked), h);
        parts.push(`<rect class="tl-booked" x="${x}" y="${(CHART_FLOOR - hb).toFixed(1)}" width="${w}" height="${hb.toFixed(1)}" rx="6"></rect>`);
      }
      if (isNum(b.forecast)) {
        const y = (CHART_FLOOR - height(b.forecast)).toFixed(1);
        parts.push(`<line class="tl-forecast" x1="${x - 4}" x2="${x + w + 4}" y1="${y}" y2="${y}"></line>`);
      }
      if (isNum(b.value)) parts.push(`<text class="tl-value" x="${cx}" y="${(top - 7).toFixed(1)}">${fmt(b.value)}</text>`);
      parts.push(`<text class="pit-hour" x="${cx}" y="${CHART_FLOOR + 20}">${esc(fmtDay(b.date, { weekday: 'narrow' }))}</text>`);
      parts.push(`<text class="pit-staff" x="${cx}" y="${CHART_FLOOR + 36}">${Number(b.date.slice(8))}</text></g>`);
    });
    parts.push('</svg>');
    return parts.join('');
  }

  /** This Monday-to-Sunday week: what happened, what is still expected, against last week. */
  function weekOutlook(data, metric) {
    const guests = metric === 'guests';
    const monday = isoAdd(data.focus_date, -mondayIndex(data.focus_date));
    const within = (iso, start) => iso >= start && iso <= isoAdd(start, 6);
    const fmt = guests ? (v) => `${fmtInt(v)} walk-ins` : fmtMoney;
    const done = data.days.filter((d) => within(d.date, monday));
    const doneDates = new Set(done.map((d) => d.date));
    const expected = (data.next_days || []).filter((d) => within(d.date, monday) && !doneDates.has(d.date));
    const previous = data.days.filter((d) => within(d.date, isoAdd(monday, -7)) && !d.in_progress);
    const soFar = done.reduce((sum, d) => sum + ((guests ? d.guests : d.net_revenue) || 0), 0);
    const still = expected.reduce((sum, d) => sum + ((guests ? d.expected_guests : d.expected_revenue) || 0), 0);
    const before = previous.reduce((sum, d) => sum + ((guests ? d.guests : d.net_revenue) || 0), 0);
    const range = `${fmtDay(monday, { month: 'short', day: 'numeric' })} to ${fmtDay(isoAdd(monday, 6), { month: 'short', day: 'numeric' })}`;
    let text = `This week, ${range}: ${fmt(soFar)} so far`;
    if (expected.length) {
      text += ` and ${fmt(still)} expected over the ${expected.length} day${expected.length === 1 ? '' : 's'} left, ${fmt(soFar + still)} in all`;
    }
    text += '.';
    if (previous.length && before > 0) {
      const pct = ((soFar + still - before) / before) * 100;
      const partial = previous.length < 7 ? ` over its ${previous.length} reported days` : '';
      text += ` Last week had ${fmt(before)}${partial}, so this week is heading for ${Math.abs(pct).toFixed(0)}% ${pct >= 0 ? 'more' : 'less'}.`;
    }
    return text;
  }

  function timelineSection(data) {
    const chart = timelineChart(data, state.metric);
    if (!chart) return '';
    const toggle = [['net_revenue', 'Revenue'], ['guests', 'Walk-ins']]
      .map(([key, label]) => `<button type="button" data-metric="${key}" aria-pressed="${state.metric === key}">${label}</button>`)
      .join('');
    const legend = `<p class="pit-legend">
        <span class="key"><span class="swatch actual"></span>Actual</span>
        <span class="key"><span class="swatch live"></span>Today so far</span>
        <span class="key"><span class="swatch projected"></span>Expected</span>
        ${state.metric === 'guests' ? '<span class="key"><span class="swatch booked"></span>Already booked</span>' : ''}
        <span class="key"><span class="dash"></span>Forecast made before the day</span>
      </p>`;
    return section(
      'Three weeks at a glance',
      'The last two weeks as they happened, against the forecast made before each day, then the next 7 days as expected now.',
      `<div class="seg" role="group" aria-label="Measure">${toggle}</div><div class="tl">${chart}</div>${legend}
       <p class="tl-week">${esc(weekOutlook(data, state.metric))}</p>`,
    );
  }

  /** Days down, hours across; each cell shaded by walk-ins, outlined when more staff are scheduled than the labor budget pays for. */
  function heatGrid(rows, { tone, value, label, cellTitle, cut }) {
    const hours = [...new Set(rows.flatMap((r) => r.hours.map((h) => h.hour)))].sort((a, b) => a - b);
    const peak = Math.max(1, ...rows.flatMap((r) => r.hours.map((h) => value(h) || 0)));
    const head = `<div class="heat-corner"></div>${hours.map((h) => `<div class="heat-head">${fmtHour(h)}</div>`).join('')}`;
    const body = rows.map((r) => {
      const byHour = new Map(r.hours.map((h) => [h.hour, h]));
      const cells = hours.map((hour) => {
        const h = byHour.get(hour);
        if (!h) return '<div class="heat-cell is-closed" aria-hidden="true"></div>';
        const fewer = cut ? cut(h) : 0;
        return `<div class="heat-cell${fewer > 0 ? ' is-over' : ''}" data-tint="${((value(h) || 0) / peak).toFixed(3)}" data-tone="${tone}" title="${esc(cellTitle(r, h))}">`
          + `<span>${fmtInt(value(h))}</span>${fewer > 0 ? `<span class="heat-cut">−${fewer}</span>` : ''}</div>`;
      }).join('');
      return `<div class="heat-label">${label(r)}</div>${cells}`;
    }).join('');
    return `<div class="heat-scroll"><div class="heat" data-cols="${hours.length}">${head}${body}</div></div>`;
  }

  function aheadHeatmap(data) {
    const rows = (data.next_days || []).filter((d) => (d.hours || []).length);
    if (!rows.length) return '';
    const grid = heatGrid(rows, {
      tone: 'pink',
      value: (h) => h.on_floor,
      cut: (h) => (h.staff_scheduled || 0) - (isNum(h.recommended) ? h.recommended : (h.staff_scheduled || 0)),
      label: (r) => esc(fmtDay(r.date, { weekday: 'short', month: 'short', day: 'numeric' })),
      cellTitle: (r, h) => `${fmtDayShort(r.date)} ${fmtHour(h.hour)}: about ${fmtInt(h.on_floor)} walk-ins on the floor, ${h.staff_scheduled} staff scheduled, ${h.recommended} within the labor budget`,
    });
    return section(
      'Next 7 days, hour by hour',
      'Expected walk-ins on the floor each hour; darker is busier. An outlined hour has more staff scheduled than its share of the labor budget pays for, and the small number is how many fewer are enough.',
      grid,
    );
  }

  function usualWeekSection(data) {
    const usual = data.usual_week;
    if (!usual || !usual.weekdays || !usual.weekdays.length) return '';
    const grid = heatGrid(usual.weekdays, {
      tone: 'sky',
      value: (h) => h.arrivals,
      label: (r) => `${WEEKDAY_NAMES[r.weekday]} <span class="muted">${r.days} day${r.days === 1 ? '' : 's'}</span>`,
      cellTitle: (r, h) => `${WEEKDAY_NAMES[r.weekday]} ${fmtHour(h.hour)}: ${h.arrivals} walk-ins arriving on average, ${h.on_floor} on the floor`,
    });
    return section(
      'A usual week',
      `Average walk-ins arriving each hour on each weekday, from the ${usual.days} reported days in the last six weeks. Darker is busier.`,
      grid,
    );
  }

  // ------------------------------------------------------------------ forecast explanations

  const MADE_BY = {
    eod: 'by the end-of-day report',
    midday: 'by the mid-day check-in',
    morning: 'by the morning report',
    reconstructed: 'rebuilt as of midnight from the bookings then on the books',
  };

  function comparableBasis(date, comparable) {
    const reported = (comparable.days || []).filter((d) => d.reported).length;
    if (comparable.rule === 'holiday_weekends') return `${reported} recent weekend day${reported === 1 ? '' : 's'}`;
    const weekday = fmtDay(date, { weekday: 'long' });
    return reported === 1 ? `the last ${weekday}` : `the last ${reported} ${weekday}s`;
  }

  function madeText(why, tz) {
    if (!why.made_at) return 'When it was made was not recorded.';
    return `Made ${fmtStamp(why.made_at, tz)}${MADE_BY[why.made_by] ? ` ${MADE_BY[why.made_by]}` : ''}.`;
  }

  function whyTeaser(data, day) {
    const why = day && day.forecast && day.forecast.why;
    if (!why) return '';
    const comparable = why.comparable || {};
    let text = `The forecast of ${fmtInt(why.guests)} walk-ins was made ${why.made_at ? fmtStamp(why.made_at, data.timezone) : 'before opening'} from ${comparableBasis(day.date, comparable)}`;
    if (isNum(comparable.avg_guests)) text += ` (${fmtInt(comparable.avg_guests)} walk-ins on average)`;
    if (isNum(why.booked_guests)) text += ` and the ${fmtInt(why.booked_guests)} walk-ins already booked`;
    text += '.';
    const outcome = day.forecast.outcome;
    if (outcome && outcome.hours && outcome.hours.length) {
      const h = outcome.hours[0];
      text += ` The biggest difference was ${fmtHour(Number(h.name))}: ${fmtInt(h.actual)} arrived against ${fmtInt(h.expected)} expected.`;
    }
    return `<div class="wrap why-teaser"><p>${esc(text)} <button type="button" class="btn-link" data-goto="forecasts" data-date="${day.date}">See why</button></p></div>`;
  }

  /** The comparable days' walk-ins as bars, their average as a line, then the forecast with its booked share. */
  function comparableChart(why) {
    const days = (why.comparable.days || []).slice().reverse();
    const cols = [
      ...days.map((d) => ({ label: fmtDay(d.date, { month: 'short', day: 'numeric' }), value: d.reported ? d.guests : null, kind: 'past' })),
      { label: 'Forecast', value: why.guests, kind: 'forecast' },
    ];
    const width = 420;
    const height = 200;
    const top = 24;
    const floor = 164;
    const avg = why.comparable.avg_guests;
    const max = Math.max(1, avg || 0, ...cols.map((c) => c.value || 0)) * 1.12;
    const y = (v) => floor - (Math.max(0, v) / max) * (floor - top);
    const step = width / cols.length;
    const barW = step * 0.56;
    const parts = [`<svg class="cmp-svg" viewBox="0 0 ${width} ${height}" role="img" aria-label="${esc(`Walk-ins on the comparable days and the forecast of ${fmtInt(why.guests)}`)}">`,
      `<line class="pit-floor" x1="0" x2="${width}" y1="${floor}" y2="${floor}"></line>`];
    cols.forEach((c, i) => {
      const x = step * i + (step - barW) / 2;
      const cx = step * i + step / 2;
      if (isNum(c.value)) {
        parts.push(`<rect class="cmp-bar ${c.kind}" x="${x.toFixed(1)}" y="${y(c.value).toFixed(1)}" width="${barW.toFixed(1)}" height="${(floor - y(c.value)).toFixed(1)}" rx="6"></rect>`);
        if (c.kind === 'forecast' && isNum(why.booked_guests) && why.booked_guests > 0) {
          const booked = Math.min(why.booked_guests, c.value);
          parts.push(`<rect class="cmp-booked" x="${x.toFixed(1)}" y="${y(booked).toFixed(1)}" width="${barW.toFixed(1)}" height="${(floor - y(booked)).toFixed(1)}" rx="6"></rect>`);
        }
        parts.push(`<text class="tl-value" x="${cx.toFixed(1)}" y="${(y(c.value) - 6).toFixed(1)}">${fmtInt(c.value)}</text>`);
      } else {
        parts.push(`<text class="pit-staff" x="${cx.toFixed(1)}" y="${floor - 8}">not reported</text>`);
      }
      parts.push(`<text class="pit-hour" x="${cx.toFixed(1)}" y="${floor + 20}">${esc(c.label)}</text>`);
    });
    if (isNum(avg)) {
      const ay = y(avg).toFixed(1);
      parts.push(`<line class="cmp-avg" x1="0" x2="${(step * days.length).toFixed(1)}" y1="${ay}" y2="${ay}"></line>`);
      parts.push(`<text class="cmp-avg-label" x="4" y="${(Number(ay) - 6).toFixed(1)}">Average ${fmtInt(avg)}</text>`);
    }
    parts.push('</svg>');
    return parts.join('');
  }

  function whySection(data, date, day, ahead) {
    const why = (day && day.forecast && day.forecast.why) || (ahead && ahead.why) || null;
    if (!why) {
      if (day && !day.forecast) {
        return section('Why the forecast said what it did', '', '<p class="muted">No forecast was saved before this day began, so there is nothing to explain for it.</p>');
      }
      return '';
    }
    const comparable = why.comparable || { days: [] };
    const title = day
      ? `Why the forecast said ${fmtInt(why.guests)} walk-ins and ${fmtMoney(why.revenue)}`
      : `Why ${fmtDayLong(date)} is expected to bring ${fmtInt(why.guests)} walk-ins`;
    const ruleText = comparable.rule === 'holiday_weekends'
      ? 'It is a weekday holiday, so the forecast learned from recent weekend days, when traffic behaves the same way.'
      : `It learned from ${comparableBasis(date, comparable)}, skipping holidays.`;
    const rows = (comparable.days || []).map((d) => `<tr><td>${esc(fmtDayShort(d.date))}</td>
      <td>${d.reported ? fmtInt(d.guests) : '<span class="muted">not reported</span>'}</td>
      <td>${d.reported ? fmtMoney(d.net_revenue) : DASH}</td><td>${d.reported ? fmtInt(d.walk_ins) : DASH}</td></tr>`).join('');
    const bookings = `${fmtInt(why.advance_bookings)} booking${why.advance_bookings === 1 ? '' : 's'}`;
    const guestsStep = isNum(why.booked_guests)
      ? `${fmtInt(why.booked_guests)} walk-ins were already booked (${bookings}), and about ${fmtInt(why.walk_in_guests)} more were expected on the day, hour by hour, as on the comparable days.`
      : `Walk-ins are what was booked (${bookings}) plus the usual same-day arrivals for each hour on the comparable days.`;
    const factor = isNum(why.revenue_factor) ? why.revenue_factor.toFixed(2) : DASH;
    const revenueStep = {
      scaled: `Revenue of ${fmtMoney(why.revenue)} is the comparable days' average of ${fmtMoney(comparable.avg_revenue)}, scaled by expected walk-ins against their average (x${factor}).`,
      bookings: `Bookings already came to more than a normal day, so revenue of ${fmtMoney(why.revenue)} is the booked value.`,
      no_history: `No comparable days were reported yet, so revenue of ${fmtMoney(why.revenue)} is only what was booked.`,
    }[why.revenue_rule] || '';
    const peaks = (why.peak_hours || []).map((p) => `${fmtHour(p.hour)} (${fmtInt(p.arrivals)})`).join(', ');
    const equation = isNum(why.booked_guests)
      ? `<span class="term"><strong>${fmtInt(why.booked_guests)}</strong> already booked</span><span class="op" aria-hidden="true">+</span>
         <span class="term"><strong>${fmtInt(why.walk_in_guests)}</strong> expected on the day</span><span class="op" aria-hidden="true">=</span>`
      : '';
    const body = `
      <p class="section-lede">${esc(madeText(why, data.timezone))} ${esc(ruleText)}</p>
      <div class="equation">${equation}<span class="term"><strong>${fmtInt(why.guests)}</strong> walk-ins</span>
        <span class="term"><strong>${fmtMoney(why.revenue)}</strong> net revenue</span></div>
      <div class="why-grid">
        <div>
          <h3 class="fig-title">What it learned from</h3>
          ${comparableChart(why)}
          <div class="table-wrap"><table class="compact"><thead><tr><th scope="col">Day</th><th scope="col">Walk-ins</th><th scope="col">Net revenue</th><th scope="col">Same-day bookings</th></tr></thead>
            <tbody>${rows}<tr class="total"><td>Average</td><td>${fmtInt(comparable.avg_guests)}</td><td>${fmtMoney(comparable.avg_revenue)}</td><td></td></tr></tbody></table></div>
        </div>
        <div>
          <h3 class="fig-title">How it got there</h3>
          <ol class="list-steps">
            <li>${esc(guestsStep)}</li>
            <li>${esc(revenueStep)}</li>
            ${peaks ? `<li>${esc(`Busiest hours expected, walk-ins arriving: ${peaks}.`)}</li>` : ''}
            <li>${esc(`Labor at ${fmtPct(why.labor_pct)} of revenue with ${fmtHours(why.scheduled_hours)} scheduled in 7shifts.`)}</li>
          </ol>
        </div>
      </div>`;
    return section(title, '', body);
  }

  function reasonRows(rows, label, describe) {
    if (!rows || !rows.length) return '';
    const peak = Math.max(1, ...rows.map((r) => Math.abs(r.change)));
    return rows.map((r) => `<li><span class="reason-name">${esc(label(r.name))}</span>
        <span class="reason-bar" aria-hidden="true"><span class="${r.change > 0 ? 'up' : 'down'}" data-width="${((Math.abs(r.change) / peak) * 0.5).toFixed(4)}"></span></span>
        <span class="reason-text">${esc(describe(r))}</span></li>`).join('');
  }

  function outcomeSection(data, day) {
    const outcome = day && day.forecast && day.forecast.outcome;
    if (!outcome) return '';
    const g = outcome.guests;
    const rev = outcome.revenue;
    const direction = g.change > 0 ? 'busier than' : g.change < 0 ? 'quieter than' : 'the same as';
    const weekday = fmtDay(day.date, { weekday: 'long' });
    const pct = isNum(g.change_pct) ? `, ${fmtSigned(g.change_pct, (v) => `${v.toFixed(0)}%`)}` : '';
    const lede = `${fmtInt(g.actual)} walk-ins came against ${fmtInt(g.expected)} expected (${fmtSigned(g.change, fmtInt)}${pct}), and net revenue was ${fmtMoney(rev.actual)} against ${fmtMoney(rev.expected)} (${fmtSigned(rev.change, fmtMoney)}).`;
    const blocks = [
      ['Arrivals by hour', reasonRows(outcome.hours, (n) => fmtHour(Number(n)),
        (r) => `${fmtInt(r.actual)} arrived, ${fmtInt(r.expected)} expected (${fmtSigned(r.change, fmtInt)})`)],
      ['Revenue by category', reasonRows(outcome.revenue_categories, categoryLabel,
        (r) => `${fmtMoney(r.actual)} against ${fmtMoney(r.expected)} forecast (${fmtSigned(r.change, fmtMoney)})`)],
      [`Who came, against a usual ${weekday}`, reasonRows(outcome.guest_groups, groupLabel,
        (r) => `${fmtInt(r.actual)} against ${fmtInt(r.expected)} usually (${fmtSigned(r.change, fmtInt)})`)],
    ].filter(([, html]) => html)
      .map(([heading, html]) => `<div><h3 class="fig-title">${esc(heading)}</h3><ul class="reason-list">${html}</ul></div>`)
      .join('');
    const booked = outcome.advance_bookings || {};
    const walk = outcome.walk_ins || {};
    const extra = `Advance bookings: ${fmtInt(booked.when_forecast)} on the books when the forecast was made, ${fmtInt(booked.on_the_day)} by the day. Same-day bookings: ${fmtInt(walk.on_the_day)}${isNum(walk.usual) ? ` against a usual ${fmtInt(walk.usual)}` : ''}.`;
    return section(`What made ${fmtDayLong(day.date)} ${direction} forecast`, lede,
      `<div class="why-grid">${blocks}</div><p class="section-lede outcome-extra">${esc(extra)}</p>`, 'band-lilac');
  }

  // ------------------------------------------------------------------ trend figures

  const FIG = { w: 520, h: 230, left: 48, right: 14, top: 18, bottom: 38 };
  const CATEGORY_ORDER = ['admission', 'party', 'stock', 'membership', 'other'];

  function niceMax(value) {
    if (!(value > 0)) return 1;
    const power = 10 ** Math.floor(Math.log10(value));
    return Math.ceil((value * 1.08) / power) * power;
  }

  function frame(max, fmt, labels, every) {
    const step = (FIG.w - FIG.left - FIG.right) / labels.length;
    const y = (v) => FIG.top + (1 - Math.max(0, Math.min(v, max)) / max) * (FIG.h - FIG.top - FIG.bottom);
    const x = (i) => FIG.left + step * (i + 0.5);
    const grid = [0, 0.5, 1].map((f) => `<line class="ax-grid" x1="${FIG.left}" x2="${FIG.w - FIG.right}" y1="${y(max * f).toFixed(1)}" y2="${y(max * f).toFixed(1)}"></line>`
      + `<text class="ax-label y" x="${FIG.left - 6}" y="${(y(max * f) + 4).toFixed(1)}">${esc(fmt(max * f))}</text>`).join('');
    const ticks = labels.map((label, i) => (i % every === 0 || i === labels.length - 1
      ? `<text class="ax-label x" x="${x(i).toFixed(1)}" y="${FIG.h - FIG.bottom + 18}">${esc(label)}</text>` : '')).join('');
    return { x, y, step, svg: grid + ticks };
  }

  const svgOpen = (label) => `<svg class="fig-svg" viewBox="0 0 ${FIG.w} ${FIG.h}" role="img" aria-label="${esc(label)}">`;
  const shortDate = (iso) => fmtDay(iso, { month: 'numeric', day: 'numeric' });
  const legendKey = (shape, cls, label) => `<span class="key"><span class="${shape} ${cls}"></span>${esc(label)}</span>`;

  function pathOf(points) {
    let d = '';
    let pen = false;
    for (const p of points) {
      if (!p) {
        pen = false;
        continue;
      }
      d += `${pen ? 'L' : 'M'}${p.x.toFixed(1)} ${p.y.toFixed(1)} `;
      pen = true;
    }
    return d.trim();
  }

  function figure(title, lede, svg, legend) {
    return `<figure class="fig"><h3 class="fig-title">${esc(title)}</h3>${lede ? `<p class="fig-lede">${esc(lede)}</p>` : ''}${svg}
      ${legend ? `<p class="pit-legend">${legend}</p>` : ''}</figure>`;
  }

  function paceFigure(data, day) {
    const rows = data.hourly[day.date] || [];
    if (!rows.some((r) => isNum(r.forecast_arrivals)) || !rows.some((r) => isNum(r.arrivals))) return '';
    let arrived = 0;
    let expected = 0;
    const actual = rows.map((r) => (!r.expected && isNum(r.arrivals) ? (arrived += r.arrivals) : null));
    const forecast = rows.map((r) => (isNum(r.forecast_arrivals) ? (expected += r.forecast_arrivals) : null));
    const max = niceMax(Math.max(arrived, expected));
    const fr = frame(max, fmtInt, rows.map((r) => fmtHour(r.hour)), rows.length > 8 ? 2 : 1);
    const points = (values) => values.map((v, i) => (isNum(v) ? { x: fr.x(i), y: fr.y(v) } : null));
    const svg = `${svgOpen(`Running total of walk-ins arriving on ${fmtDayLong(day.date)} against the forecast`)}${fr.svg}
      <path class="ln forecast" d="${pathOf(points(forecast))}"></path><path class="ln actual" d="${pathOf(points(actual))}"></path></svg>`;
    return figure('Walk-ins through the day', `${fmtInt(arrived)} arrived ${day.in_progress && !day.after_close ? 'so far ' : ''}against ${fmtInt(expected)} in the forecast for the whole day.`, svg,
      legendKey('dash-key', 'actual', 'Arrived') + legendKey('dash-key', 'forecast', 'Forecast'));
  }

  function missFigure(data) {
    const days = data.days.filter((d) => d.forecast && !d.in_progress && isNum(d.forecast.guests) && d.forecast.guests > 0).slice(-TIMELINE_PAST_DAYS);
    if (days.length < 2) return '';
    const values = days.map((d) => ((d.guests - d.forecast.guests) / d.forecast.guests) * 100);
    const limit = niceMax(Math.min(200, Math.max(10, ...values.map((v) => Math.abs(v)))));
    const mid = (FIG.top + FIG.h - FIG.bottom) / 2;
    const y = (v) => mid - (Math.max(-limit, Math.min(limit, v)) / limit) * (mid - FIG.top);
    const step = (FIG.w - FIG.left - FIG.right) / days.length;
    const barW = step * 0.6;
    const grid = [limit, 0, -limit].map((v) => `<line class="${v === 0 ? 'zero' : 'ax-grid'}" x1="${FIG.left}" x2="${FIG.w - FIG.right}" y1="${y(v).toFixed(1)}" y2="${y(v).toFixed(1)}"></line>`
      + `<text class="ax-label y" x="${FIG.left - 6}" y="${(y(v) + 4).toFixed(1)}">${v > 0 ? '+' : v < 0 ? MINUS : ''}${Math.abs(v)}%</text>`).join('');
    const bars = days.map((d, i) => {
      const v = values[i];
      const top = Math.min(y(v), mid);
      const x = FIG.left + step * i + (step - barW) / 2;
      const label = `${fmtDayShort(d.date)}: ${fmtInt(d.guests)} walk-ins against ${fmtInt(d.forecast.guests)} forecast (${fmtSigned(v, (n) => `${n.toFixed(0)}%`)})`;
      const tick = i % 2 === 0 || i === days.length - 1 ? `<text class="ax-label x" x="${(x + barW / 2).toFixed(1)}" y="${FIG.h - FIG.bottom + 18}">${esc(shortDate(d.date))}</text>` : '';
      return `<rect class="${v >= 0 ? 'bar-up' : 'bar-down'}" x="${x.toFixed(1)}" y="${top.toFixed(1)}" width="${barW.toFixed(1)}" height="${Math.max(1, Math.abs(y(v) - mid)).toFixed(1)}" rx="3"><title>${esc(label)}</title></rect>${tick}`;
    }).join('');
    const busier = values.filter((v) => v > 0).length;
    return figure('Busier or quieter than forecast', `Walk-ins against the forecast made before each day: ${busier} of ${days.length} days came in busier.`,
      `${svgOpen('Each day\'s walk-ins against its forecast, in percent')}${grid}${bars}</svg>`,
      legendKey('dot', 'bar-up-key', 'Busier than forecast') + legendKey('dot', 'bar-down-key', 'Quieter than forecast'));
  }

  function stackedFigure(title, lede, columns, keys, fmt, label) {
    const totals = columns.map((c) => keys.reduce((sum, k) => sum + (c.parts[k.key] || 0), 0));
    if (!totals.some((t) => t > 0)) return '';
    const fr = frame(niceMax(Math.max(...totals)), fmt, columns.map((c) => shortDate(c.date)), 2);
    const barW = Math.max(4, fr.step * 0.62);
    const bars = columns.map((c, i) => {
      let base = 0;
      return keys.map((k) => {
        const v = c.parts[k.key] || 0;
        if (v <= 0) return '';
        const top = fr.y(base + v);
        const bottom = fr.y(base);
        base += v;
        return `<rect class="${k.fill}" x="${(fr.x(i) - barW / 2).toFixed(1)}" y="${top.toFixed(1)}" width="${barW.toFixed(1)}" height="${Math.max(0.5, bottom - top).toFixed(1)}"><title>${esc(`${fmtDayShort(c.date)}, ${k.label}: ${fmt(v)}`)}</title></rect>`;
      }).join('');
    }).join('');
    const shown = keys.filter((k) => columns.some((c) => (c.parts[k.key] || 0) > 0));
    return figure(title, lede, `${svgOpen(label)}${fr.svg}${bars}</svg>`, shown.map((k) => legendKey('dot', k.dot, k.label)).join(''));
  }

  function guestMixFigure(data) {
    const days = data.days.slice(-TIMELINE_PAST_DAYS);
    return stackedFigure('Who came, day by day', 'People by pass type over the last two weeks.',
      days.map((d) => ({ date: d.date, parts: d.guests_by_group || {} })),
      GUEST_GROUPS.map((g) => ({ key: g.key, label: g.label, fill: `fill-${g.key}`, dot: g.cls })), fmtInt,
      'People by pass type for each of the last two weeks');
  }

  function revenueMixFigure(data) {
    const days = data.days.slice(-TIMELINE_PAST_DAYS).map((d) => {
      const parts = {};
      for (const [name, value] of Object.entries(d.revenue_by_category || {})) {
        const key = CATEGORY_ORDER.includes(name) ? name : 'other';
        parts[key] = (parts[key] || 0) + (value || 0);
      }
      return { date: d.date, parts };
    });
    return stackedFigure('Where the money came from', 'Net revenue by category over the last two weeks.', days,
      CATEGORY_ORDER.map((k) => ({ key: k, label: categoryLabel(k), fill: `fill-cat-${k}`, dot: `cat-${k}` })), fmtMoneyShort,
      'Net revenue by category for each of the last two weeks');
  }

  function laborFigure(data) {
    const past = data.days.filter((d) => !d.in_progress).slice(-TIMELINE_PAST_DAYS);
    const ahead = data.next_days || [];
    const cols = [...past.map((d) => ({ date: d.date, actual: d.labor_pct, expected: null })),
      ...ahead.map((d) => ({ date: d.date, actual: null, expected: d.expected_labor_pct }))];
    const values = cols.flatMap((c) => [c.actual, c.expected]).filter(isNum);
    if (values.length < 2) return '';
    const target = data.targets.labor_pct;
    const max = niceMax(Math.min(120, Math.max(target, ...values)));
    const fr = frame(max, (v) => `${Math.round(v)}%`, cols.map((c) => shortDate(c.date)), 3);
    const actual = cols.map((c, i) => (isNum(c.actual) ? { x: fr.x(i), y: fr.y(c.actual) } : null));
    const joinAt = past.length - 1;
    const expected = cols.map((c, i) => {
      if (isNum(c.expected)) return { x: fr.x(i), y: fr.y(c.expected) };
      return i === joinAt && isNum(c.actual) ? { x: fr.x(i), y: fr.y(c.actual) } : null;
    });
    const ty = fr.y(target).toFixed(1);
    const svg = `${svgOpen('Labor as a percentage of net revenue for each day, with the target')}${fr.svg}
      <line class="ln target" x1="${FIG.left}" x2="${FIG.w - FIG.right}" y1="${ty}" y2="${ty}"></line>
      <path class="ln expected" d="${pathOf(expected)}"></path><path class="ln actual" d="${pathOf(actual)}"></path></svg>`;
    const over = past.filter((d) => isNum(d.labor_pct) && d.labor_pct > target).length;
    return figure('Labor as a share of revenue', `Target ${fmtPct(target)}; ${over} of the last ${past.length} days were above it. The dotted line is the next 7 days with the staff scheduled now.`, svg,
      legendKey('dash-key', 'actual', 'Actual') + legendKey('dash-key', 'expected', 'Expected') + legendKey('dash-key', 'target', 'Target'));
  }

  function figuresSection(data, day) {
    const figures = [day ? paceFigure(data, day) : '', missFigure(data), guestMixFigure(data), revenueMixFigure(data), laborFigure(data)]
      .filter(Boolean);
    if (!figures.length) return '';
    return section('Trends', 'How the day built up, how close the forecasts came, and what the last two weeks were made of.', `<div class="figs">${figures.join('')}</div>`);
  }

  const TAB_RENDERERS = {
    overview: overviewTab,
    guests: guestsTab,
    revenue: revenueTab,
    staff: staffTab,
    calendar: calendarTab,
    forecasts: forecastsTab,
    analysis: analysisTab,
    updates: updatesTab,
  };

  // ------------------------------------------------------------------ events

  function setFocus(date, scroll) {
    const { data } = state;
    if (!date || date < firstDate(data) || date > lastDate(data)) return;
    state.focus = date;
    state.showAllAttention = false;
    render(true);
    if (scroll) $('#panel').scrollIntoView({ behavior: prefersReducedMotion() ? 'auto' : 'smooth', block: 'start' });
    const title = $('#day-title');
    if (title) title.focus({ preventScroll: true });
  }

  function setTab(id) {
    if (!TAB_RENDERERS[id]) return;
    state.tab = id;
    render(false);
    const tab = $(`#tab-${id}`);
    if (tab) tab.focus();
  }

  function onAppClick(event) {
    if (!event.target.closest('.info-btn, .info-tip')) closeInfo();
    const el = event.target.closest('[data-goto], [data-tab], [data-focus], [data-shift], [data-metric], [data-action]');
    if (!el || el.disabled) return;
    if (el.dataset.goto) {
      state.tab = el.dataset.goto;
      setFocus(el.dataset.date || state.focus, true);
    } else if (el.dataset.tab) setTab(el.dataset.tab);
    else if (el.dataset.focus) setFocus(el.dataset.focus, true);
    else if (el.dataset.shift) setFocus(isoAdd(state.focus, Number(el.dataset.shift)), false);
    else if (el.dataset.metric) {
      state.metric = el.dataset.metric;
      render(false);
    } else if (el.dataset.action === 'info') toggleInfo(el);
    else if (el.dataset.action === 'sign-out') signOut();
    else if (el.dataset.action === 'latest') setFocus(state.data.focus_date, false);
    else if (el.dataset.action === 'show-all-attention') {
      state.showAllAttention = true;
      render(false);
    }
  }

  function onAppChange(event) {
    if (event.target.id === 'pick-date') setFocus(event.target.value, false);
  }

  function onAppKeydown(event) {
    if (event.key === 'Escape') closeInfo();
    const tab = event.target.closest('.tab');
    if (!tab || !['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
    event.preventDefault();
    const index = TABS.findIndex((t) => t.id === tab.dataset.tab);
    const next = event.key === 'Home' ? 0
      : event.key === 'End' ? TABS.length - 1
        : (index + (event.key === 'ArrowRight' ? 1 : -1) + TABS.length) % TABS.length;
    setTab(TABS[next].id);
  }

  document.addEventListener('DOMContentLoaded', () => {
    $('#login-form').addEventListener('submit', onLogin);
    const app = $('#app');
    app.addEventListener('click', onAppClick);
    app.addEventListener('change', onAppChange);
    app.addEventListener('keydown', onAppKeydown);
    if (!window.crypto || !crypto.subtle || typeof DecompressionStream === 'undefined') {
      showLogin('This browser cannot open the dashboard. Update it, or use a current Chrome, Safari, Edge or Firefox.');
      $('#login-button').disabled = true;
      return;
    }
    boot();
  });
})();
