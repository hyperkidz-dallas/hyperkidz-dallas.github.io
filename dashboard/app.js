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
  const DASH = '–';
  const MINUS = '−';

  const TABS = [
    { id: 'overview', label: 'Overview' },
    { id: 'guests', label: 'Guests' },
    { id: 'revenue', label: 'Revenue' },
    { id: 'staff', label: 'Staff' },
    { id: 'calendar', label: 'Calendar' },
    { id: 'forecasts', label: 'Forecasts' },
    { id: 'analysis', label: "Claude's analysis" },
    { id: 'updates', label: 'Updates' },
  ];
  const MODE_NAMES = { morning: 'Morning report', midday: 'Mid-day check-in', eod: 'End of day' };
  const STATUS = {
    under: { cls: 'under', label: 'Short-staffed' },
    ok: { cls: 'ok', label: 'On target' },
    over: { cls: 'over', label: 'Extra staff' },
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
    food: 'Food',
    retail: 'Retail',
    membership: 'Memberships',
    other: 'Fees and other',
  };
  /** Guest groups in display order; keys are src.config.GuestGroup values. */
  const GUEST_GROUPS = [
    { key: 'children', label: 'Children 3-13', cls: 'grp-children' },
    { key: 'toddlers', label: 'Toddlers 1-2', cls: 'grp-toddlers' },
    { key: 'infants', label: 'Infants under 1', cls: 'grp-infants' },
    { key: 'other_passes', label: 'Other kid passes', cls: 'grp-other' },
    { key: 'party_guests', label: 'Party guests', cls: 'grp-party' },
    { key: 'adults', label: 'Adults', cls: 'grp-adults' },
  ];

  const encoder = new TextEncoder();
  const $ = (selector, root = document) => root.querySelector(selector);
  const state = { data: null, focus: null, tab: 'overview', showAllAttention: false };

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
  const categoryLabel = (key) => CATEGORY_LABELS[key] || key;

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
      el.style.backgroundColor = `rgba(${TINT_RGB}, ${(0.08 + Number(el.dataset.tint) * 0.42).toFixed(3)})`;
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
    const link = safeLink(data.links && data.links.update);
    const update = link
      ? `<a class="btn-update" href="${esc(link)}" target="_blank" rel="noopener noreferrer">Update now</a>`
      : '';
    return `<header class="topbar wrap">
      <img class="topbar-logo" src="hyperkidz-logo.png" alt="Hyper Kidz" width="192" height="40">
      <div class="topbar-meta">
        ${stale}
        <span>Last updated ${esc(fmtStamp(data.generated_at, data.timezone))} ${esc(updatedBy(refresh))}.</span>
        ${update}
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
      ? `<p>Expected: ${fmtInt(ahead.expected_guests)} guests and ${fmtMoney(ahead.expected_revenue)} in net revenue, with labor at ${fmtPct(ahead.expected_labor_pct)} of revenue.</p>`
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
      const base = `By close: ${fmtInt(soFar.guests_so_far)} guests and ${fmtMoney(soFar.revenue_so_far)} in net revenue, pulled at ${fmtClock(soFar.as_of, data.timezone)}. The end-of-day report adds funds received and Claude's analysis.`;
      return day.forecast ? `${base} ${compareToForecast(day, day.forecast)}` : base;
    }
    if (day.in_progress && soFar) {
      let text = `So far today: ${fmtInt(soFar.guests_so_far)} guests and ${fmtMoney(soFar.revenue_so_far)} in net revenue by ${fmtClock(soFar.as_of, data.timezone)}.`;
      if (isNum(soFar.projected_guests_so_far)) {
        text += ` The forecast for these hours was ${fmtInt(soFar.projected_guests_so_far)} guests and ${fmtMoney(soFar.projected_revenue_so_far)}.`;
      }
      if (isNum(soFar.expected_total_guests)) {
        text += ` Expected at close: ${fmtInt(soFar.expected_total_guests)} guests and ${fmtMoney(soFar.expected_total_revenue)}, with labor at ${fmtPct(soFar.expected_close_labor_pct)} of revenue.`;
      }
      return text;
    }
    const base = `${fmtInt(day.guests)} guests and ${fmtMoney(day.net_revenue)} in net revenue.`;
    return day.forecast ? `${base} ${compareToForecast(day, day.forecast)}` : base;
  }

  function compareToForecast(day, forecast) {
    const parts = [];
    if (isNum(forecast.guests) && isNum(day.guests)) {
      const diff = Math.round(day.guests - forecast.guests);
      parts.push(diff === 0
        ? `guests matched the forecast of ${fmtInt(forecast.guests)}`
        : `${fmtInt(Math.abs(diff))} ${diff > 0 ? 'more' : 'fewer'} guests than the forecast of ${fmtInt(forecast.guests)}`);
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
      : forecast ? `Forecast ${fmtInt(forecast.guests)}` : `${fmtInt(day.walk_ins)} walk-ins`;
    const revenueNote = soFar
      ? `Expected at close ${fmtMoney(soFar.expected_total_revenue)}`
      : forecast ? `Forecast ${fmtMoney(forecast.revenue)}` : `After ${fmtMoney(day.refunds)} in refunds`;
    const rows = [
      ['Guests', fmtInt(day.guests), guestsNote],
      ['Passes booked', fmtInt(day.passes), 'Every pass, adults and memberships included'],
      ['Net revenue', fmtMoney(day.net_revenue), revenueNote],
      ['Funds received', fmtMoney(day.funds_received), isNum(day.funds_received) ? `Payments taken, ${fmtMoney(day.tips)} in tips left out` : 'Known after close'],
      ['Labor cost', fmtMoney(day.actual_labor), `${fmtPct(day.labor_pct)} of revenue, target ${fmtPct(data.targets.labor_pct)}`],
      ['Labor hours', fmtHours(day.actual_hours), `${fmtHours(day.scheduled_hours)} scheduled`],
    ];
    return `<dl class="numbers">${rows.map(([label, value, sub]) => `<div class="number"><dt>${esc(label)}</dt><dd>${esc(value)}<span class="sub">${esc(sub)}</span></dd></div>`).join('')}</dl>`;
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
      ${changeChip(change.guests, 'Guests')}${changeChip(change.passes, 'Passes')}${changeChip(change.net_revenue, 'Revenue')}
      ${changeChip(change.labor_pct, 'Labor', { points: true, lowerIsBetter: true })}
    </p>`).join('');
    return `<div class="wrap growth-wrap"><h2 class="section-title small">Growth</h2>${lines}${declineCallout(day)}</div>`;
  }

  function declineCallout(day) {
    const decline = day.growth && day.growth.decline;
    if (!decline) return '';
    const change = day.growth.vs_last_week;
    const fell = decline.metrics.map((m) => `${m === 'guests' ? 'guests' : 'revenue'} ${Math.abs(change[m]).toFixed(0)}%`).join(' and ');
    const drivers = decline.drivers || {};
    const parts = [
      ...(drivers.guest_groups || []).slice(0, 3).map((r) => `${groupLabel(r.name).toLowerCase()} ${fmtSigned(r.change, fmtInt)}`),
      ...(drivers.revenue_categories || []).slice(0, 3).map((r) => `${categoryLabel(r.name).toLowerCase()} ${fmtSigned(r.change, fmtMoney)}`),
      ...(drivers.hours || []).slice(0, 3).map((r) => `${fmtHour(Number(r.name))} arrivals ${fmtSigned(r.change, fmtInt)}`),
      ...(drivers.bookings || []).map((r) => `${r.name === 'walk_ins' ? 'walk-in bookings' : 'advance bookings'} ${fmtSigned(r.change, fmtInt)}`),
    ];
    return `<div class="callout" role="note"><strong>Down against ${esc(fmtDayLong(decline.baseline_date))}:</strong>
      ${esc(fell)} lower. Biggest drops: ${esc(parts.join('; ') || 'spread evenly across the day')}.</div>`;
  }

  function pitBlock(rows) {
    return `<div class="pit">${ballPit(rows)}</div>
      <p class="pit-legend">
        <span class="key"><span class="dot ok"></span>On target</span>
        <span class="key"><span class="dot under"></span>Short-staffed</span>
        <span class="key"><span class="dot over"></span>Extra staff</span>
        <span class="key"><span class="ring"></span>Forecast</span>
        <span>Ball size is the guests arriving in that hour.</span>
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
    if (!actual.length) return `Guests by hour ${span}`;
    const busiest = actual.reduce((a, b) => (b.arrivals > a.arrivals ? b : a));
    return `Guests arriving each hour ${span}. Busiest was ${fmtHour(busiest.hour)} with ${fmtInt(busiest.arrivals)} guests.`;
  }

  function hourTitle(row) {
    const parts = [fmtHour(row.hour)];
    if (isNum(row.arrivals)) parts.push(`${fmtInt(row.arrivals)} guests arrived`);
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
       <button type="button" class="btn-quiet" data-tab="analysis">Read all of Claude's analysis</button>`,
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
      growthBlock(day),
      analysisTeaser(data, date),
      attentionSection(data, date, ATTENTION_PREVIEW),
      aheadSection(data),
    ].join('');
  }

  // ------------------------------------------------------------------ guests

  function guestMix(day) {
    const groups = day.guests_by_group || {};
    const rows = GUEST_GROUPS.map((g) => ({ ...g, count: groups[g.key] || 0 })).filter((g) => g.count > 0);
    if (!rows.length) return '<p class="muted">No guest breakdown was stored for this day.</p>';
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
      ['Guests', fmtInt(day.guests)],
      ['Passes booked', fmtInt(day.passes)],
      ['Walk-in bookings', fmtInt(day.walk_ins)],
      ['Advance bookings', fmtInt(day.advance_bookings)],
      ['Memberships sold', fmtInt(day.memberships_sold)],
    ];
    const hours = data.hourly[day.date] || [];
    const hourRows = hours.map((r) => `<tr class="${r.expected ? 'is-expected' : ''}"><td>${fmtHour(r.hour)}${r.expected ? ' <span class="muted">expected</span>' : ''}</td>
      <td>${fmtInt(r.arrivals)}</td><td>${fmtInt(r.forecast_arrivals)}</td><td>${fmtInt(r.on_floor)}</td></tr>`).join('');
    return [
      `<section class="day wrap" aria-labelledby="day-title">${navDayTitle(data, day)}
        <dl class="kv">${numbers.map(([k, v]) => `<div><dt>${esc(k)}</dt><dd>${esc(v)}</dd></div>`).join('')}</dl>
      </section>`,
      section('Who came', 'People by pass type, read from the ROLLER pass names. Adults are not counted as guests.', `${guestMix(day)}
        ${groupRows ? `<div class="table-wrap"><table><thead><tr><th scope="col">Group</th><th scope="col">This day</th>
        <th scope="col">${lastWeek ? esc(fmtDayShort(lastWeek.date)) : 'Last week'}</th><th scope="col">Change</th></tr></thead>
        <tbody>${groupRows}</tbody></table></div>` : ''}`),
      hours.length ? section('Guests by hour', 'Arrivals each hour against the forecast, and how many were on the floor.', `<div class="table-wrap"><table>
        <thead><tr><th scope="col">Hour</th><th scope="col">Arrived</th><th scope="col">Forecast</th><th scope="col">On the floor</th></tr></thead>
        <tbody>${hourRows}</tbody></table></div>`) : '',
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
    const categoryRows = names.map((name) => `<tr><td>${esc(categoryLabel(name))}</td><td>${fmtMoney(categories[name] || 0)}</td>
      <td>${gross ? fmtPct(((categories[name] || 0) / gross) * 100) : DASH}</td>
      <td>${lastWeek ? fmtMoney(before[name] || 0) : DASH}</td>
      <td>${lastWeek ? fmtSigned((categories[name] || 0) - (before[name] || 0), fmtMoney) : DASH}</td></tr>`).join('');
    const methods = Object.entries(day.payments_by_method || {});
    const numbers = [
      ['Net revenue', fmtMoney(day.net_revenue)],
      ['Gross revenue', fmtMoney(day.gross_revenue)],
      ['Refunds', fmtMoney(day.refunds)],
      ['Funds received', fmtMoney(day.funds_received)],
      ['Tips', fmtMoney(day.tips)],
    ];
    const roller = safeLink(data.links && data.links.roller);
    return [
      `<section class="day wrap" aria-labelledby="day-title">${navDayTitle(data, day)}
        <dl class="kv">${numbers.map(([k, v]) => `<div><dt>${esc(k)}</dt><dd>${esc(v)}</dd></div>`).join('')}</dl>
      </section>`,
      section('Revenue by category', 'Before sales tax, counted on the day guests visit, against the same day last week.', `<div class="table-wrap"><table>
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
      hours.length ? section('Staffing by hour', 'Staff scheduled, on the clock and recommended for the guests on the floor.', `<div class="table-wrap"><table>
        <thead><tr><th scope="col">Hour</th><th scope="col">On the floor</th><th scope="col">Scheduled</th><th scope="col">On the clock</th>
        <th scope="col">Recommended</th><th scope="col">Staffing</th></tr></thead><tbody>${hourRows}</tbody></table></div>`) : '',
    ].join('');
  }

  // ------------------------------------------------------------------ calendar

  function partyLine(p) {
    const hosts = p.hosts_scheduled === 0
      ? '<span class="chip under">No party host</span>'
      : isNum(p.hosts_scheduled) ? `${p.hosts_scheduled} host${p.hosts_scheduled === 1 ? '' : 's'}` : '';
    const people = isNum(p.kids)
      ? `${fmtInt(p.kids)} kids${p.adults ? `, ${fmtInt(p.adults)} adults` : ''}`
      : `${fmtInt(p.guests)} guests`;
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
        ? `${fmtInt(actual.guests)} guests, ${fmtMoney(actual.net_revenue)}${actual.in_progress ? ' so far' : ''}`
        : ahead ? `Expected ${fmtInt(ahead.expected_guests)} guests, ${fmtMoney(ahead.expected_revenue)}` : '';
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
      <p class="section-lede">Seven days from ${esc(fmtDayLong(start))}: parties with their rooms, guests and payments from ROLLER, and the shifts published in 7shifts. Rooms come from the booking notes.</p>
      ${blocks}</div>`;
  }

  // ------------------------------------------------------------------ forecasts

  function shortStaffedText(short) {
    if (!short || !short.length) return '';
    const ranges = [];
    for (const slot of short.slice().sort((a, b) => a.hour - b.hour)) {
      const last = ranges[ranges.length - 1];
      if (last && slot.hour === last.end + 1) {
        last.end = slot.hour;
        last.need = Math.max(last.need, slot.short_by);
      } else {
        ranges.push({ start: slot.hour, end: slot.hour, need: slot.short_by });
      }
    }
    const text = ranges
      .map((r) => `${r.need} more at ${r.start === r.end ? fmtHour(r.start) : `${fmtHour(r.start)} to ${fmtHour(r.end + 1)}`}`)
      .join('; ');
    return `<span class="ahead-gap">Needs ${esc(text)}</span>`;
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
        <span class="ahead-meta">${fmtInt(r.expected_guests)} guests</span>
        ${isNum(r.revenue_change_pct) ? `<span class="ahead-meta">${esc(fmtSigned(r.revenue_change_pct, (v) => `${v.toFixed(0)}%`))} revenue vs last week</span>` : ''}
        <span class="ahead-meta">Labor ${fmtPct(r.expected_labor_pct)}, ${fmtHours(r.scheduled_hours)} scheduled</span>
        ${r.holiday_note ? `<span class="ahead-holiday">${esc(r.holiday_note)}</span>` : ''}
        ${shortStaffedText(r.short_staffed)}
      </li>`).join('');
    return section('Next 7 days', 'Expected from the bookings already made plus the usual walk-ins for each weekday, against the staff scheduled in 7shifts.', `
      <div class="ahead-scroll"><ol class="ahead">${items}</ol></div>
      <p class="ahead-total">${fmtInt(totals.guests)} guests and ${fmtMoney(totals.revenue)} in net revenue expected, with scheduled labor at ${fmtPct(laborPct)} of revenue.</p>`, 'band-sky');
  }

  function weekToDateSection(data) {
    const week = data.week_to_date;
    if (!week || !week.this_week || !week.this_week.days) return '';
    const change = week.change_pct || {};
    const rows = [['Guests', 'guests', fmtInt], ['Passes', 'passes', fmtInt], ['Net revenue', 'net_revenue', fmtMoney], ['Labor cost', 'actual_labor', fmtMoney]]
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
    let sentence = `Over the last ${accuracy.days} days with a forecast, guest forecasts were off by ${fmtPct(accuracy.mape_guests)} on average and revenue forecasts by ${fmtPct(accuracy.mape_revenue)}.`;
    const bias = accuracy.bias_guests_pct;
    if (isNum(bias) && Math.abs(bias) >= BIAS_WORTH_MENTIONING) {
      sentence += ` Guest forecasts have run ${bias < 0 ? 'low' : 'high'} by ${Math.abs(bias).toFixed(0)}%, so plan for ${bias < 0 ? 'more' : 'fewer'} guests than forecast.`;
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
          <td>${fmtMoney(f.revenue)}</td><td>${fmtMoney(d.net_revenue)}</td><td${cls(f.revenue_error_pct)}>${missText(f.revenue_error_pct)}</td></tr>`;
      }).join('');
    return section('How good the forecasts have been', `${sentence} Each forecast is the last one made before the day began.`, rows ? `<div class="table-wrap"><table>
        <thead><tr><th scope="col">Day</th><th scope="col">Guests forecast</th><th scope="col">Guests actual</th><th scope="col">Guest forecast was</th><th scope="col">Revenue forecast</th><th scope="col">Revenue actual</th><th scope="col">Revenue forecast was</th></tr></thead>
        <tbody>${rows}</tbody>
      </table></div>` : '');
  }

  function forecastsTab(data, day, date) {
    const lead = day
      ? `<p class="day-sentence">${esc(daySentence(data, day))}</p>`
      : '';
    return [
      `<section class="day wrap" aria-labelledby="day-title"><h1 class="day-title" id="day-title" tabindex="-1">Forecasts</h1>${lead}</section>`,
      aheadSection(data),
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
        <div class="read-lists">${list('Staffing moves', a.staffing_actions)}${list('Coming up', a.predictions)}${list('What stood out', a.insights)}${list('Watch for', a.risks)}</div>
        ${a.model ? `<p class="read-by">Written by ${esc(a.model)} from that run's numbers.</p>` : ''}`
        : '<p>The run produced its numbers, but Claude did not write an analysis.</p>'}
    </div>`).join('');
    return `<div class="wrap day"><h1 class="day-title" id="day-title" tabindex="-1">Claude's analysis</h1>
      <p class="day-sentence">${esc(fmtDayLong(date))}</p>
      ${statusItems ? `<ul class="status-list" aria-label="Scheduled reports">${statusItems}</ul>` : '<p class="section-lede">No scheduled reports for this day.</p>'}
      ${cards || '<p class="empty">No analysis was written for this day.</p>'}
    </div>`;
  }

  function updatesTab(data) {
    const refresh = data.refresh || {};
    const link = safeLink(data.links && data.links.update);
    const failures = refresh.failures || [];
    const rows = (data.updates || []).map((u) => `<tr>
      <td>${esc(fmtStamp(u.run_at, data.timezone))}</td>
      <td class="text">${esc(UPDATE_KINDS[u.kind] || u.kind)}</td>
      <td class="text">${u.trigger ? esc(u.trigger === 'manual' ? 'By hand' : 'Scheduled') : DASH}</td>
      <td class="text"><span class="chip ${u.ok ? 'done' : 'failed'}">${u.ok ? 'Worked' : 'Failed'}</span></td>
      <td class="notes">${esc(u.notes)}</td></tr>`).join('');
    return `<div class="wrap day"><h1 class="day-title" id="day-title" tabindex="-1">Updates</h1>
      <p class="day-sentence">Last updated ${esc(fmtStamp(data.generated_at, data.timezone))} ${esc(updatedBy(refresh))}. The dashboard refreshes every hour while the venue is open, and after the mid-day and end-of-day reports.</p>
      ${link ? `<p><a class="btn-update" href="${esc(link)}" target="_blank" rel="noopener noreferrer">Update now</a></p>
        <p class="section-lede">Opens the refresh in Claude, where "Run now" starts it. New numbers appear here a few minutes later; reload the page to see them.</p>` : ''}
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
        const label = `${fmtDayLong(date)}: ${fmtInt(d.guests)} guests, ${fmtMoney(d.net_revenue)} net revenue${d.in_progress ? ' so far' : ''}`;
        return `<button type="button" class="cell${focused ? ' is-focus' : ''}" data-focus="${date}" data-tint="${((d[metric] || 0) / peak).toFixed(3)}" aria-pressed="${focused}" aria-label="${esc(label)}">
          <span class="cell-day">${dayNumber}</span>
          <span class="cell-rev">${show(d[metric])}</span>
          <span class="cell-guests">${metric === 'guests' ? fmtMoneyShort(d.net_revenue) : `${fmtInt(d.guests)} guests`}</span>
          ${d.holiday ? `<span class="cell-holiday">${esc(d.holiday)}</span>` : ''}
        </button>`;
      }).join('');
      const laborPct = totals.revenue ? (totals.labor / totals.revenue) * 100 : null;
      const partial = present.length < 7 ? `, ${present.length} of 7 days` : '';
      rows.push(`<div class="week-label">${fmtMDY(monday)} – ${fmtMDY(isoAdd(monday, 6))}</div>${cells}
        <div class="week-total">${fmtMoney(totals.revenue)}, ${fmtInt(totals.guests)} guests<br>Labor ${fmtPct(laborPct)}${partial}</div>`);
    }
    return section('Week by week', `Each square is one day, shaded by ${metric === 'guests' ? 'guests' : 'net revenue'}, so the same weekday lines up down each column. Pick a day to open it.`,
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
    const el = event.target.closest('[data-tab], [data-focus], [data-shift], [data-action]');
    if (!el || el.disabled) return;
    if (el.dataset.tab) setTab(el.dataset.tab);
    else if (el.dataset.focus) setFocus(el.dataset.focus, true);
    else if (el.dataset.shift) setFocus(isoAdd(state.focus, Number(el.dataset.shift)), false);
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
