/* Hyper Kidz Dallas staff dashboard.
 *
 * data.json is written by publish_dashboard.py and is public, so it is encrypted: the dashboard
 * document is gzip-compressed and sealed with AES-256-GCM under a random data key, and that key is
 * wrapped once per account under a key derived from the account password (PBKDF2-HMAC-SHA256). This
 * script derives the same key from the password typed at sign-in, unwraps the data key and decrypts,
 * all inside the browser. The derived key (never the password) is kept for the tab, or on the device
 * when "Keep me signed in" is ticked, so a reload does not ask again.
 *
 * Contract with src/dashboard.py: ACCOUNT_ID_PREFIX, SUPPORTED_ENVELOPE and SUPPORTED_SCHEMA match
 * ACCOUNT_ID_PREFIX, ENVELOPE_VERSION and DATA_SCHEMA_VERSION there (pinned by tests/test_publish_dashboard.py).
 */
'use strict';

(() => {
  const DATA_URL = 'data.json';
  const ACCOUNT_ID_PREFIX = 'hyperkidz-dashboard:';
  const SUPPORTED_ENVELOPE = 1;
  const SUPPORTED_SCHEMA = 1;
  const SESSION_KEY = 'hyperkidz-dashboard-session';
  const STALE_AFTER_HOURS = 30;
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
  const TINT_RGB = '240, 78, 152';
  const DASH = '–';
  const MODE_LABELS = { morning: 'morning report', midday: 'mid-day check-in', eod: 'closing report' };
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

  const encoder = new TextEncoder();
  const $ = (selector, root = document) => root.querySelector(selector);
  const state = { data: null, focus: null, showAllAttention: false };

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
    showLogin();
  }

  function openDashboard(data) {
    state.data = data;
    state.focus = data.focus_date;
    state.showAllAttention = false;
    show('app');
    render(true);
  }

  // ------------------------------------------------------------------ formatting

  const isNum = (v) => typeof v === 'number' && Number.isFinite(v);
  const fmtInt = (v) => (isNum(v) ? Math.round(v).toLocaleString('en-US') : DASH);
  const fmtMoney = (v) => (isNum(v) ? `$${Math.round(v).toLocaleString('en-US')}` : DASH);
  const fmtCents = (v) => (isNum(v) ? `$${v.toFixed(2)}` : DASH);
  const fmtMoneyShort = (v) => {
    if (!isNum(v)) return DASH;
    return Math.abs(v) >= 1000 ? `$${(v / 1000).toFixed(1)}k` : `$${Math.round(v)}`;
  };
  const fmtPct = (v) => (isNum(v) ? `${v.toFixed(1)}%` : DASH);
  const fmtHours = (v) => (isNum(v) ? `${v.toFixed(1)} h` : DASH);
  const esc = (v) => String(v ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);

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
  const fmtClock = (iso, timeZone) => compactMeridiem(
    new Date(iso).toLocaleTimeString('en-US', { timeZone, hour: 'numeric', minute: '2-digit' }),
  );
  const prefersReducedMotion = () => window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  // ------------------------------------------------------------------ rendering

  function render(animate) {
    const { data } = state;
    const app = $('#app');
    if (!data.days.length) {
      app.innerHTML = `${topbar(data)}<p class="wrap">No days have been reported yet.</p>`;
      return;
    }
    const day = data.days.find((d) => d.date === state.focus) || data.days[data.days.length - 1];
    state.focus = day.date;
    app.innerHTML = [
      topbar(data),
      daySection(data, day),
      readSection(data, day),
      aheadSection(data),
      weeksSection(data, day),
      hoursSection(data, day),
      partiesSection(data, day),
      attentionSection(data, day),
      accuracySection(data),
      footer(data),
    ].join('');
    applyDynamicStyles(app, animate);
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
    root.querySelectorAll('[data-min-width]').forEach((el) => {
      el.style.minWidth = `${el.dataset.minWidth}px`;
    });
  }

  function topbar(data) {
    const run = data.source_run;
    const after = run && MODE_LABELS[run.mode] ? ` after the ${MODE_LABELS[run.mode]}` : '';
    const ageHours = (Date.now() - Date.parse(data.generated_at)) / 3.6e6;
    const stale = ageHours > STALE_AFTER_HOURS
      ? `<span class="stale">Not updated since ${esc(fmtStamp(data.generated_at, data.timezone))}</span>`
      : '';
    return `<header class="topbar wrap">
      <img class="topbar-logo" src="hyperkidz-logo.png" alt="Hyper Kidz" width="192" height="40">
      <div class="topbar-meta">
        ${stale}
        <span>${esc(data.venue)}. Updated ${esc(fmtStamp(data.generated_at, data.timezone))}${esc(after)}.</span>
        <button type="button" class="btn-quiet" data-action="sign-out">Sign out</button>
      </div>
    </header>`;
  }

  function navButton(target, label, glyph) {
    if (!target) return `<button type="button" class="nav-btn" disabled aria-label="${label}">${glyph}</button>`;
    return `<button type="button" class="nav-btn" data-focus="${target.date}" aria-label="${label}, ${esc(fmtDayLong(target.date))}">${glyph}</button>`;
  }

  function daySection(data, day) {
    const index = data.days.findIndex((d) => d.date === day.date);
    const hours = data.hourly[day.date] || [];
    const tags = [];
    if (day.in_progress) tags.push('<span class="tag tag-live">Open now, numbers so far</span>');
    if (day.holiday_note) tags.push(`<span class="tag tag-holiday">${esc(day.holiday_note)}</span>`);
    const numbers = dayNumbers(data, day)
      .map(([label, value, sub]) => `<div class="number"><dt>${esc(label)}</dt><dd>${esc(value)}<span class="sub">${esc(sub)}</span></dd></div>`)
      .join('');
    return `<section class="day wrap" id="day" aria-labelledby="day-title">
      <div class="day-nav">
        ${navButton(data.days[index - 1], 'Previous day', '‹')}
        <h1 class="day-title" id="day-title" tabindex="-1">${esc(fmtDayLong(day.date))}</h1>
        ${navButton(data.days[index + 1], 'Next day', '›')}
      </div>
      ${tags.length ? `<div class="day-tags">${tags.join('')}</div>` : ''}
      <p class="day-sentence">${esc(daySentence(data, day))}</p>
      ${hours.length ? pitBlock(hours) : '<p class="pit-missing">Hour-by-hour detail is kept for the last 14 days.</p>'}
      <dl class="numbers">${numbers}</dl>
    </section>`;
  }

  function daySentence(data, day) {
    const soFar = day.so_far;
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

  function dayNumbers(data, day) {
    const forecast = day.forecast;
    const soFar = day.in_progress ? day.so_far : null;
    const guestsNote = soFar
      ? `Expected at close ${fmtInt(soFar.expected_total_guests)}`
      : forecast ? `Forecast ${fmtInt(forecast.guests)}` : `${fmtInt(day.walk_ins)} walk-ins`;
    const revenueNote = soFar
      ? `Expected at close ${fmtMoney(soFar.expected_total_revenue)}`
      : forecast ? `Forecast ${fmtMoney(forecast.revenue)}` : `After ${fmtMoney(day.refunds)} in refunds`;
    return [
      ['Guests', fmtInt(day.guests), guestsNote],
      ['Net revenue', fmtMoney(day.net_revenue), revenueNote],
      ['Labor cost', fmtMoney(day.actual_labor), `${fmtPct(day.labor_pct)} of revenue, target ${fmtPct(data.targets.labor_pct)}`],
      ['Labor hours', fmtHours(day.actual_hours), `${fmtHours(day.scheduled_hours)} scheduled`],
      ['Revenue per labor hour', fmtMoney(day.revenue_per_labor_hour), `${fmtCents(day.labor_per_guest)} of labor per guest`],
    ];
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

  function readSection(data, day) {
    const analysis = data.analysis;
    if (!analysis || !analysis.summary || analysis.report_date !== day.date) return '';
    const list = (title, items) => (items && items.length
      ? `<div><h3>${title}</h3><ul>${items.map((item) => `<li>${esc(item)}</li>`).join('')}</ul></div>`
      : '');
    return `<section class="band band-lilac" aria-labelledby="read-title"><div class="wrap">
      <h2 class="section-title" id="read-title">The read on ${esc(fmtDayLong(day.date))}</h2>
      <p class="read-summary">${esc(analysis.summary)}</p>
      <div class="read-lists">
        ${list('Staffing moves', analysis.staffing_actions)}
        ${list('Coming up', analysis.predictions)}
        ${list('What stood out', analysis.insights)}
        ${list('Watch for', analysis.risks)}
      </div>
      ${analysis.model ? `<p class="read-by">Written by ${esc(analysis.model)} from the numbers on this page.</p>` : ''}
    </div></section>`;
  }

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
        <span class="ahead-meta">Labor ${fmtPct(r.expected_labor_pct)}, ${fmtHours(r.scheduled_hours)} scheduled</span>
        ${r.holiday_note ? `<span class="ahead-holiday">${esc(r.holiday_note)}</span>` : ''}
        ${shortStaffedText(r.short_staffed)}
      </li>`).join('');
    return `<section class="band band-sky" aria-labelledby="ahead-title"><div class="wrap">
      <h2 class="section-title" id="ahead-title">Next 7 days</h2>
      <p class="section-lede">Expected from the bookings already made plus the usual walk-ins for each weekday, against the staff scheduled in 7shifts.</p>
      <div class="ahead-scroll"><ol class="ahead">${items}</ol></div>
      <p class="ahead-total">${fmtInt(totals.guests)} guests and ${fmtMoney(totals.revenue)} in net revenue expected, with scheduled labor at ${fmtPct(laborPct)} of revenue.</p>
    </div></section>`;
  }

  function weeksSection(data, focusDay) {
    const days = data.days;
    const byDate = new Map(days.map((d) => [d.date, d]));
    const firstMonday = isoAdd(days[0].date, -mondayIndex(days[0].date));
    const lastDate = days[days.length - 1].date;
    const peak = Math.max(1, ...days.map((d) => d.net_revenue || 0));
    const heads = ['Week', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun', 'Week total']
      .map((label, i) => `<div class="weeks-head${i === 0 ? ' col-label' : ''}${i === 8 ? ' col-total' : ''}">${label}</div>`)
      .join('');
    const rows = [];
    for (let monday = isoAdd(lastDate, -mondayIndex(lastDate)); monday >= firstMonday; monday = isoAdd(monday, -7)) {
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
        const focused = date === focusDay.date;
        const label = `${fmtDayLong(date)}: ${fmtInt(d.guests)} guests, ${fmtMoney(d.net_revenue)} net revenue${d.in_progress ? ' so far' : ''}`;
        return `<button type="button" class="cell${focused ? ' is-focus' : ''}" data-focus="${date}" data-scroll="1" data-tint="${((d.net_revenue || 0) / peak).toFixed(3)}" aria-pressed="${focused}" aria-label="${esc(label)}">
          <span class="cell-day">${dayNumber}</span>
          <span class="cell-rev">${fmtMoneyShort(d.net_revenue)}</span>
          <span class="cell-guests">${fmtInt(d.guests)} guests</span>
          ${d.holiday ? `<span class="cell-holiday">${esc(d.holiday)}</span>` : ''}
        </button>`;
      }).join('');
      const laborPct = totals.revenue ? (totals.labor / totals.revenue) * 100 : null;
      const partial = present.length < 7 ? `, ${present.length} of 7 days` : '';
      rows.push(`<div class="week-label">${fmtMDY(monday)} – ${fmtMDY(isoAdd(monday, 6))}</div>${cells}
        <div class="week-total">${fmtMoney(totals.revenue)}, ${fmtInt(totals.guests)} guests<br>Labor ${fmtPct(laborPct)}${partial}</div>`);
    }
    return `<section class="plain" aria-labelledby="weeks-title"><div class="wrap">
      <h2 class="section-title" id="weeks-title">Week by week</h2>
      <p class="section-lede">Each square is one day, shaded by net revenue, so the same weekday lines up down each column. Pick a day to see it above.</p>
      <div class="weeks">${heads}${rows.join('')}</div>
    </div></section>`;
  }

  function hoursSection(data, day) {
    const rows = data.hourly[day.date] || [];
    if (!rows.length) return '';
    const body = rows.map((r) => {
      const status = STATUS[r.status];
      return `<tr class="${r.expected ? 'is-expected' : ''}">
        <td>${fmtHour(r.hour)}${r.expected ? ' <span class="muted">expected</span>' : ''}</td>
        <td>${fmtInt(r.arrivals)}</td>
        <td>${fmtInt(r.forecast_arrivals)}</td>
        <td>${fmtInt(r.on_floor)}</td>
        <td>${fmtMoney(r.revenue)}</td>
        <td>${fmtInt(r.staff_scheduled)}</td>
        <td>${r.expected ? DASH : fmtInt(r.staff_actual)}</td>
        <td>${fmtInt(r.recommended)}</td>
        <td>${status ? `<span class="chip ${status.cls}">${status.label}</span>` : DASH}</td>
      </tr>`;
    }).join('');
    return `<section class="plain" aria-labelledby="hours-title"><div class="wrap">
      <h2 class="section-title" id="hours-title">Hour by hour</h2>
      <p class="section-lede">Guests arriving and on the floor each hour of ${esc(fmtDayLong(day.date))}, with revenue placed at arrival and the staff scheduled, on the clock and recommended for that many guests.</p>
      <div class="table-wrap"><table>
        <thead><tr><th scope="col">Hour</th><th scope="col">Arrived</th><th scope="col">Forecast</th><th scope="col">On the floor</th><th scope="col">Revenue</th><th scope="col">Scheduled</th><th scope="col">On the clock</th><th scope="col">Recommended</th><th scope="col">Staffing</th></tr></thead>
        <tbody>${body}</tbody>
      </table></div>
    </div></section>`;
  }

  function partiesSection(data, day) {
    const parties = data.parties || {};
    const rows = Object.keys(parties)
      .filter((date) => date >= day.date)
      .sort()
      .flatMap((date) => parties[date].map((party) => ({ ...party, date })));
    if (!rows.length) return '';
    const items = rows.map((p) => {
      const when = `${p.date === day.date ? '' : `${fmtDayShort(p.date)}, `}${fmtClockText(p.start)}`;
      let hosts = '';
      if (p.hosts_scheduled === 0) hosts = '<span class="chip under">No party host scheduled</span>';
      else if (isNum(p.hosts_scheduled)) hosts = `${p.hosts_scheduled} party host${p.hosts_scheduled === 1 ? '' : 's'} scheduled`;
      return `<li><span class="list-when">${esc(when)}</span><span class="list-detail">${esc(p.product)}, ${fmtInt(p.guests)} guests</span><span class="list-action">${hosts}</span></li>`;
    }).join('');
    return `<section class="plain" aria-labelledby="parties-title"><div class="wrap">
      <h2 class="section-title" id="parties-title">Parties</h2>
      <p class="section-lede">Booked parties from ${esc(fmtDayLong(day.date))} on, with the party hosts scheduled in 7shifts.</p>
      <ul class="list-plain">${items}</ul>
    </div></section>`;
  }

  function attentionSection(data, day) {
    const rank = (a) => (SEVERITY[a.severity] ? SEVERITY[a.severity].rank : 9);
    const list = ((data.anomalies || {})[day.date] || []).slice().sort((a, b) => rank(a) - rank(b));
    if (!list.length) return '';
    const shown = state.showAllAttention ? list : list.slice(0, ATTENTION_PREVIEW);
    const items = shown.map((a) => {
      const severity = SEVERITY[a.severity] || SEVERITY.low;
      const at = isNum(a.hour) ? ` at ${fmtHour(a.hour)}` : '';
      return `<li><span class="chip sev ${esc(a.severity)}">${severity.label}${at}</span><span class="list-detail">${esc(a.description)}</span><span class="list-action">${esc(a.action)}</span></li>`;
    }).join('');
    const more = list.length > shown.length
      ? `<button type="button" class="btn-quiet more" data-action="show-all-attention">Show all ${list.length}</button>`
      : '';
    return `<section class="plain" aria-labelledby="attention-title"><div class="wrap">
      <h2 class="section-title" id="attention-title">Needs attention</h2>
      <p class="section-lede">What the report flagged for ${esc(fmtDayLong(day.date))}, most urgent first.</p>
      <ul class="list-plain">${items}</ul>
      ${more}
    </div></section>`;
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
    return `<section class="plain" aria-labelledby="accuracy-title"><div class="wrap">
      <h2 class="section-title" id="accuracy-title">How good the forecasts have been</h2>
      <p class="section-lede">${esc(sentence)} Each forecast is the last one made before the day began.</p>
      ${rows ? `<div class="table-wrap"><table>
        <thead><tr><th scope="col">Day</th><th scope="col">Guests forecast</th><th scope="col">Guests actual</th><th scope="col">Guest forecast was</th><th scope="col">Revenue forecast</th><th scope="col">Revenue actual</th><th scope="col">Revenue forecast was</th></tr></thead>
        <tbody>${rows}</tbody>
      </table></div>` : ''}
    </div></section>`;
  }

  function footer(data) {
    const notes = (data.notes || []).map(esc).join(' ');
    return `<footer class="foot wrap">
      <p>${notes}</p>
      <p>Opening hours: ${esc(data.opening_hours)}. Labor target: ${fmtPct(data.targets.labor_pct)} of net revenue.</p>
    </footer>`;
  }

  // ------------------------------------------------------------------ events

  function onAppClick(event) {
    const el = event.target.closest('[data-focus], [data-action]');
    if (!el || el.disabled) return;
    if (el.dataset.focus) {
      const scroll = Boolean(el.dataset.scroll);
      state.focus = el.dataset.focus;
      state.showAllAttention = false;
      render(true);
      if (scroll) $('#day').scrollIntoView({ behavior: prefersReducedMotion() ? 'auto' : 'smooth', block: 'start' });
      $('#day-title').focus({ preventScroll: true });
      return;
    }
    if (el.dataset.action === 'sign-out') signOut();
    else if (el.dataset.action === 'show-all-attention') {
      state.showAllAttention = true;
      render(false);
    }
  }

  document.addEventListener('DOMContentLoaded', () => {
    $('#login-form').addEventListener('submit', onLogin);
    $('#app').addEventListener('click', onAppClick);
    if (!window.crypto || !crypto.subtle || typeof DecompressionStream === 'undefined') {
      showLogin('This browser cannot open the dashboard. Update it, or use a current Chrome, Safari, Edge or Firefox.');
      $('#login-button').disabled = true;
      return;
    }
    boot();
  });
})();
