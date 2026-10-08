import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import vm from 'node:vm';

// HTML parsers normalize CRLF before CSP hashes are checked.
const html = (await readFile(new URL('../index.html', import.meta.url), 'utf8'))
  .replace(/\r\n?/g, '\n');
const script = html.match(/<script>([\s\S]*?)<\/script>/)?.[1];
assert.ok(script, 'The page must have an inline widget script');

class TextNode {
  constructor(text) { this.textContent = String(text); }
}

class Element {
  constructor(tag = 'div') {
    this.tagName = tag.toUpperCase();
    this.children = [];
    this.className = '';
    this.dataset = {};
    this.handlers = new Map();
    this.hidden = false;
    this.classList = {
      contains: name => this.className.split(/\s+/).includes(name),
      add: name => {
        const names = new Set(this.className.split(/\s+/).filter(Boolean));
        names.add(name);
        this.className = [...names].join(' ');
      },
      remove: name => {
        this.className = this.className.split(/\s+/).filter(n => n && n !== name).join(' ');
      }
    };
  }
  // A dangerous rendering regression fails before a fake DOM can hide it.
  set innerHTML(_) { throw new Error('HTML insertion is forbidden in the widget'); }
  set textContent(text) { this.replaceChildren(new TextNode(text)); }
  get textContent() { return this.children.map(node => node.textContent).join(''); }
  append(...nodes) {
    for (const node of nodes) {
      node.parentElement = this;
      this.children.push(node);
    }
  }
  appendChild(node) { this.append(node); return node; }
  replaceChildren(...nodes) {
    for (const old of this.children) old.parentElement = null;
    this.children = [];
    this.append(...nodes);
  }
  contains(node) {
    for (let current = node; current; current = current.parentElement) {
      if (current === this) return true;
    }
    return false;
  }
  closest(selector) {
    return this.classList.contains(selector.slice(1))
      ? this : this.parentElement?.closest(selector) || null;
  }
  addEventListener(type, callback) { this.handlers.set(type, callback); }
}

function xmlFixture(entries = [], { malformed = false, root = 'rss' } = {}) {
  const items = entries.map(({ title = '', date }) => ({
    querySelector(selector) {
      const value = selector === 'title' ? title : selector === 'pubDate' ? date : null;
      return value == null ? null : { textContent: value };
    }
  }));
  return {
    documentElement: { localName: root },
    querySelector: selector => selector === 'parsererror' && malformed ? {} : null,
    querySelectorAll: selector => selector === 'item' ? items : []
  };
}

const makeResponse = (text = '<rss><channel/></rss>', headers = {}, status = 200) =>
  new Response(text, { status, headers: { 'content-type': 'application/rss+xml; charset=utf-8', ...headers } });

function harness({ entries = [], xmlOptions, fetchImpl } = {}) {
  const elements = new Map([...html.matchAll(/\bid="([^"]+)"/g)]
    .map(([, id]) => [id, new Element()]));
  const requests = [];
  const errors = [];
  const timers = new Map();
  let nextTimer = 1;
  let parseCount = 0;
  let nextFetch = fetchImpl || (async () => makeResponse());
  let nextXml = xmlFixture(entries, xmlOptions);
  const context = vm.createContext({
    document: {
      getElementById: id => elements.get(id),
      createElement: tag => new Element(tag),
      createTextNode: text => new TextNode(text)
    },
    DOMParser: class {
      parseFromString(text, type) {
        assert.equal(type, 'application/xml');
        assert.equal(typeof text, 'string');
        parseCount++;
        return nextXml;
      }
    },
    fetch: async (url, options) => {
      requests.push({ url, options });
      return nextFetch(url, options);
    },
    AbortController,
    TextDecoder,
    console: { error: (...args) => errors.push(args) },
    setTimeout: (callback, ms) => {
      const id = nextTimer++;
      timers.set(id, { callback, ms });
      return id;
    },
    clearTimeout: id => timers.delete(id),
    setInterval: () => nextTimer++
  });
  vm.runInContext(script, context, { filename: 'index.html' });
  return {
    elements, requests, errors, timers,
    evaluate: source => vm.runInContext(source, context),
    setFetch: fn => { nextFetch = fn; },
    setXml: xml => { nextXml = xml; },
    get parseCount() { return parseCount; },
    async settled() {
      for (let i = 0; i < 30 && vm.runInContext('feedLoading', context); i++) {
        await new Promise(resolve => setImmediate(resolve));
      }
      assert.equal(vm.runInContext('feedLoading', context), false, 'Metadata request must settle');
    }
  };
}

function assertOffline(h) {
  assert.equal(h.elements.get('statCountSub').textContent, 'Could not reach RSS metadata');
  assert.equal(h.elements.get('statAgeSub').textContent, 'Metadata offline');
  assert.equal(h.elements.get('tickerInner').children.length, 0);
  assert.equal(h.evaluate('lastTitles.length'), 0);
}

test('CSP allows exactly the current script/style and fixed HTTPS feed endpoints', () => {
  const meta = html.match(/<meta http-equiv="Content-Security-Policy" content="([^"]+)" \/>/);
  assert.ok(meta);
  assert.ok(html.indexOf(meta[0]) < html.indexOf('<style>'));
  const directives = new Map(meta[1].split('; ').map(value => {
    const [name, ...sources] = value.split(' ');
    return [name, sources.join(' ')];
  }));
  assert.equal(directives.size, 8, 'Extra source directives must not override the restrictive policy');
  for (const tag of ['script', 'style']) {
    const blocks = [...html.matchAll(new RegExp(`<${tag}>([\\s\\S]*?)<\\/${tag}>`, 'g'))];
    assert.equal(blocks.length, 1);
    const hash = createHash('sha256').update(blocks[0][1]).digest('base64');
    assert.equal(directives.get(`${tag}-src`), `'sha256-${hash}'`);
  }
  for (const directive of ['default-src', 'base-uri', 'object-src', 'form-action']) {
    assert.equal(directives.get(directive), "'none'");
  }
  assert.equal(directives.get('connect-src'), 'https://rss.app/feeds/NbvgRJvMlmSIRBEe.xml');
  assert.equal(directives.get('frame-src'), 'https://rss.app/embed/v1/wall/NbvgRJvMlmSIRBEe');
  assert.doesNotMatch(meta[1], /unsafe-inline|unsafe-eval|\*/);
  assert.doesNotMatch(html, /\s(?:on[a-z]+|style)\s*=/i);
});

test('third-party wall is cross-origin, sandboxed, and receives no referrer', () => {
  const iframe = html.match(/<iframe\b[^>]*>/)?.[0];
  assert.ok(iframe);
  assert.match(iframe, /src="https:\/\/rss\.app\/embed\/v1\/wall\/NbvgRJvMlmSIRBEe"/);
  assert.match(iframe, /sandbox="allow-scripts allow-same-origin allow-popups"/);
  assert.doesNotMatch(iframe, /allow-top-navigation|allow-forms|allow-downloads|allow-popups-to-escape-sandbox/);
  assert.match(iframe, /referrerpolicy="no-referrer"/);
  assert.match(html, /<meta name="referrer" content="no-referrer" \/>/);
  for (const feature of ['camera', 'microphone', 'geolocation', 'payment', 'usb', 'clipboard-read', 'clipboard-write']) {
    assert.ok(iframe.includes(`${feature} 'none'`));
  }
});

test('hostile feed titles render as literal text with only a fixed strong label', async () => {
  const payloads = ['<img src=x onerror=alert(1)>', '<svg onload=alert(1)>', '</strong><script>alert(1)</script>'];
  const h = harness({ entries: payloads.map(title => ({ title })) });
  await h.settled();
  const spans = h.elements.get('tickerInner').children;
  assert.equal(spans.length, 6, 'Ticker must still duplicate titles for scrolling');
  spans.forEach((span, index) => {
    assert.equal(span.tagName, 'SPAN');
    assert.equal(span.children.length, 2);
    assert.equal(span.children[0].tagName, 'STRONG');
    assert.equal(span.children[0].textContent, 'r/ryobi');
    assert.ok(span.children[1] instanceof TextNode);
    assert.equal(span.textContent, `r/ryobi ${payloads[index % 3]}`);
  });
  assert.equal(h.elements.get('tickerEmpty').hidden, true);
});

test('normal feed statistics, title truncation and keyword filtering still work', async () => {
  const entries = [
    { title: 'Ryobi drill for the garage', date: new Date(Date.now() - 5 * 60000).toUTCString() },
    { title: 'Ryobi saw for the workshop', date: 'invalid date' },
    { title: 'Trimmer '.repeat(150) }
  ];
  const h = harness({ entries });
  await h.settled();
  assert.equal(h.elements.get('statCount').textContent, '3');
  assert.equal(h.elements.get('statAge').textContent, '5 min');
  assert.equal(h.evaluate('lastTitles[2].length'), 1000);
  assert.equal(h.evaluate('formatAge(new Date("invalid date"))'), '--');
  assert.equal(h.elements.get('tickerInner').children[2].textContent.length, 88);
  const chips = h.elements.get('keywordChips');
  const ryobi = chips.children.find(chip => chip.dataset.key === 'ryobi');
  assert.ok(ryobi);
  chips.handlers.get('click')({ target: ryobi });
  assert.equal(ryobi.classList.contains('active'), true);
  assert.equal(h.elements.get('tickerInner').children.length, 4);
  chips.handlers.get('click')({ target: ryobi });
  assert.equal(h.elements.get('tickerInner').children.length, 6);
});

test('fetch never attaches credentials/referrers and rejects redirects', async () => {
  const h = harness();
  await h.settled();
  assert.equal(h.requests.length, 1);
  const { url, options } = h.requests[0];
  assert.equal(url, 'https://rss.app/feeds/NbvgRJvMlmSIRBEe.xml');
  assert.equal(options.credentials, 'omit');
  assert.equal(options.referrerPolicy, 'no-referrer');
  assert.equal(options.redirect, 'error');
  assert.equal(options.mode, 'cors');
  assert.ok(options.signal instanceof AbortSignal);
  assert.equal([...h.timers.values()].some(timer => timer.ms === 15000), false);
});

test('oversized streams without Content-Length are cancelled before XML parsing', async () => {
  let cancelled = false;
  let released = false;
  let reads = 0;
  const reader = {
    async read() {
      reads++;
      return { done: false, value: new Uint8Array(300 * 1024) };
    },
    async cancel() { cancelled = true; },
    releaseLock() { released = true; }
  };
  const h = harness({ fetchImpl: async () => ({
    ok: true,
    headers: new Headers({ 'content-type': 'application/xml' }),
    body: { getReader: () => reader }
  }) });
  await h.settled();
  assert.equal(reads, 2);
  assert.equal(cancelled, true);
  assert.equal(released, true);
  assert.equal(h.parseCount, 0);
  assertOffline(h);
});

test('oversized Content-Length and unexpected response types cancel the body', async t => {
  for (const headers of [
    { 'content-type': 'application/xml', 'content-length': String(512 * 1024 + 1) },
    { 'content-type': 'text/html' }
  ]) {
    await t.test(JSON.stringify(headers), async () => {
      let cancelled = false;
      const h = harness({ fetchImpl: async () => ({
        ok: true,
        headers: new Headers(headers),
        body: { cancel: async () => { cancelled = true; } }
      }) });
      await h.settled();
      assert.equal(cancelled, true);
      assert.equal(h.parseCount, 0);
      assertOffline(h);
    });
  }
});

test('DTD/entity declarations are rejected before invoking the XML parser', async t => {
  for (const text of [
    '<!DOCTYPE rss [<!ENTITY a "boom">]><rss/>',
    '<!ENTITY steal SYSTEM "file:///private"><rss/>'
  ]) {
    await t.test(text, async () => {
      const h = harness({ fetchImpl: async () => makeResponse(text) });
      await h.settled();
      assert.equal(h.parseCount, 0);
      assertOffline(h);
    });
  }
});

test('malformed XML, unrelated documents, item floods, HTTP errors and invalid UTF-8 fail safely', async t => {
  const cases = [
    { name: 'parse error', options: { xmlOptions: { malformed: true } } },
    { name: 'wrong document root', options: { xmlOptions: { root: 'html' } } },
    { name: 'item flood', options: { entries: Array.from({ length: 201 }, () => ({ title: 'test' })) } },
    { name: 'HTTP failure', options: { fetchImpl: async () => makeResponse('error', {}, 403) } },
    { name: 'invalid UTF-8', options: { fetchImpl: async () => makeResponse(new Uint8Array([0xC3, 0x28])) } }
  ];
  for (const { name, options } of cases) {
    await t.test(name, async () => {
      const h = harness(options);
      await h.settled();
      assertOffline(h);
    });
  }
});

test('timeout aborts a stalled fetch, prevents overlapping loads and permits recovery', async () => {
  const h = harness({ fetchImpl: async (_url, { signal }) => new Promise((_, reject) => {
    signal.addEventListener('abort', () => reject(new Error('Aborted')), { once: true });
  }) });
  assert.equal(h.requests.length, 1);
  await h.evaluate('loadFeedMeta()');
  assert.equal(h.requests.length, 1, 'A second interval must not overlap the pending request');
  const timeout = [...h.timers.values()].find(timer => timer.ms === 15000);
  assert.ok(timeout);
  timeout.callback();
  await h.settled();
  assert.equal(h.requests[0].options.signal.aborted, true);
  assertOffline(h);
  h.setFetch(async () => makeResponse());
  h.setXml(xmlFixture([{ title: 'Ryobi recovery' }]));
  await h.evaluate('loadFeedMeta()');
  assert.equal(h.requests.length, 2);
  assert.equal(h.elements.get('statCount').textContent, '1');
  assert.equal(h.elements.get('tickerInner').children[0].textContent, 'r/ryobi Ryobi recovery');
});

test('the request timeout also aborts a stalled response body and releases its reader', async () => {
  let started = false;
  let cancelled = false;
  let released = false;
  const h = harness({ fetchImpl: async (_url, { signal }) => ({
    ok: true,
    headers: new Headers({ 'content-type': 'application/xml' }),
    body: {
      getReader: () => ({
        read: () => new Promise((_, reject) => {
          started = true;
          signal.addEventListener('abort', () => reject(new Error('Body aborted')), { once: true });
        }),
        async cancel() { cancelled = true; },
        releaseLock() { released = true; }
      })
    }
  }) });
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(started, true);
  [...h.timers.values()].find(timer => timer.ms === 15000).callback();
  await h.settled();
  assert.equal(cancelled, true);
  assert.equal(released, true);
  assert.equal(h.parseCount, 0);
  assertOffline(h);
});

test('a failed refresh removes stale titles and chip selection', async () => {
  const h = harness({ entries: [{ title: 'Ryobi drill' }] });
  await h.settled();
  h.evaluate('activeKeywords.add("ryobi")');
  h.setFetch(async () => { throw new Error('Metadata unavailable'); });
  await h.evaluate('loadFeedMeta()');
  assertOffline(h);
  assert.equal(h.evaluate('activeKeywords.size'), 0);
  assert.equal(h.elements.get('tickerEmpty').hidden, false);
});
