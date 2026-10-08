# xeneon-ryobi-widget

A standalone r/ryobi dashboard for a Xeneon display. Open `index.html` in a modern
browser or serve it over HTTPS. It displays the RSS.app wall, a local clock, feed
statistics, and a scrolling title ticker with keyword filters.

## Security and privacy

- Feed titles are displayed as text, so titles containing HTML cannot create
  elements or run code in the dashboard.
- A Content Security Policy permits only the exact inline script and stylesheet,
  the configured RSS metadata endpoint, and the configured RSS wall endpoint.
- The external wall runs in a sandboxed cross-origin iframe. Its scripts and
  article popups are allowed; top-level navigation, forms, and downloads are not.
  Article popups inherit the sandbox, so some external page features may be limited.
- Metadata requests omit credentials and referrers and reject redirects. Requests
  time out after 15 seconds. XML bodies are limited to 512 KiB and 200 items;
  malformed XML and entity/DTD declarations are rejected.
- No accounts, passwords, API keys, analytics, or persistent browser storage are
  required by this repository. The RSS.app feed identifier in the page is a public
  feed address, not an authentication credential.

RSS.app controls the embedded wall and may make its own requests or use its own
cookies. The parent page's metadata protections do not change the provider's
privacy practices. If RSS.app metadata is unavailable or blocked by CORS, the
dashboard displays an offline state while the embedded wall remains independent.

## Development checks

Node.js 24 is used for dependency-free checks. No package installation is needed.

```sh
node --test tests/security.test.mjs
```

When changing the inline JavaScript or CSS, regenerate the CSP hashes and rerun
the tests. The tests also fail if the policy's hashes no longer match the page.

```sh
node scripts/update-csp.mjs
node --test tests/security.test.mjs
```

These tests use synthetic DOM, XML, and network fixtures. They do not call Reddit
or RSS.app and do not replace a live browser check of the third-party wall.
