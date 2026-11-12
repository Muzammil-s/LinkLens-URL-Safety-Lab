# LinkLens — URL Safety Lab

LinkLens is a small, privacy-first educational tool that inspects a URL for a handful of common warning indicators. It runs entirely in the browser using the built-in URL parser. It does not visit the submitted website or send the address to a server.

## Features
- Parses HTTP and HTTPS links.
- Highlights plain HTTP, embedded URL credentials, punycode labels, IP-address hosts, many subdomain levels, non-default ports and unusually long URLs.
- Explains why each indicator deserves attention.
- Includes a sample address and mobile-friendly interface.
- No API key, backend, account or external dependency.

## Run
Open `index.html` in a browser, or serve this folder with VS Code Live Server.

## Deploy
Import this repository into Vercel as a static site, or publish the folder with GitHub Pages. No build command is needed.

## Important limitation
LinkLens is an educational heuristic tool, not an anti-phishing engine or reputation checker. Indicators can occur on legitimate sites. A clean result is not proof of safety. The tool does not verify certificates, domain ownership, redirects, site content or threat-intelligence feeds.

## Built with
HTML · CSS · Vanilla JavaScript · URL API
