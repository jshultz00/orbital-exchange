# VS-XXX-NNN — _short, finding-style title_

> **Severity:** _Critical / High / Medium / Low / Informational_  
> **CVSS:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N`  &nbsp; **Score:** _0.0_  
> **OWASP 2021:** _A0X — Category Name_  
> **OWASP WSTG:** _WSTG-XXX-NN_  
> **Status:** _Draft / Verified / False positive_  
> **Discovered by:** _scanner check ID (e.g. `a05.headers`) or "Manual"_

---

## 1. Summary

One paragraph. What is wrong, where, and what an attacker could do about it. A reader who only reads this section should understand the risk.

## 2. Affected target

- **URL / endpoint:** `http://localhost:3000/...`
- **Parameter / field:** _e.g. `?q=`, JSON body field `email`_
- **Authentication required:** _yes / no_
- **Discovered:** _2026-MM-DD HH:MM TZ_

## 3. Description

Two or three paragraphs:

1. **The vulnerability class.** What this kind of bug is, generally.
2. **How it manifests here.** Specific to this finding and this target.
3. **Why it matters.** Impact framed in business / data terms, not just technical.

## 4. Evidence

Raw artifacts that prove the finding. Use literal request/response snippets, not paraphrases.

```http
GET /target/path HTTP/1.1
Host: localhost:3000
...

HTTP/1.1 200 OK
...
<relevant excerpt>
```

## 5. Reproduction

```bash
# Step 1 — set up
./juiceshop-start.sh

# Step 2 — the curl that demonstrates the bug
curl -i 'http://localhost:3000/...' ...

# Expected: <what proves the finding>
```

A reviewer should be able to copy-paste this block and reproduce the finding from a clean container.

## 6. Impact

- _Confidentiality:_ …
- _Integrity:_ …
- _Availability:_ …
- _Exploitability:_ _easy / moderate / hard_ — and why.

## 7. Remediation

What to change, in plain language. Where possible, name the specific control:

> Add an explicit `Content-Security-Policy` response header. Suggested baseline: `default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'`.

If the fix has a known footgun (e.g. CSP breaks inline scripts), call it out.

## 8. References

- _OWASP WSTG link_
- _MDN / vendor docs_
- _Related CVE(s) if applicable_

---

_Filename convention: `<lower-case-id>-<slug>.md`, e.g. `vs-a05-001-missing-content-security-policy-header.md`. The scanner emits this exact shape when run with `--output md`, so a hand-written finding and a scanner-emitted finding are indistinguishable to the final report._
