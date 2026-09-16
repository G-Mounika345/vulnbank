# VulnBank — Intentionally Vulnerable Banking App (OWASP Top 10, 2021)

A small Spring Boot "banking" app built **on purpose** with OWASP Top 10
(2021) vulnerabilities baked in, so you can practice finding and exploiting
them with Burp Suite. Same spirit as OWASP WebGoat / Juice Shop, just a
banking theme and small enough to read end-to-end.

> ⚠️ **Run this only on your own machine, on `localhost`, inside a network
> you control.** Never deploy it to a shared server or expose it to the
> internet — it is deliberately broken.

## Requirements
- Java 11+
- Maven 3.6+
- Burp Suite (Community edition is fine)

## Run it
```bash
cd vulnbank
mvn spring-boot:run
```
App comes up on `http://localhost:8080`. Seed logins:
- `alice` / `password123`
- `bob` / `password123`
- `admin` / `admin`

H2 console: `http://localhost:8080/h2-console` (JDBC URL `jdbc:h2:mem:vulnbank`, user `sa`, blank password).
Actuator: `http://localhost:8080/actuator`

## Burp Suite setup
1. In Burp, go to **Proxy → Options**, confirm listener `127.0.0.1:8080`... actually use Burp's default `127.0.0.1:8080` for the *proxy*, and point your browser at the app through Burp using **FoxyProxy** or Burp's built-in Chromium browser (**Proxy → Intercept → Open Browser**).
2. Browse to `http://localhost:8080/login` through that proxied browser so every request lands in **Proxy → HTTP history**.
3. Right-click interesting requests → **Send to Repeater** to manually tamper with parameters, or **Send to Intruder** to fuzz/brute-force them.

## Vulnerability map (OWASP Top 10:2021)

| Category | Where | How to trigger in Burp |
|---|---|---|
| **A01 Broken Access Control** | `GET /account/{id}` (IDOR), `GET /accounts`, `POST /account/{id}/balance`, `/admin/debug/all-data` | Log in as alice, in Repeater change `/account/1` → `/account/3` to read admin's balance with no ownership check. |
| **A02 Cryptographic Failures** | MD5 password hashing (`AuthController.md5`), hardcoded JWT secret in `JwtUtil`/`application.properties`, non-HttpOnly/non-Secure session cookie | Inspect the `VULNBANK_TOKEN` cookie in Proxy → it has no `HttpOnly`/`Secure`/`SameSite`; decode the JWT at jwt.io, then re-sign a forged token with the leaked secret. |
| **A03 Injection** | `POST /login/debug` (raw SQLi), reflected XSS at `GET /search?q=`, stored XSS via `POST /messages` | Send `username=admin' --` to `/login/debug` in Repeater; send `<script>alert(1)</script>` as `q` to `/search`. |
| **A04 Insecure Design** | `POST /transfer` has no per-transaction cap, no re-auth, allows negative balances; `POST /profile/upload-picture` has no file-type/size limits | Script (or Repeater-replay) many `/transfer` calls to drain an account with no friction. |
| **A05 Security Misconfiguration** | CSRF disabled + CORS `*` in `SecurityConfig`, `/actuator/**` fully exposed, verbose stack traces, XXE in `/profile/import` (missing secure XML parser flags), open `/h2-console` | Hit `/actuator/env` to see config/secrets dumped; send the XXE payload in the README's ProfileController comment to `/profile/import`. |
| **A06 Vulnerable & Outdated Components** | `pom.xml` pins Spring Boot 2.7.5 and `jjwt` 0.9.1 on purpose | Run `mvn versions:display-dependency-updates` or an SCA tool like OWASP Dependency-Check against the project. |
| **A07 Identification & Authentication Failures** | No account lockout / rate limiting on `/login`, tokens never expire, weak default passwords | Use Burp Intruder against `/login` with a small password list to brute-force `admin`. |
| **A08 Software & Data Integrity Failures** | XML import in `/profile/import` trusts client-supplied structure/content with no integrity check; no dependency/artifact signing checks anywhere in the build | Combine with A05's XXE entry to show untrusted data flowing straight into parsing/output. |
| **A09 Security Logging & Monitoring Failures** | `AdminController` — failed "auth" attempts and admin data dumps are never logged | Hit `/admin/users` with wrong and right keys back-to-back and note there's nothing in app logs distinguishing an attack from normal use. |
| **A10 SSRF** | `GET /currency/rate?source=` fetches any URL server-side | In Repeater, try `source=http://localhost:8080/actuator/env` to pivot past a "no direct internet access" boundary, or a cloud metadata IP if you deploy this in a cloud VM for the exercise. |

Every vulnerable method has a comment in the source (`// VULNERABLE:` or a
class/method Javadoc) explaining exactly what's wrong and a suggested Burp
payload — read the code alongside your testing, not just the table above.

## Suggested exercise order
1. **Recon** — crawl the app through Burp, note every endpoint in Proxy history.
2. **A03 SQLi** on `/login/debug`, then real login bypass on `/login`.
3. **A01 IDOR** on `/account/{id}` and `/accounts`.
4. **A03 XSS** — reflected on `/search`, stored on `/messages`.
5. **A05 CSRF** — build the auto-submitting HTML form from `TransferController`'s comment, host it locally, open it while logged into VulnBank.
6. **A02** — decode/forge the JWT cookie.
7. **A01 path traversal** — `/statements/download?filename=../../../../etc/passwd`.
8. **A05 XXE** — `/profile/import`.
9. **A10 SSRF** — `/currency/rate`.
10. **A05 misconfig** — poke `/actuator/env`, `/actuator/heapdump`, `/h2-console`.

## Using Claude alongside Burp Suite (see full write-up in chat)
This README's companion explanation covers three practical integration
patterns: (1) manually pasting captured requests/responses into Claude for
analysis, (2) a custom Burp extension (Java, Montoya API) that calls the
Claude API to auto-annotate traffic, and (3) using Claude Code to help you
build/modify this lab and write your own PoC scripts.
