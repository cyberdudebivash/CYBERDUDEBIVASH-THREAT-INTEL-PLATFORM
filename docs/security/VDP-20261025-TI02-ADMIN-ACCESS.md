# TI-02: Administrative frontend exposure — controlled remediation

**Status:** PENDING operator-controlled edge configuration and verification. This document is not evidence that production is protected.

## Security boundary
- Public `/admin` and `/admin.html` must not return administrative HTML or JavaScript to anonymous clients.
- Existing `ADMIN_SECRET` backend checks remain mandatory. Cloudflare Access is an additional boundary, not a replacement.
- Protect aliases, query variants, trailing-slash and case variants as applicable; verify the actual routing and redirects.
- Restrict an Access application to explicitly authorized operator identities, enforce MFA, and use least privilege. Do not use a shared public bypass token.
- Preserve a tested recovery path for authorized operators before enforcement. Do not commit secrets or Access credentials.

## Operator rollout
1. Identify the Cloudflare zone, Pages/Worker routing, static asset origin, redirects and all admin entry points. Confirm the authenticated admin workflow and known-good rollback.
2. Configure Cloudflare Access for the admin frontend routes. Test the policy with an authorized operator and a separate anonymous browser session.
3. Verify anonymous `GET /admin` and `GET /admin.html` cannot retrieve HTML/JS (redirect to Access login or 401/403). Confirm that no alternate static asset URL exposes the same admin bundle.
4. Verify authenticated operators can load the page and perform authorized admin API operations. Verify invalid `ADMIN_SECRET` remains denied.
5. Update `deploy/billing-canary/canary-lib.mjs`: the current `admin_page_complete` public check expects HTTP 200 and complete HTML, which conflicts with the required policy. Replace with a negative public-access assertion and a separate authenticated operator check.
6. Update `deploy/billing-canary/canary.test.mjs` and any browser tests expecting anonymous 200. Run locally; Actions availability is not assumed.
7. Capture redacted HTTP status evidence, Access policy identifiers, test results, change approval and rollback evidence. Never capture secrets in logs.

## Acceptance gates
- Anonymous and unauthorized identities cannot retrieve admin frontend assets.
- Authorized operator login and backend operations work.
- Public billing pages and customer journeys are unaffected.
- Canary and frontend tests match the enforced access boundary.
- Live production verification is documented before researcher closure.

**Do not enable a rule that could lock out the sole operator without first validating recovery access.**
