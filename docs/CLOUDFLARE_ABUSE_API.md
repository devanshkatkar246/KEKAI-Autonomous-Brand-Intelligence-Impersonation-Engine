# Cloudflare Abuse Reports API (verified 2026-08-23)

Cloudflare documents `POST /accounts/{account_id}/abuse-reports/{report_param}` at its [Abuse Reports API reference](https://developers.cloudflare.com/api/resources/abuse_reports/methods/create/). It uses a bearer API token and requires the Abuse Reports entitlement (Enterprise by default; other accounts request access) plus `Account > Abuse Reports > Edit`. KEIKAI uses `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID` only on the server.

For phishing, the official schema is the `abuse_phishing` report type and requires reporter identity/contact, notification choices, a justification, and newline-separated URLs for one hostname. Successful creation returns `abuse_rand`; Cloudflare also documents report details/list endpoints. The API reference does not document an idempotency header, so KEIKAI must use its own snapshot fingerprint and never retry an ambiguous timeout.

KEIKAI policy: default `ABUSE_SUBMISSION_MODE=DRY_RUN`; LIVE requires explicit server configuration, a frozen human-approved snapshot, evidence revalidation, and the trusted `https://api.cloudflare.com/client/v4` endpoint. Screenshots/hashes are kept in KEIKAI evidence; the documented JSON schema has no screenshot attachment field, so they are not fabricated into the Cloudflare payload.
