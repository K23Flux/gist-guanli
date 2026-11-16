# Security Policy

## Reporting

Please report vulnerabilities through GitHub's private vulnerability reporting
(Security → Advisories). Do not open a public issue containing real share URLs,
tokens, node credentials, server addresses, or subscription content.

## Operational boundary

`/s/{slug}/{token}/{filename}` links are bearer credentials in the URL path.
Reverse proxies must not record the full URI in access or error logs, and
public monitoring must not receive these URLs. Secret or unlisted Gists are
not an access-control boundary; anyone who obtains the original raw URL can
bypass this gateway.

Successful fetches store the time and client IP in SQLite, keeping the latest
30 per share. This history is visible only to the administrator; treat the
database and its backups as sensitive. Enable `--trust-proxy` only when the
reverse proxy overwrites, rather than appends, client-supplied forwarding
headers.
