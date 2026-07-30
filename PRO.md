# ASL V6 Pro Subscription

ASL V6 uses an open-core service model:

- **Community:** the complete local scanner, released under the MIT License.
- **Pro:** paid hosted and managed capabilities for teams and organizations.
- **Advisory:** separate human-led security reviews, remediation work, and compliance engagements.

## Pro Product Boundary

Pro should provide capabilities that require an ongoing service rather than hiding local scanner rules:

- Organization workspaces and role-based access.
- Central scan history, findings triage, and risk trends.
- Shared policy packs, suppressions, and severity gates.
- Scheduled repository scans.
- Managed GitHub PR reviews and SARIF ingestion.
- Compliance-ready exports and evidence retention.
- Priority updates and customer support.

## Subscription Security

The local client must not decide whether a payment is valid by matching license-key text. A production Pro service should:

1. Verify billing and subscription state on a trusted backend.
2. Issue short-lived, signed entitlement tokens.
3. Validate tenant and feature claims server-side.
4. Avoid logging raw license keys or repository secrets.
5. Support revocation, expiry, audit logs, and key rotation.

`ASL_PRO_LICENSE_KEY` only indicates that a key was configured. It does not unlock Pro locally until a trusted service verifies the entitlement.

## Before Selling Pro

- Deploy the entitlement and billing backend.
- Complete tenant-isolation and authorization tests.
- Publish pricing, terms of service, privacy policy, and support commitments.
- Validate the managed GitHub integration end to end.
- Define data retention and repository-source handling clearly.
