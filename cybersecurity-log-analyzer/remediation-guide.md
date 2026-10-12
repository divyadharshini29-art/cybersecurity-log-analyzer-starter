# Investigation and Remediation Guide

These are general recommendations for an authorized environment. Validate findings and follow organizational policy before taking action.

## When repeated failed logins are flagged
1. Confirm the timestamps, account, source address, and threshold.
2. Compare activity with expected user behavior and related authentication logs.
3. Review MFA prompts, VPN records, and endpoint telemetry if available and authorized.
4. If compromise is suspected, escalate to the responsible security team.
5. Under approved procedures, consider rate limiting, MFA enforcement, password reset, session revocation, or temporary account protection.
6. Preserve relevant logs and document all actions.
7. Monitor for recurrence and record the outcome.

## Preventive controls
- Enable MFA, especially for privileged accounts.
- Apply rate limiting and sensible lockout or throttling controls.
- Use unique passwords and a password manager.
- Monitor authentication activity and tune alert thresholds.
- Restrict administrative access and follow least privilege.
- Keep systems patched and logs time-synchronized.
- Train users to report unexpected authentication prompts.

## Important
An IP address can be shared, proxied, spoofed in some contexts, or used by legitimate users. A repeated-failure alert alone does not establish malicious intent. Avoid blocking accounts or addresses without validation and appropriate authorization.
