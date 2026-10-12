# Security Architecture

## Purpose
The Cybersecurity Log Analyzer is a small educational application for analyzing user-supplied text logs.

## Data flow
1. User selects a `.txt` or `.log` file in the browser.
2. Streamlit receives the uploaded bytes for the current app session.
3. The app decodes the text and parses each non-empty line.
4. Simple patterns identify likely failed/successful logins, usernames, severity labels, and IPv4-like strings.
5. The dashboard aggregates counts, flags IPs meeting the selected threshold, and displays findings.
6. User may download the parsed event table as CSV.

## Components
- User interface: Streamlit
- Processing: Python regular expressions and collections
- Tabular data: pandas
- Input: uploaded text log or bundled synthetic sample
- Output: dashboard tables/charts and CSV export

## Security considerations
- Analyze only synthetic or explicitly authorized logs.
- Avoid real secrets and personal data in demo files.
- Do not commit production logs, credentials, tokens, or private IP/customer data.
- Use HTTPS and platform secrets/settings when deployed.
- Limit access to the hosted application if analyzing non-public information; preferably use synthetic data only.
- Apply file size limits and stronger parsing/validation before production use.
- Review dependencies and update them as needed.
- The prototype is not designed for multi-tenant use or production incident response.

## Trust boundaries
The uploaded file is untrusted input. Parsing is text-based and does not execute the file. Still, production versions should enforce size limits, validate content, and handle malformed input safely.

## Known limitations
- Pattern-based parsing may miss alternate log formats or misclassify messages.
- IP extraction does not validate octets.
- A repeated failed-login pattern can be caused by legitimate mistakes and is not proof of an attack.
- No authentication, persistent storage, alert delivery, or SIEM integration is implemented.
