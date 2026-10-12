# Cybersecurity Log Analyzer

A beginner-friendly Streamlit dashboard that parses sample authentication logs, counts failed and successful login events, flags IP addresses that meet a configurable failed-login threshold, and exports parsed events as CSV.

## Features
- Upload `.txt` or `.log` files
- Built-in synthetic sample logs
- Configurable failed-login threshold
- Summary metrics and charts
- Parsed event table
- CSV export
- Investigation recommendations and limitations

## Requirements
- Python 3.10 or newer recommended
- pip

## Run locally (Windows PowerShell)
1. Open this folder in VS Code.
2. Create a virtual environment:

   ```powershell
   py -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```

3. Install dependencies:

   ```powershell
   python -m pip install -r requirements.txt
   ```

4. Start the app:

   ```powershell
   python -m streamlit run app.py
   ```

5. Open the local URL printed in the terminal, usually `http://localhost:8501`.

If PowerShell blocks activation, you can skip activation and run `.\.venv\Scripts\python.exe -m pip install -r requirements.txt`, then `.\.venv\Scripts\python.exe -m streamlit run app.py`.

## Sample log format
`2026-10-12 09:01:12 WARN login failed user=admin ip=198.51.100.23`

The parser uses simple text patterns. Your logs may require adapting the patterns.

## Security and privacy
Use synthetic sample data or logs you are authorized to analyze. Do not upload credentials, tokens, or sensitive production logs to public repositories or third-party hosting. The IPs in the sample file are documentation-only example addresses.

## Important limitations
This is an educational prototype, not a production SIEM. It does not prove malicious activity, validate IP addresses, perform network scanning, or replace professional incident response. Review alerts with context and follow your organization's procedures.

## Capstone deliverables
- [ ] Repository published to GitHub
- [ ] Security architecture documented
- [ ] Testing report completed with actual results
- [ ] Remediation guide completed
- [ ] Demo video recorded
- [ ] Live deployment tested
- [ ] LinkedIn post published
