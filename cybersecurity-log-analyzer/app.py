import re
from collections import Counter
from io import StringIO

import pandas as pd
import streamlit as st

st.set_page_config(page_title="Cybersecurity Log Analyzer", page_icon="🛡️", layout="wide")

st.title("🛡️ Cybersecurity Log Analyzer")
st.caption("Analyze sample authentication logs and identify patterns that may warrant investigation.")
st.warning("Use only sample data or logs you are authorized to analyze. Alerts are indicators for review, not proof of compromise.")

DEFAULT_LOG = """2026-10-12 09:00:01 INFO login success user=alex ip=192.0.2.10
2026-10-12 09:01:12 WARN login failed user=admin ip=198.51.100.23
2026-10-12 09:01:20 WARN login failed user=admin ip=198.51.100.23
2026-10-12 09:01:28 WARN login failed user=admin ip=198.51.100.23
2026-10-12 09:02:04 INFO login success user=sam ip=192.0.2.15
2026-10-12 09:05:19 WARN login failed user=guest ip=203.0.113.7
2026-10-12 09:05:31 WARN login failed user=guest ip=203.0.113.7
2026-10-12 09:08:43 INFO login success user=alex ip=192.0.2.10
2026-10-12 09:10:00 INFO password reset user=sam ip=192.0.2.15
"""

with st.sidebar:
    st.header("Analysis settings")
    threshold = st.slider("Failed logins to flag per IP", min_value=2, max_value=10, value=3)
    st.write("Accepted example format:")
    st.code("2026-10-12 09:01:12 WARN login failed user=admin ip=198.51.100.23", language="text")

uploaded = st.file_uploader("Upload a .txt or .log file", type=["txt", "log"])
if uploaded:
    try:
        raw_text = uploaded.getvalue().decode("utf-8", errors="replace")
        source_name = uploaded.name
    except Exception:
        raw_text = ""
        source_name = "uploaded file"
else:
    st.info("Showing built-in synthetic sample data. Upload your own authorized sample log to analyze it.")
    raw_text = DEFAULT_LOG
    source_name = "built-in sample logs"

ip_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
user_pattern = re.compile(r"\buser=([A-Za-z0-9_.@-]+)")
failed_pattern = re.compile(r"\b(failed|failure|denied|invalid password|authentication failure)\b", re.I)
success_pattern = re.compile(r"\b(success|successful|logged in)\b", re.I)
severity_pattern = re.compile(r"\b(INFO|WARN|WARNING|ERROR|CRITICAL|DEBUG)\b", re.I)

records = []
for line_number, line in enumerate(raw_text.splitlines(), start=1):
    if not line.strip():
        continue
    ip_match = ip_pattern.search(line)
    user_match = user_pattern.search(line)
    severity_match = severity_pattern.search(line)
    is_failed = bool(failed_pattern.search(line))
    is_success = bool(success_pattern.search(line)) and not is_failed
    records.append({
        "Line": line_number,
        "Event": line.strip(),
        "IP Address": ip_match.group(0) if ip_match else "Unknown",
        "User": user_match.group(1) if user_match else "Unknown",
        "Severity": severity_match.group(1).upper() if severity_match else "UNSPECIFIED",
        "Failed Login": is_failed,
        "Successful Login": is_success,
    })

df = pd.DataFrame(records)
if df.empty:
    st.error("No non-empty log lines were found. Upload a text log file and try again.")
    st.stop()

failed_df = df[df["Failed Login"]]
success_count = int(df["Successful Login"].sum())
failed_count = int(df["Failed Login"].sum())
ip_counts = Counter(ip for ip in failed_df["IP Address"] if ip != "Unknown")
flagged_ips = {ip: count for ip, count in ip_counts.items() if count >= threshold}
suspicious_lines = df[df["IP Address"].isin(flagged_ips.keys())] if flagged_ips else df.iloc[0:0]

c1, c2, c3, c4 = st.columns(4)
c1.metric("Total log events", len(df))
c2.metric("Failed login events", failed_count)
c3.metric("Successful login events", success_count)
c4.metric("IPs flagged for review", len(flagged_ips))

st.subheader("Summary")
st.write(f"**Source:** {source_name}")
st.write(f"**Detection threshold:** {threshold} failed login events per IP address.")
if flagged_ips:
    st.warning("One or more IP addresses meet the configured failed-login threshold. Investigate context before concluding malicious activity.")
    summary_df = pd.DataFrame([{"IP Address": ip, "Failed logins": count, "Review status": "Investigate"} for ip, count in sorted(flagged_ips.items(), key=lambda item: item[1], reverse=True)])
    st.dataframe(summary_df, use_container_width=True, hide_index=True)
else:
    st.success("No IP address met the configured failed-login threshold in the analyzed data.")

left, right = st.columns(2)
with left:
    st.subheader("Events by type")
    event_counts = pd.DataFrame({
        "Event type": ["Failed login", "Successful login", "Other / unclassified"],
        "Count": [failed_count, success_count, len(df) - failed_count - success_count]
    })
    st.bar_chart(event_counts.set_index("Event type"))
with right:
    st.subheader("Failed logins by IP")
    if ip_counts:
        ip_df = pd.DataFrame([{"IP Address": ip, "Failed logins": count} for ip, count in ip_counts.most_common()])
        st.bar_chart(ip_df.set_index("IP Address"))
    else:
        st.write("No failed-login events detected with the supported patterns.")

st.subheader("Parsed log events")
st.dataframe(df, use_container_width=True, hide_index=True)

st.subheader("Recommended next steps")
if flagged_ips:
    st.markdown("- Verify whether the activity is expected and check the relevant account and time window.\n- Correlate with MFA, endpoint, VPN, and application logs where authorized.\n- Escalate according to your incident response policy if compromise is suspected.\n- Consider rate limiting or account protection controls after validation and approval.")
else:
    st.markdown("- Review parsing coverage and confirm that the sample log format matches the supported patterns.\n- Continue monitoring and correlate with other authorized log sources when appropriate.")

report_csv = df.to_csv(index=False).encode("utf-8")
st.download_button("Download parsed events as CSV", data=report_csv, file_name="parsed_log_events.csv", mime="text/csv")
st.caption("Limitations: this prototype uses simple text patterns, does not validate IP addresses, and may miss events or flag benign activity. It is a learning project, not a production SIEM.")
