import sys
from pathlib import Path

import streamlit as st

import json
import pandas as pd

# ==========================================
# Project Path
# ==========================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


from scanner.scanner import scan_directory


# ==========================================
# Page Configuration
# ==========================================

st.set_page_config(
    page_title="AI Identity Security",
    page_icon="🔐",
    layout="wide"
)


# ==========================================
# Header
# ==========================================

st.title("🔐 AI Identity Security")
st.caption(
    "NHI Inventory & Risk Governance Dashboard"
)


# ==========================================
# Scan Configuration
# ==========================================

TARGET_DIRECTORY = PROJECT_ROOT / "test-target"

AUDIT_LOG_FILE = PROJECT_ROOT / "logs" / "audit.jsonl"


@st.cache_data
def load_audit_events():

    if not AUDIT_LOG_FILE.exists():
        return []

    events = []

    with open(
        AUDIT_LOG_FILE,
        "r",
        encoding="utf-8"
    ) as file:

        for line in file:

            line = line.strip()

            if not line:
                continue

            try:
                events.append(
                    json.loads(line)
                )

            except json.JSONDecodeError:
                continue

    return events

# ==========================================
# Run Scanner
# ==========================================

if st.button("🔄 Run NHI Scan"):

    st.cache_data.clear()


@st.cache_data
def run_scan():

    return scan_directory(
        str(TARGET_DIRECTORY)
    )


try:

    results = run_scan()

except Exception as error:

    st.error(
        f"Scanner failed: {error}"
    )

    st.stop()


if not results:

    st.warning(
        "No scan results available."
    )

    st.stop()


# ==========================================
# Extract Results
# ==========================================

risk_results = results.get(
    "risk_results",
    []
)

nhi_profiles = results.get(
    "nhi_profiles",
    []
)

credential_findings = results.get(
    "credential_findings",
    []
)

mcp_findings = results.get(
    "mcp_findings",
    []
)

# ==========================================
# Risk Summary Table
# ==========================================

table_data = []

for item in risk_results:

    profile = item["profile"]
    risk = item["risk"]

    table_data.append({
        "NHI": profile.name,
        "Role": profile.role,
        "Risk Score": risk["total_score"],
        "Severity": risk["severity"],
        "Credential": risk["credential_risk"],
        "Privilege": risk["privilege_risk"],
        "Exposure": risk["exposure_risk"],
        "Blast Radius": risk["blast_radius"],
    })

st.dataframe(
    table_data,
    use_container_width=True,
    hide_index=True
)


# ==========================================
# Overview Metrics
# ==========================================

total_nhis = len(nhi_profiles)

high_risk = sum(
    1
    for item in risk_results
    if item["risk"]["severity"] == "HIGH"
)

critical_risk = sum(
    1
    for item in risk_results
    if item["risk"]["severity"] == "CRITICAL"
)

medium_risk = sum(
    1
    for item in risk_results
    if item["risk"]["severity"] == "MEDIUM"
)

low_risk = sum(
    1
    for item in risk_results
    if item["risk"]["severity"] == "LOW"
)


st.subheader("Security Overview")


col1, col2, col3, col4, col5 = st.columns(5)

with col1:
    st.metric(
        "NHIs Discovered",
        total_nhis
    )

with col2:
    st.metric(
        "Critical",
        critical_risk
    )

with col3:
    st.metric(
        "High Risk",
        high_risk
    )

with col4:
    st.metric(
        "Medium Risk",
        medium_risk
    )

with col5:
    st.metric(
        "Low Risk",
        low_risk
    )


st.divider()


# ==========================================
# NHI Inventory
# ==========================================

st.subheader("NHI Inventory")


for item in risk_results:

    profile = item["profile"]
    risk = item["risk"]

    severity = risk["severity"]
    score = risk["total_score"]

    if severity == "CRITICAL":
        indicator = "🔴"

    elif severity == "HIGH":
        indicator = "🟠"

    elif severity == "MEDIUM":
        indicator = "🟡"

    else:
        indicator = "🟢"

    with st.expander(
        f"{indicator} {profile.name} — "
        f"{score}/100 ({severity})"
    ):

        col1, col2 = st.columns(2)

        # ----------------------------------
        # Identity Information
        # ----------------------------------

        with col1:

            st.markdown("### Identity")

            st.write(
                f"**Name:** {profile.name}"
            )

            st.write(
                f"**Type:** "
                f"{profile.identity_type}"
            )

            st.write(
                f"**Role:** {profile.role}"
            )

        # ----------------------------------
        # Credentials
        # ----------------------------------

        with col2:

            st.markdown("### Credentials")

            if profile.credentials:

                for credential in profile.credentials:

                    st.write(
                        f"🔑 {credential.name} "
                        f"({credential.provider})"
                    )

            else:

                st.write(
                    "No correlated credentials"
                )


        # ==================================
        # Tools
        # ==================================

        st.markdown("### Tools")

        if profile.tools:

            for tool in profile.tools:

                st.write(
                    f"🛠️ **{tool.name}**"
                )

                for permission in tool.permissions:

                    st.write(
                        f"　└─ `{permission}`"
                    )

        else:

            st.write("No tools detected")


        # ==================================
        # MCP Servers
        # ==================================

        st.markdown("### MCP Servers")

        if profile.mcp_servers:

            for server in profile.mcp_servers:

                st.write(
                    f"🔌 **{server.name}**"
                )

                for permission in server.permissions:

                    st.write(
                        f"　└─ `{permission}`"
                    )

        else:

            st.write(
                "No MCP servers associated"
            )


        # ==================================
        # Risk Assessment
        # ==================================

        st.markdown("### Risk Assessment")

        r1, r2 = st.columns(2)

        with r1:

            st.metric(
                "Credential Risk",
                f"{risk['credential_risk']}/25"
            )

            st.metric(
                "Privilege Risk",
                f"{risk['privilege_risk']}/30"
            )

        with r2:

            st.metric(
                "Exposure Risk",
                f"{risk['exposure_risk']}/20"
            )

            st.metric(
                "Blast Radius",
                f"{risk['blast_radius']}/25"
            )


        st.progress(score / 100)

        st.write(
            f"**Total Risk: "
            f"{score}/100 — {severity}**"
        )

        # ==================================
        # Risk Breakdown
        # ==================================

        st.markdown("#### Risk Breakdown")

        risk_breakdown = {
            "Credential Risk": risk["credential_risk"],
            "Privilege Risk": risk["privilege_risk"],
            "Exposure Risk": risk["exposure_risk"],
            "Blast Radius": risk["blast_radius"],
        }

        risk_maximums = {
            "Credential Risk": 25,
            "Privilege Risk": 30,
            "Exposure Risk": 20,
            "Blast Radius": 25,
        }

        for category, value in risk_breakdown.items():

            maximum = risk_maximums[category]

            percentage = value / maximum

            st.write(
                f"**{category}:** "
                f"{value}/{maximum}"
            )

            st.progress(percentage)


st.divider()


# ==========================================
# Repository Findings
# ==========================================

st.subheader("Repository Security Findings")

f1, f2, f3 = st.columns(3)

with f1:

    st.metric(
        "Credential Findings",
        len(credential_findings)
    )

with f2:

    st.metric(
        "MCP Servers",
        len(mcp_findings)
    )

with f3:

    st.metric(
        "Total Findings",
        results.get(
            "total_findings",
            0
        )
    )


# ==========================================
# Scan Information
# ==========================================

st.divider()

st.caption(
    f"Scanned directory: "
    f"{results.get('directory', 'Unknown')}"
)


# ==========================================
# IAM Activity
# ==========================================

st.divider()

st.subheader("🔐 IAM Activity")


audit_events = load_audit_events()


if not audit_events:

    st.info(
        "No IAM audit events available yet."
    )

else:

    # --------------------------------------
    # Convert events to DataFrame
    # --------------------------------------

    audit_df = pd.DataFrame(
        audit_events
    )

    # --------------------------------------
    # Activity Metrics
    # --------------------------------------

    total_events = len(audit_df)

    granted_events = len(
        audit_df[
            audit_df["result"] == "GRANTED"
        ]
    )

    denied_events = len(
        audit_df[
            audit_df["result"] == "DENIED"
        ]
    )

    revoked_events = len(
        audit_df[
            audit_df["result"] == "REVOKED"
        ]
    )


    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric(
            "Total Events",
            total_events
        )

    with col2:
        st.metric(
            "Granted",
            granted_events
        )

    with col3:
        st.metric(
            "Denied",
            denied_events
        )

    with col4:
        st.metric(
            "Revoked",
            revoked_events
        )


    # --------------------------------------
    # Activity Table
    # --------------------------------------

    st.markdown(
        "### Recent IAM Events"
    )

    display_columns = [
        "timestamp",
        "event_type",
        "agent",
        "permission",
        "task_id",
        "result",
    ]

    available_columns = [
        column
        for column in display_columns
        if column in audit_df.columns
    ]

    st.dataframe(
        audit_df[
            available_columns
        ].sort_values(
            "timestamp",
            ascending=False
        ),
        use_container_width=True,
        hide_index=True
    )