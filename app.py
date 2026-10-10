import streamlit as st
import pandas as pd

from analyzer import analyze_rules, simulate_traffic


EXPLAINABLE_FINDING_COLUMNS = {
    "Evidence",
    "Potential Impact",
    "Investigation Priority",
    "Assessment Scope",
}


st.set_page_config(
    page_title="Firewall Sentinel",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

with st.container(border=True):
    title_col, status_col = st.columns([5, 2], vertical_alignment="center")
    with title_col:
        st.title("Firewall Sentinel", icon=":material/shield:")
        st.caption("Firewall policy intelligence console")
    with status_col:
        st.badge(
            "Read-only analysis",
            icon=":material/verified_user:",
            color="primary",
        )
        st.caption("No firewall changes or network connections")

with st.sidebar:
    st.title("Firewall Sentinel", icon=":material/shield:")
    st.caption("POLICY INTELLIGENCE CONSOLE")
    st.badge(
        "Read-only workspace",
        icon=":material/visibility:",
        color="primary",
    )
    st.header("Workspace", icon=":material/grid_view:", divider="blue")
    page = st.radio(
        "Choose a section",
        [
            "Dashboard",
            "Firewall Analysis",
            "Traffic Simulator",
            "Security Reports",
        ],
    )

# Store results between Streamlit reruns.
if "findings" not in st.session_state:
    st.session_state.findings = pd.DataFrame()

if "security_score" not in st.session_state:
    st.session_state.security_score = None

if "rules_count" not in st.session_state:
    st.session_state.rules_count = 0

if "loaded_rules" not in st.session_state:
    st.session_state.loaded_rules = None


if page == "Dashboard":
    st.header(
        "Security posture",
        icon=":material/monitoring:",
        divider="blue",
    )
    st.caption(
        "A compact view of the latest rule analysis and investigation load."
    )

    findings = st.session_state.findings
    score = st.session_state.security_score
    severities = findings.get("Severity", pd.Series(dtype="string"))

    critical = int((severities == "Critical").sum())
    high = int((severities == "High").sum())

    col1, col2, col3, col4 = st.columns(4)
    with col1.container(border=True):
        st.metric("Rules Analyzed", st.session_state.rules_count)
    with col2.container(border=True):
        st.metric("Critical Findings", critical)
    with col3.container(border=True):
        st.metric("High-Risk Findings", high)
    with col4.container(border=True):
        st.metric(
            "Security Score",
            f"{score}/100" if score is not None else "—",
        )

    if findings.empty:
        with st.container(border=True):
            st.info(
                "No analysis results yet. Open Firewall Analysis "
                "to upload or generate sample rules.",
                icon=":material/info:",
            )
    else:
        st.subheader("Security analytics", icon=":material/analytics:")
        chart_col, summary_col = st.columns([3, 2])

        with chart_col.container(border=True):
            st.subheader("Findings by severity", icon=":material/bar_chart:")
            severity_counts = (
                severities.value_counts()
                .reindex(
                    ["Critical", "High", "Medium", "Low"],
                    fill_value=0,
                )
                .rename_axis("Severity")
                .reset_index(name="Count")
            )
            st.bar_chart(
                severity_counts,
                x="Severity",
                y="Count",
                alt="Security findings grouped by severity",
            )

        with summary_col.container(border=True):
            st.subheader("Finding summary", icon=":material/summarize:")
            st.write(f"**Total findings:** {len(findings)}")
            st.write(f"**Critical:** {critical}")
            st.write(f"**High:** {high}")
            st.write(f"**Medium:** {int((severities == 'Medium').sum())}")
            st.write(f"**Low:** {int((severities == 'Low').sum())}")

        with st.container(border=True):
            st.subheader(
                "Detailed security findings",
                icon=":material/manage_search:",
            )
            st.dataframe(
                findings,
                hide_index=True,
                alt="Detailed firewall security findings",
            )


elif page == "Firewall Analysis":
    st.header(
        "Firewall rule analysis",
        icon=":material/policy:",
        divider="blue",
    )
    st.caption(
        "Upload a rule export or use the demonstration set. Analysis is "
        "read-only and produces review recommendations."
    )

    required_columns = [
        "rule_id",
        "source",
        "destination",
        "port",
        "protocol",
        "action",
    ]

    sample_data = pd.DataFrame([
        {
            "rule_id": "R001",
            "source": "Any",
            "destination": "Any",
            "port": "Any",
            "protocol": "Any",
            "action": "Allow",
        },
        {
            "rule_id": "R002",
            "source": "192.168.1.10",
            "destination": "10.0.0.5",
            "port": "443",
            "protocol": "TCP",
            "action": "Allow",
        },
        {
            "rule_id": "R003",
            "source": "Any",
            "destination": "10.0.0.5",
            "port": "22",
            "protocol": "TCP",
            "action": "Allow",
        },
        {
            "rule_id": "R004",
            "source": "192.168.1.10",
            "destination": "10.0.0.5",
            "port": "443",
            "protocol": "TCP",
            "action": "Allow",
        },
        {
            "rule_id": "R005",
            "source": "192.168.1.0/24",
            "destination": "10.0.0.8",
            "port": "80",
            "protocol": "TCP",
            "action": "Deny",
        },
    ])

    with st.container(border=True):
        st.subheader("Rule source", icon=":material/source:")
        upload_col, demo_col = st.columns([3, 1], vertical_alignment="bottom")
        with upload_col:
            uploaded_file = st.file_uploader(
                "Upload firewall rules",
                type=["csv"],
            )
        with demo_col:
            st.caption("Need a test set?")
            load_demo = st.button("Load Demo Rules")

    if load_demo:
        st.session_state.demo_rules = sample_data

    if uploaded_file is not None:
        try:
            rules = pd.read_csv(uploaded_file, dtype=str).fillna("")
            with st.container(border=True):
                st.subheader("Uploaded rules", icon=":material/upload_file:")
                st.dataframe(
                    rules,
                    hide_index=True,
                    alt="Uploaded firewall rule set",
                )
        except Exception as error:
            st.error(f"Could not read the CSV file: {error}")
            rules = None

    elif "demo_rules" in st.session_state:
        rules = st.session_state.demo_rules
        with st.container(border=True):
            st.subheader(
                "Demonstration rules",
                icon=":material/dataset:",
            )
            st.dataframe(
                rules,
                hide_index=True,
                alt="Demonstration firewall rule set",
            )

    else:
        rules = None

    if rules is not None:
        # Retain the most recently loaded CSV or demo rules for simulation.
        st.session_state.loaded_rules = rules.copy()

        if st.button("Analyze Firewall Rules", type="primary"):
            try:
                findings, score, validation = analyze_rules(rules)

                st.session_state.findings = findings
                st.session_state.security_score = score
                st.session_state.rules_count = len(rules)
                st.session_state.validation = validation

                st.success(
                    "Firewall analysis completed!",
                    icon=":material/check_circle:",
                )

            except ValueError as error:
                st.error(str(error))

    if not st.session_state.findings.empty:
        findings = st.session_state.findings

        st.subheader("Security findings", icon=":material/security:")

        severity_filter = st.multiselect(
            "Filter by severity",
            ["Critical", "High", "Medium", "Low"],
            default=["Critical", "High", "Medium", "Low"],
        )

        filtered = findings[
            findings["Severity"].isin(severity_filter)
        ]

        with st.container(border=True):
            st.dataframe(
                filtered,
                hide_index=True,
                alt="Filtered firewall security findings",
            )

            if filtered.empty:
                st.info("No findings match the selected severity filter.")
            elif not EXPLAINABLE_FINDING_COLUMNS.issubset(filtered.columns):
                st.info(
                    "These findings were created before Explainable Risk "
                    "Analysis was added. Click Analyze Firewall Rules to "
                    "refresh the findings with evidence and investigation "
                    "details."
                )
            else:
                inspectable_findings = filtered.reset_index(drop=True)
                finding_options = list(range(len(inspectable_findings)))
                selected_position = st.selectbox(
                    "Inspect a finding",
                    finding_options,
                    format_func=lambda position: (
                        f"{inspectable_findings.iloc[position]['Rule ID']} — "
                        f"{inspectable_findings.iloc[position]['Issue']}"
                    ),
                )
                selected_finding = inspectable_findings.iloc[selected_position]

                with st.container(border=True):
                    st.subheader(
                        "Finding explanation",
                        icon=":material/lightbulb:",
                    )
                    st.write(
                        f"**Affected rule:** {selected_finding['Rule ID']}"
                    )
                    st.write(
                        f"**Severity:** {selected_finding['Severity']}"
                    )
                    st.write(
                        "**Investigation priority:** "
                        f"{selected_finding['Investigation Priority']}"
                    )
                    st.write(
                        f"**Evidence:** {selected_finding['Evidence']}"
                    )
                    st.write(
                        "**Potential impact:** "
                        f"{selected_finding['Potential Impact']}"
                    )
                    st.write(
                        "**Recommendation:** "
                        f"{selected_finding['Recommendation']}"
                    )
                    st.info(selected_finding["Assessment Scope"])

        validation = st.session_state.get("validation", [])

        if validation:
            with st.container(border=True):
                st.subheader(
                    "Input validation messages",
                    icon=":material/fact_check:",
                )
                st.dataframe(
                    pd.DataFrame(validation),
                    hide_index=True,
                    alt="Firewall rule validation messages",
                )

        st.download_button(
            "Download Audit Report",
            data=findings.to_csv(index=False).encode("utf-8"),
            file_name="firewall_security_report.csv",
            mime="text/csv",
        )


elif page == "Traffic Simulator":
    st.header(
        "Traffic simulator",
        icon=":material/route:",
        divider="blue",
    )
    st.caption(
        "Read-only policy simulation using a simplified first-match model "
        "in CSV row order. No matching rule means DENY under an implicit-"
        "deny assumption."
    )

    loaded_rules = st.session_state.loaded_rules

    if loaded_rules is None:
        with st.container(border=True):
            st.info(
                "Load demo rules or upload a CSV in Firewall Analysis before "
                "running a traffic simulation.",
                icon=":material/info:",
            )
    else:
        with st.container(border=True):
            st.badge(
                f"{len(loaded_rules)} rules loaded",
                icon=":material/rule:",
                color="primary",
            )
            st.caption("Define one traffic flow to evaluate against the policy.")

            with st.form("traffic_simulator"):
                source_col, destination_col = st.columns(2)
                with source_col:
                    source = st.text_input(
                        "Source IP address",
                        value="192.168.1.10",
                    )
                with destination_col:
                    destination = st.text_input(
                        "Destination IP address",
                        value="10.0.0.5",
                    )

                port_col, protocol_col = st.columns(2)
                with port_col:
                    port = st.number_input(
                        "Destination port",
                        min_value=1,
                        max_value=65535,
                        value=443,
                        step=1,
                    )
                with protocol_col:
                    protocol = st.selectbox(
                        "Protocol",
                        ["TCP", "UDP", "ICMP"],
                    )

                submitted = st.form_submit_button(
                    "Simulate Traffic",
                    type="primary",
                )

        if submitted:
            result = simulate_traffic(
                loaded_rules,
                source,
                destination,
                port,
                protocol,
            )

            if result["errors"]:
                st.error("Simulation input error: " + "; ".join(result["errors"]))
            else:
                with st.container(border=True):
                    st.subheader(
                        "Simulation result",
                        icon=":material/terminal:",
                    )

                    result_col, rule_col, checked_col = st.columns(3)
                    with result_col:
                        st.metric("Decision", result["decision"])
                    with rule_col:
                        st.metric(
                            "First matching rule",
                            result["matched_rule_id"] or "None",
                        )
                    with checked_col:
                        st.metric(
                            "Earlier rules checked",
                            result["earlier_rules_checked"],
                        )

                    if result["decision"] == "ALLOW":
                        st.success(
                            "The first matching rule allows this traffic.",
                            icon=":material/check_circle:",
                        )
                    else:
                        st.info(
                            "The simulator denies this traffic.",
                            icon=":material/block:",
                        )

                    st.write(f"**Why:** {result['reason']}")

                    if result["later_shadowed_rule_ids"]:
                        st.warning(
                            "For this traffic, later opposite-action rules may "
                            "be shadowed: "
                            + ", ".join(result["later_shadowed_rule_ids"])
                        )

                    if result["invalid_rule_ids"]:
                        st.warning(
                            "Ignored invalid rules during simulation: "
                            + ", ".join(result["invalid_rule_ids"])
                        )


elif page == "Security Reports":
    st.header(
        "Security reports",
        icon=":material/description:",
        divider="blue",
    )
    st.caption("Review the latest findings or export a CSV audit report.")

    findings = st.session_state.findings

    if findings.empty:
        with st.container(border=True):
            st.info(
                "Run an analysis to generate a report.",
                icon=":material/info:",
            )
    else:
        rules_col, score_col, findings_col = st.columns(3)
        with rules_col.container(border=True):
            st.metric("Rules analyzed", st.session_state.rules_count)
        with score_col.container(border=True):
            st.metric(
                "Security score",
                f"{st.session_state.security_score}/100",
            )
        with findings_col.container(border=True):
            st.metric("Findings exported", len(findings))

        with st.container(border=True):
            st.subheader("Audit report preview", icon=":material/table_chart:")
            st.dataframe(
                findings,
                hide_index=True,
                alt="Firewall security audit report",
            )
            st.download_button(
                "Download Security Report",
                data=findings.to_csv(index=False).encode("utf-8"),
                file_name="firewall_security_report.csv",
                mime="text/csv",
            )


with st.container(border=True):
    st.caption(
        "Firewall Sentinel · Read-only security analysis · "
        "Verify findings against your firewall's policy semantics."
    )
