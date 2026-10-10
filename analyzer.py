import ipaddress
import pandas as pd


ADMIN_PORTS = {
    22: "SSH",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    5985: "WinRM HTTP",
    5986: "WinRM HTTPS",
}

REQUIRED_RULE_COLUMNS = {
    "rule_id",
    "source",
    "destination",
    "port",
    "protocol",
    "action",
}

SIMULATOR_PROTOCOLS = {"TCP", "UDP", "ICMP"}

CONFIGURATION_FINDING_SCOPE = (
    "Configuration-based finding only; it does not prove that a service "
    "is reachable or exploitable."
)

FIRST_MATCH_ASSUMPTION = (
    "Conflict analysis assumes rules are evaluated in CSV row order "
    "by a first-match firewall."
)


def is_any(value):
    """Check whether a field represents unrestricted scope."""
    return str(value).strip().lower() in {
        "any", "*", "all", "0.0.0.0/0", "::/0"
    }


def normalize(value):
    """Normalize values for comparisons."""
    return str(value).strip().lower()


def parse_network(value):
    """Return an IP network for a validated address or CIDR value."""
    return ipaddress.ip_network(str(value).strip(), strict=False)


def network_contains(container, contained):
    """Return whether one source or destination scope contains another."""
    if is_any(container):
        return True

    if is_any(contained):
        return False

    try:
        container_network = parse_network(container)
        contained_network = parse_network(contained)
    except ValueError:
        return False

    return (
        container_network.version == contained_network.version
        and contained_network.subnet_of(container_network)
    )


def networks_overlap(first, second):
    """Return whether two source or destination scopes overlap."""
    if is_any(first) or is_any(second):
        return True

    try:
        first_network = parse_network(first)
        second_network = parse_network(second)
    except ValueError:
        return False

    return (
        first_network.version == second_network.version
        and first_network.overlaps(second_network)
    )


def port_contains(container, contained):
    """Return whether one validated port scope contains another."""
    if is_any(container):
        return True

    if is_any(contained):
        return False

    return int(container) == int(contained)


def ports_overlap(first, second):
    """Return whether two validated port scopes overlap."""
    return is_any(first) or is_any(second) or int(first) == int(second)


def protocol_contains(container, contained):
    """Return whether one validated protocol scope contains another."""
    if normalize(container) == "any":
        return True

    if normalize(contained) == "any":
        return False

    return normalize(container) == normalize(contained)


def protocols_overlap(first, second):
    """Return whether two validated protocol scopes overlap."""
    return (
        normalize(first) == "any"
        or normalize(second) == "any"
        or normalize(first) == normalize(second)
    )


def rule_covers(earlier_rule, later_rule):
    """Return whether an earlier rule matches all traffic in a later rule."""
    return (
        network_contains(earlier_rule["source"], later_rule["source"])
        and network_contains(
            earlier_rule["destination"], later_rule["destination"]
        )
        and port_contains(earlier_rule["port"], later_rule["port"])
        and protocol_contains(
            earlier_rule["protocol"], later_rule["protocol"]
        )
    )


def rules_overlap(first_rule, second_rule):
    """Return whether two rules share any matching traffic."""
    return (
        networks_overlap(first_rule["source"], second_rule["source"])
        and networks_overlap(
            first_rule["destination"], second_rule["destination"]
        )
        and ports_overlap(first_rule["port"], second_rule["port"])
        and protocols_overlap(
            first_rule["protocol"], second_rule["protocol"]
        )
    )


def validate_rule(rule):
    """Return validation errors for a firewall rule."""
    errors = []

    for field in ["source", "destination"]:
        value = str(rule[field]).strip()

        if not is_any(value):
            try:
                if "/" in value:
                    ipaddress.ip_network(value, strict=False)
                else:
                    ipaddress.ip_address(value)
            except ValueError:
                errors.append(f"Invalid {field} address: {value}")

    port = str(rule["port"]).strip()

    if not is_any(port):
        try:
            port_number = int(port)
            if not 1 <= port_number <= 65535:
                errors.append(f"Port out of range: {port}")
        except ValueError:
            errors.append(f"Invalid port: {port}")

    protocol = normalize(rule["protocol"]).upper()

    if protocol not in {"TCP", "UDP", "ICMP", "ANY"}:
        errors.append(f"Unsupported protocol: {protocol}")

    action = normalize(rule["action"]).upper()

    if action not in {"ALLOW", "DENY"}:
        errors.append(f"Unsupported action: {action}")

    return errors


def validate_traffic(source, destination, port, protocol):
    """Validate one read-only traffic simulation request."""
    errors = []

    for field, value in [("source", source), ("destination", destination)]:
        try:
            ipaddress.ip_address(str(value).strip())
        except ValueError:
            errors.append(f"Invalid {field} IP address: {value}")

    try:
        port_number = int(port)
        if not 1 <= port_number <= 65535:
            errors.append(f"Port out of range: {port}")
    except (TypeError, ValueError):
        port_number = None
        errors.append(f"Invalid port: {port}")

    normalized_protocol = normalize(protocol).upper()
    if normalized_protocol not in SIMULATOR_PROTOCOLS:
        errors.append(f"Unsupported protocol: {protocol}")

    return errors, port_number, normalized_protocol


def evidence_for_rule(rule_id, source, destination, port, protocol, action):
    """Describe the policy fields that produced a finding."""
    def value_or_blank(value):
        value = str(value).strip()
        return value or "(blank)"

    return (
        f"Affected rule {rule_id}: Source={value_or_blank(source)}; "
        f"Destination={value_or_blank(destination)}; "
        f"Port={value_or_blank(port)}; "
        f"Protocol={value_or_blank(protocol)}; "
        f"Action={value_or_blank(action)}."
    )


def potential_impact_for_issue(issue):
    """Return a cautious, configuration-based impact explanation."""
    if issue == "Invalid Rule Configuration":
        return (
            "The firewall platform may reject the rule or interpret it "
            "differently than intended, leaving the policy unclear."
        )
    if issue == "Unrestricted Allow Rule":
        return (
            "Broadly permitted traffic may bypass least-privilege controls "
            "and expand the attack surface."
        )
    if issue.startswith("Unrestricted-Source "):
        return (
            "If the policy is active and the service is reachable, "
            "unapproved sources may be able to attempt access."
        )
    if issue == "Shadowed Allow/Deny Rule":
        return (
            "The intended later policy may never take effect, causing "
            "unexpected allowed or denied traffic."
        )
    if issue == "Potential Allow/Deny Conflict":
        return (
            "Overlapping rules can lead to unexpected traffic decisions "
            "when their order or policy intent is misunderstood."
        )
    if issue == "Duplicate Rule":
        return (
            "Duplicate entries can make policy reviews harder and obscure "
            "later configuration mistakes."
        )
    return "Review the rule's policy effect before making a change."


def investigation_priority_for_severity(severity):
    """Map the existing severity levels to a plain-language review order."""
    return {
        "Critical": "Immediate review",
        "High": "High-priority review",
        "Medium": "Review soon",
        "Low": "Routine review",
    }.get(severity, "Review")


def create_finding(
    rule_id,
    issue,
    severity,
    reason,
    recommendation,
    source,
    destination,
    port,
    protocol,
    action,
):
    """Build one compatible, explainable finding from an existing check."""
    return {
        "Rule ID": rule_id,
        "Issue": issue,
        "Severity": severity,
        "Reason": reason,
        "Recommendation": recommendation,
        "Evidence": evidence_for_rule(
            rule_id, source, destination, port, protocol, action
        ),
        "Potential Impact": potential_impact_for_issue(issue),
        "Investigation Priority": investigation_priority_for_severity(severity),
        "Assessment Scope": CONFIGURATION_FINDING_SCOPE,
    }


def rule_matches_traffic(rule, source, destination, port, protocol):
    """Return whether a validated rule matches one traffic request."""
    try:
        return (
            network_contains(rule["source"], source)
            and network_contains(rule["destination"], destination)
            and port_contains(rule["port"], port)
            and protocol_contains(rule["protocol"], protocol)
        )
    except (KeyError, TypeError, ValueError):
        return False


def simulation_result(
    decision,
    matched_rule_id,
    reason,
    earlier_rules_checked,
    later_shadowed_rule_ids=None,
    invalid_rule_ids=None,
    errors=None,
):
    """Build a consistent result for the read-only traffic simulator."""
    return {
        "decision": decision,
        "matched_rule_id": matched_rule_id,
        "reason": reason,
        "earlier_rules_checked": earlier_rules_checked,
        "later_shadowed_rule_ids": later_shadowed_rule_ids or [],
        "invalid_rule_ids": invalid_rule_ids or [],
        "errors": errors or [],
    }


def simulate_traffic(data, source, destination, port, protocol):
    """
    Simulate a single packet against rules in CSV row order.

    This is a read-only, simplified first-match model. If no valid rule
    matches, the simulator returns DENY using an implicit-deny assumption.
    """
    errors, port_number, normalized_protocol = validate_traffic(
        source, destination, port, protocol
    )

    if errors:
        return simulation_result(
            "INVALID",
            None,
            "Traffic input must be corrected before simulation.",
            0,
            errors=errors,
        )

    if not isinstance(data, pd.DataFrame):
        return simulation_result(
            "INVALID",
            None,
            "Loaded firewall rules are not available in table form.",
            0,
            errors=["Firewall rules must be a pandas DataFrame."],
        )

    missing = REQUIRED_RULE_COLUMNS - set(data.columns)
    if missing:
        return simulation_result(
            "INVALID",
            None,
            "Loaded firewall rules are missing required columns.",
            0,
            errors=["Missing required columns: " + ", ".join(sorted(missing))],
        )

    valid_rules = []
    invalid_rule_ids = []
    rules = data.copy().fillna("")

    for priority, (_, rule) in enumerate(rules.iterrows(), start=1):
        rule_id = str(rule["rule_id"]).strip() or f"ROW-{priority}"
        rule_errors = validate_rule(rule)

        if rule_errors:
            invalid_rule_ids.append(rule_id)
            continue

        valid_rules.append({
            "Rule ID": rule_id,
            "source": str(rule["source"]).strip(),
            "destination": str(rule["destination"]).strip(),
            "port": str(rule["port"]).strip(),
            "protocol": str(rule["protocol"]).strip().upper(),
            "action": str(rule["action"]).strip().upper(),
            "priority": priority,
        })

    for position, rule in enumerate(valid_rules):
        if not rule_matches_traffic(
            rule, source, destination, port_number, normalized_protocol
        ):
            continue

        later_shadowed_rule_ids = [
            later_rule["Rule ID"]
            for later_rule in valid_rules[position + 1:]
            if (
                later_rule["action"] != rule["action"]
                and rule_matches_traffic(
                    later_rule,
                    source,
                    destination,
                    port_number,
                    normalized_protocol,
                )
            )
        ]

        return simulation_result(
            rule["action"],
            rule["Rule ID"],
            (
                "The traffic matches this rule's source, destination, "
                "port, and protocol scope."
            ),
            rule["priority"] - 1,
            later_shadowed_rule_ids=later_shadowed_rule_ids,
            invalid_rule_ids=invalid_rule_ids,
        )

    return simulation_result(
        "DENY",
        None,
        (
            "No valid firewall rule matched this traffic. Under the "
            "simplified first-match model, the simulator assumes an "
            "implicit deny."
        ),
        len(rules),
        invalid_rule_ids=invalid_rule_ids,
    )


def analyze_rules(data):
    """
    Analyze firewall rules and return:
    1. A DataFrame of findings
    2. A heuristic security score
    3. Validation messages

    Conflict analysis assumes a first-match firewall model, where CSV
    row order determines rule priority.
    """

    missing = REQUIRED_RULE_COLUMNS - set(data.columns)

    if missing:
        raise ValueError(
            "Missing required columns: " + ", ".join(sorted(missing))
        )

    findings = []
    validation_messages = []

    rules = data.copy().fillna("")

    # Normalize common fields.
    for column in [
        "source", "destination", "port", "protocol", "action"
    ]:
        rules[column] = rules[column].astype(str).str.strip()

    # Keep track of duplicate rules.
    seen_rules = {}
    valid_rules = []

    for priority, (index, rule) in enumerate(rules.iterrows(), start=1):
        rule_id = str(rule["rule_id"]).strip() or f"ROW-{index + 1}"

        source = rule["source"]
        destination = rule["destination"]
        port = rule["port"]
        protocol = rule["protocol"].upper()
        action = rule["action"].upper()

        errors = validate_rule(rule)

        if errors:
            for error in errors:
                validation_messages.append({
                    "Rule ID": rule_id,
                    "Issue": error,
                })

            findings.append(create_finding(
                rule_id=rule_id,
                issue="Invalid Rule Configuration",
                severity="Medium",
                reason="; ".join(errors),
                recommendation=(
                    "Correct the invalid fields and validate the rule "
                    "against the intended firewall platform."
                ),
                source=source,
                destination=destination,
                port=port,
                protocol=protocol,
                action=action,
            ))

            # Do not run security checks on malformed rules.
            continue

        current_rule = {
            "Rule ID": rule_id,
            "source": source,
            "destination": destination,
            "port": port,
            "protocol": protocol,
            "action": action,
            "priority": priority,
        }

        # Compare valid rules in CSV row order. This follows a first-match
        # model; invalid rules are deliberately excluded from comparisons.
        fully_shadowed = False
        for earlier_rule in valid_rules:
            if action == earlier_rule["action"]:
                continue

            if rule_covers(earlier_rule, current_rule):
                findings.append(create_finding(
                    rule_id=rule_id,
                    issue="Shadowed Allow/Deny Rule",
                    severity="High",
                    reason=(
                        f"Earlier rule {earlier_rule['Rule ID']} "
                        f"(input row {earlier_rule['priority']}) matches "
                        "all traffic in this rule but has the opposite "
                        f"action. {FIRST_MATCH_ASSUMPTION} This "
                        "later rule is never evaluated."
                    ),
                    recommendation=(
                        f"Review the order of this rule and earlier rule "
                        f"{earlier_rule['Rule ID']}. Confirm the intended "
                        "policy, then narrow or reorder one of the rules."
                    ),
                    source=source,
                    destination=destination,
                    port=port,
                    protocol=protocol,
                    action=action,
                ))
                fully_shadowed = True
                break

            if rules_overlap(earlier_rule, current_rule):
                findings.append(create_finding(
                    rule_id=rule_id,
                    issue="Potential Allow/Deny Conflict",
                    severity="Medium",
                    reason=(
                        f"This rule overlaps earlier rule "
                        f"{earlier_rule['Rule ID']} (input row "
                        f"{earlier_rule['priority']}) but has the opposite "
                        f"action. {FIRST_MATCH_ASSUMPTION} Rule "
                        "order can change the decision for overlapping "
                        "traffic."
                    ),
                    recommendation=(
                        f"Review this rule with earlier rule "
                        f"{earlier_rule['Rule ID']}. Narrow the overlapping "
                        "traffic or reorder the rules after confirming the "
                        "intended policy."
                    ),
                    source=source,
                    destination=destination,
                    port=port,
                    protocol=protocol,
                    action=action,
                ))

        # A fully shadowed rule is never evaluated, so it cannot affect a
        # later rule under the same first-match assumption.
        if not fully_shadowed:
            valid_rules.append(current_rule)

        # Exact duplicate detection.
        signature = tuple(
            normalize(rule[column])
            for column in [
                "source", "destination", "port", "protocol", "action"
            ]
        )

        if signature in seen_rules:
            findings.append(create_finding(
                rule_id=rule_id,
                issue="Duplicate Rule",
                severity="Medium",
                reason=(
                    f"This rule duplicates {seen_rules[signature]} "
                    "under normalized field comparison."
                ),
                recommendation=(
                    "Review whether both rules are required before "
                    "considering any change."
                ),
                source=source,
                destination=destination,
                port=port,
                protocol=protocol,
                action=action,
            ))
        else:
            seen_rules[signature] = rule_id

        # Analyze only rules that permit traffic.
        if action != "ALLOW":
            continue

        # Broad access detection.
        if (
            is_any(source)
            and is_any(destination)
            and is_any(port)
            and protocol in {"ANY", "*", "ALL"}
        ):
            findings.append(create_finding(
                rule_id=rule_id,
                issue="Unrestricted Allow Rule",
                severity="Critical",
                reason=(
                    "The rule allows traffic across unrestricted "
                    "sources, destinations, ports, and protocols."
                ),
                recommendation=(
                    "Restrict the source, destination, port, and "
                    "protocol to the minimum required for the service."
                ),
                source=source,
                destination=destination,
                port=port,
                protocol=protocol,
                action=action,
            ))

        # Administrative service exposure.
        if is_any(source) and not is_any(port):
            try:
                port_number = int(port)
            except ValueError:
                port_number = None

            if port_number in ADMIN_PORTS and protocol in {"TCP", "ANY", "*", "ALL"}:
                service = ADMIN_PORTS[port_number]

                findings.append(create_finding(
                    rule_id=rule_id,
                    issue=f"Unrestricted-Source {service} Access",
                    severity="High",
                    reason=(
                        f"The rule allows {service} on port "
                        f"{port_number} from any source. This unrestricted "
                        "exposure may increase security risk."
                    ),
                    recommendation=(
                        "Restrict access to approved administration "
                        "hosts or trusted management networks."
                    ),
                    source=source,
                    destination=destination,
                    port=port,
                    protocol=protocol,
                    action=action,
                ))

    findings_df = pd.DataFrame(
        findings,
        columns=[
            "Rule ID",
            "Issue",
            "Severity",
            "Reason",
            "Recommendation",
            "Evidence",
            "Potential Impact",
            "Investigation Priority",
            "Assessment Scope",
        ],
    )

    # Simple heuristic score. Each finding has a penalty.
    penalties = {
        "Critical": 25,
        "High": 15,
        "Medium": 7,
        "Low": 2,
    }

    total_penalty = sum(
        penalties.get(severity, 0)
        for severity in findings_df.get(
            "Severity", pd.Series(dtype=str)
        )
    )

    security_score = max(0, 100 - total_penalty)

    return findings_df, security_score, validation_messages
