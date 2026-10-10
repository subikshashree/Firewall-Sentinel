import unittest

import pandas as pd

from analyzer import analyze_rules, simulate_traffic


RULE_COLUMNS = [
    "rule_id",
    "source",
    "destination",
    "port",
    "protocol",
    "action",
]


def make_rules(rows):
    """Create a rule DataFrame with the app's required column order."""
    return pd.DataFrame(rows, columns=RULE_COLUMNS)


class OrderedConflictTests(unittest.TestCase):
    def assert_issue_for_rule(self, findings, rule_id, issue):
        matching = findings[
            (findings["Rule ID"] == rule_id)
            & (findings["Issue"] == issue)
        ]
        self.assertEqual(len(matching), 1)
        return matching.iloc[0]

    def test_later_deny_is_shadowed_by_earlier_allow(self):
        findings, score, validation = analyze_rules(make_rules([
            ["R001", "Any", "10.0.0.5", "443", "TCP", "Allow"],
            ["R002", "192.168.1.0/24", "10.0.0.5", "443", "TCP", "Deny"],
        ]))

        finding = self.assert_issue_for_rule(
            findings, "R002", "Shadowed Allow/Deny Rule"
        )
        self.assertEqual(finding["Severity"], "High")
        self.assertIn("R001", finding["Recommendation"])
        self.assertEqual(score, 85)
        self.assertEqual(validation, [])

    def test_later_allow_is_shadowed_by_earlier_deny(self):
        findings, score, validation = analyze_rules(make_rules([
            ["R001", "Any", "10.0.0.5", "22", "TCP", "Deny"],
            ["R002", "192.168.1.0/24", "10.0.0.5", "22", "TCP", "Allow"],
        ]))

        finding = self.assert_issue_for_rule(
            findings, "R002", "Shadowed Allow/Deny Rule"
        )
        self.assertIn("R001", finding["Reason"])
        self.assertEqual(score, 85)
        self.assertEqual(validation, [])

    def test_partially_overlapping_rules_with_different_actions(self):
        findings, score, validation = analyze_rules(make_rules([
            ["R001", "10.0.0.0/24", "10.1.0.0/24", "443", "TCP", "Allow"],
            ["R002", "10.0.0.128/25", "10.1.0.128/25", "Any", "TCP", "Deny"],
        ]))

        finding = self.assert_issue_for_rule(
            findings, "R002", "Potential Allow/Deny Conflict"
        )
        self.assertEqual(finding["Severity"], "Medium")
        self.assertIn("R001", finding["Recommendation"])
        self.assertEqual(score, 93)
        self.assertEqual(validation, [])

    def test_shadowed_rule_does_not_create_later_false_conflicts(self):
        findings, score, validation = analyze_rules(make_rules([
            ["R001", "Any", "10.0.0.5", "443", "TCP", "Allow"],
            ["R002", "Any", "10.0.0.5", "443", "TCP", "Deny"],
            ["R003", "192.168.1.0/24", "10.0.0.5", "443", "TCP", "Allow"],
        ]))

        self.assert_issue_for_rule(
            findings, "R002", "Shadowed Allow/Deny Rule"
        )
        self.assertFalse((findings["Rule ID"] == "R003").any())
        self.assertEqual(score, 85)
        self.assertEqual(validation, [])

    def test_rules_that_do_not_overlap_do_not_create_conflicts(self):
        findings, score, validation = analyze_rules(make_rules([
            ["R001", "10.0.0.0/24", "10.1.0.5", "443", "TCP", "Allow"],
            ["R002", "10.0.1.0/24", "10.1.0.5", "443", "TCP", "Deny"],
        ]))

        self.assertTrue(findings.empty)
        self.assertEqual(score, 100)
        self.assertEqual(validation, [])

    def test_identical_same_action_rules_are_not_allow_deny_conflicts(self):
        findings, score, validation = analyze_rules(make_rules([
            ["R001", "10.0.0.0/24", "10.1.0.5", "443", "TCP", "Allow"],
            ["R002", "10.0.0.0/24", "10.1.0.5", "443", "TCP", "Allow"],
        ]))

        self.assert_issue_for_rule(findings, "R002", "Duplicate Rule")
        self.assertFalse(
            findings["Issue"].isin([
                "Shadowed Allow/Deny Rule",
                "Potential Allow/Deny Conflict",
            ]).any()
        )
        self.assertEqual(score, 93)
        self.assertEqual(validation, [])

    def test_invalid_network_is_not_used_for_conflict_detection(self):
        findings, score, validation = analyze_rules(make_rules([
            ["R001", "not-a-network", "10.0.0.5", "443", "TCP", "Allow"],
            ["R002", "Any", "10.0.0.5", "443", "TCP", "Deny"],
        ]))

        self.assert_issue_for_rule(
            findings, "R001", "Invalid Rule Configuration"
        )
        self.assertFalse(
            findings["Issue"].isin([
                "Shadowed Allow/Deny Rule",
                "Potential Allow/Deny Conflict",
            ]).any()
        )
        self.assertEqual(score, 93)
        self.assertEqual(len(validation), 1)


class SensitiveServiceExposureTests(unittest.TestCase):
    def test_any_source_tcp_smb_allow_is_reported(self):
        findings, score, validation = analyze_rules(make_rules([
            ["R001", "Any", "10.0.0.5", "445", "TCP", "Allow"],
        ]))

        finding = findings.iloc[0]
        self.assertEqual(finding["Issue"], "Unrestricted-Source SMB Access")
        self.assertEqual(finding["Severity"], "High")
        self.assertIn("may increase security risk", finding["Reason"])
        self.assertIn("approved administration hosts", finding["Recommendation"])
        self.assertEqual(score, 85)
        self.assertEqual(validation, [])

    def test_any_source_tcp_mysql_allow_is_reported(self):
        findings, score, validation = analyze_rules(make_rules([
            ["R001", "Any", "10.0.0.5", "3306", "TCP", "Allow"],
        ]))

        finding = findings.iloc[0]
        self.assertEqual(finding["Issue"], "Unrestricted-Source MySQL Access")
        self.assertEqual(finding["Severity"], "High")
        self.assertEqual(score, 85)
        self.assertEqual(validation, [])

    def test_trusted_source_smb_allow_is_not_reported(self):
        findings, score, validation = analyze_rules(make_rules([
            ["R001", "192.168.1.0/24", "10.0.0.5", "445", "TCP", "Allow"],
        ]))

        self.assertTrue(findings.empty)
        self.assertEqual(score, 100)
        self.assertEqual(validation, [])

    def test_any_source_smb_deny_is_not_reported(self):
        findings, score, validation = analyze_rules(make_rules([
            ["R001", "Any", "10.0.0.5", "445", "TCP", "Deny"],
        ]))

        self.assertTrue(findings.empty)
        self.assertEqual(score, 100)
        self.assertEqual(validation, [])

    def test_any_source_udp_smb_allow_is_not_reported(self):
        findings, score, validation = analyze_rules(make_rules([
            ["R001", "Any", "10.0.0.5", "445", "UDP", "Allow"],
        ]))

        self.assertTrue(findings.empty)
        self.assertEqual(score, 100)
        self.assertEqual(validation, [])


class ExplainableFindingTests(unittest.TestCase):
    def test_evidence_references_the_affected_rule_and_policy_fields(self):
        findings, score, validation = analyze_rules(make_rules([
            ["R-SMB", "Any", "10.0.0.10", "445", "TCP", "Allow"],
        ]))

        finding = findings.iloc[0]
        self.assertIn("Affected rule R-SMB", finding["Evidence"])
        self.assertIn("Source=Any", finding["Evidence"])
        self.assertIn("Destination=10.0.0.10", finding["Evidence"])
        self.assertIn("Port=445", finding["Evidence"])
        self.assertIn("Protocol=TCP", finding["Evidence"])
        self.assertIn("Action=ALLOW", finding["Evidence"])
        self.assertEqual(score, 85)
        self.assertEqual(validation, [])

    def test_explainable_finding_keeps_recommendation_and_scope(self):
        findings, score, validation = analyze_rules(make_rules([
            ["R001", "Any", "Any", "Any", "Any", "Allow"],
        ]))

        finding = findings.iloc[0]
        self.assertTrue(finding["Recommendation"])
        self.assertTrue(finding["Potential Impact"])
        self.assertEqual(finding["Investigation Priority"], "Immediate review")
        self.assertIn("does not prove", finding["Assessment Scope"])
        self.assertEqual(score, 75)
        self.assertEqual(validation, [])

    def test_invalid_rule_has_safe_explainable_evidence(self):
        findings, score, validation = analyze_rules(make_rules([
            ["R-BAD", "not-an-ip", "10.0.0.10", "445", "TCP", "Allow"],
        ]))

        finding = findings.iloc[0]
        self.assertEqual(finding["Issue"], "Invalid Rule Configuration")
        self.assertIn("Affected rule R-BAD", finding["Evidence"])
        self.assertIn("Source=not-an-ip", finding["Evidence"])
        self.assertTrue(finding["Recommendation"])
        self.assertEqual(score, 93)
        self.assertEqual(len(validation), 1)

    def test_original_finding_columns_and_score_remain_compatible(self):
        findings, score, validation = analyze_rules(make_rules([
            ["R001", "Any", "10.0.0.5", "22", "TCP", "Allow"],
        ]))

        self.assertEqual(
            list(findings.columns[:5]),
            ["Rule ID", "Issue", "Severity", "Reason", "Recommendation"],
        )
        self.assertEqual(findings.iloc[0]["Issue"], "Unrestricted-Source SSH Access")
        self.assertEqual(findings.iloc[0]["Severity"], "High")
        csv_header = findings.to_csv(index=False).splitlines()[0]
        self.assertIn("Evidence", csv_header)
        self.assertIn("Assessment Scope", csv_header)
        self.assertEqual(score, 85)
        self.assertEqual(validation, [])

    def test_traffic_simulator_behavior_remains_intact(self):
        result = simulate_traffic(
            make_rules([
                ["R001", "Any", "10.0.0.5", "443", "TCP", "Allow"],
                ["R002", "Any", "10.0.0.5", "443", "TCP", "Deny"],
            ]),
            "192.168.1.10",
            "10.0.0.5",
            443,
            "TCP",
        )

        self.assertEqual(result["decision"], "ALLOW")
        self.assertEqual(result["matched_rule_id"], "R001")
        self.assertEqual(result["later_shadowed_rule_ids"], ["R002"])


class TrafficSimulationTests(unittest.TestCase):
    def test_matching_allow_rule(self):
        result = simulate_traffic(
            make_rules([
                ["R001", "Any", "10.0.0.5", "443", "TCP", "Allow"],
            ]),
            "192.168.1.10",
            "10.0.0.5",
            443,
            "TCP",
        )

        self.assertEqual(result["decision"], "ALLOW")
        self.assertEqual(result["matched_rule_id"], "R001")
        self.assertEqual(result["earlier_rules_checked"], 0)
        self.assertEqual(result["later_shadowed_rule_ids"], [])
        self.assertEqual(result["errors"], [])

    def test_matching_deny_rule(self):
        result = simulate_traffic(
            make_rules([
                ["R001", "Any", "10.0.0.5", "22", "TCP", "Deny"],
            ]),
            "192.168.1.10",
            "10.0.0.5",
            22,
            "TCP",
        )

        self.assertEqual(result["decision"], "DENY")
        self.assertEqual(result["matched_rule_id"], "R001")
        self.assertEqual(result["errors"], [])

    def test_earlier_rule_takes_precedence_over_later_opposite_action(self):
        result = simulate_traffic(
            make_rules([
                ["R001", "Any", "10.0.0.5", "443", "TCP", "Allow"],
                ["R002", "Any", "10.0.0.5", "443", "TCP", "Deny"],
            ]),
            "192.168.1.10",
            "10.0.0.5",
            443,
            "TCP",
        )

        self.assertEqual(result["decision"], "ALLOW")
        self.assertEqual(result["matched_rule_id"], "R001")
        self.assertEqual(result["later_shadowed_rule_ids"], ["R002"])

    def test_no_match_uses_implicit_deny(self):
        result = simulate_traffic(
            make_rules([
                ["R001", "Any", "10.0.0.5", "443", "TCP", "Allow"],
            ]),
            "192.168.1.10",
            "10.0.0.5",
            80,
            "TCP",
        )

        self.assertEqual(result["decision"], "DENY")
        self.assertIsNone(result["matched_rule_id"])
        self.assertIn("implicit deny", result["reason"])
        self.assertEqual(result["earlier_rules_checked"], 1)

    def test_invalid_input_is_handled_safely(self):
        result = simulate_traffic(
            make_rules([
                ["R001", "Any", "10.0.0.5", "443", "TCP", "Allow"],
            ]),
            "not-an-ip",
            "10.0.0.5",
            443,
            "TCP",
        )

        self.assertEqual(result["decision"], "INVALID")
        self.assertTrue(result["errors"])
        self.assertEqual(result["earlier_rules_checked"], 0)

    def test_cidr_matching_works_for_source_and_destination(self):
        result = simulate_traffic(
            make_rules([
                [
                    "R001",
                    "192.168.1.0/24",
                    "10.0.0.0/24",
                    "443",
                    "TCP",
                    "Allow",
                ],
            ]),
            "192.168.1.25",
            "10.0.0.10",
            443,
            "TCP",
        )

        self.assertEqual(result["decision"], "ALLOW")
        self.assertEqual(result["matched_rule_id"], "R001")


if __name__ == "__main__":
    unittest.main()
