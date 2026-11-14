from sentinel.models.base import stable_id
from sentinel.models.report import ScenarioReport
from sentinel.reasoning.backward import knowledge


def scenario_reports(context, shared, verification):
    attack = context.attack
    if not attack.applicable:
        return []
    conditions = {c.id: c for c in attack.conditions}
    impact = next(o["impact"] for o in knowledge("outcomes.yaml")["outcomes"] if o["id"] == attack.outcome_id)
    reports = []
    for index, path in enumerate(attack.paths):
        required, facts, assumptions, unknowns, evidence = [], [], [], [], set()
        blocked = False
        for literal in path:
            condition = conditions[literal.lstrip("!")]
            negated = literal.startswith("!")
            needed = "false" if negated else "true"
            blocked |= condition.truth not in {needed, "unknown"}
            required.append({**condition.model_dump(), "required_truth": needed, "negated": negated})
            evidence.update(condition.evidence_ids)
            assumptions.extend(condition.assumptions)
            if condition.truth == "unknown":
                unknowns.append(condition.description)
            elif condition.truth == needed and condition.status in {"observed", "verified"}:
                facts.append(condition.description)
        reports.append(
            ScenarioReport(
                scenario_id=stable_id(
                    "scenario", context.snapshot.repository_id, attack.outcome_id, str(index)
                ),
                title=f"Potential {attack.outcome_id.replace('_', ' ')} via "
                + ("agent tool" if any("agent_compromised" in x for x in path) else "service identity"),
                status="refuted_within_model" if blocked else "hypothetical",
                dangerous_outcome=attack.outcome_id,
                required_conditions=required,
                possible_impact=impact,
                critical_dependencies=sorted(
                    {a for item in shared for a in conditions[item["condition_id"]].asset_ids}
                ),
                alternate_routes=[" + ".join(other) for other in attack.paths if other != path],
                interruption_points=shared,
                verified_facts=facts,
                assumptions=sorted(set(assumptions)),
                unknowns=unknowns,
                evidence_ids=sorted(evidence),
                verification=verification,
                confidence_evidence={
                    "level": "static_supported" if facts else "inconclusive",
                    "numeric_probability": None,
                    "bounds": attack.bounds,
                    "limitations": attack.limitations,
                    "fact_label": "verified_facts includes source-observed facts, not verified exploits",
                    "mock_scope": "Fixture results never establish repository or production exploitability",
                },
            )
        )
    return reports


def markdown_report(reports):
    lines = [
        "# SENTINEL scenario report",
        "",
        "Source analysis and synthetic fixture results are scoped separately.",
        "",
    ]
    for report in reports:
        lines += [
            f"## {report.title}",
            "",
            f"Status: **{report.status}**",
            "",
            f"Impact: {report.possible_impact}",
            "",
            "Required conditions:",
        ]
        lines += [
            f"- {c['description']} (requires {c['required_truth']}; observed truth: {c['truth']}; {c['status']})"
            for c in report.required_conditions
        ]
        lines += [
            "",
            "Critical dependencies: " + ", ".join(report.critical_dependencies),
            "",
            "Alternate routes: " + "; ".join(report.alternate_routes),
            "",
            "Interruption candidates:",
        ]
        lines += ["- " + p["action"] + ". " + p["qualification"] for p in report.interruption_points]
        lines += [
            "",
            "Unknowns: " + "; ".join(report.unknowns),
            "",
            "Evidence: " + ", ".join(report.evidence_ids),
            "",
        ]
    return "\n".join(lines)
