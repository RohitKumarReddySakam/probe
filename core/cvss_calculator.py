"""CVSS v3.1 base score calculator and severity mapper."""

SEVERITY_THRESHOLDS = [
    (9.0, "CRITICAL"),
    (7.0, "HIGH"),
    (4.0, "MEDIUM"),
    (0.1, "LOW"),
    (0.0, "INFO"),
]


def severity_from_cvss(score: float) -> str:
    for threshold, label in SEVERITY_THRESHOLDS:
        if score >= threshold:
            return label
    return "INFO"


def overall_score(findings: list[dict]) -> float:
    """Compute overall risk score (0-10) from a list of findings."""
    if not findings:
        return 0.0
    scores = [f.get("cvss", 0.0) for f in findings]
    # Highest score drives the result, with a boost from finding count
    max_score = max(scores)
    count_factor = min(len(findings) * 0.05, 1.0)
    composite = min(max_score + count_factor, 10.0)
    return round(composite, 1)


def risk_grade(score: float) -> str:
    if score == 0:
        return "A+"
    if score < 2:
        return "A"
    if score < 4:
        return "B"
    if score < 6:
        return "C"
    if score < 7.5:
        return "D"
    return "F"


def cvss_summary(findings: list[dict]) -> dict:
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev = f.get("severity", "INFO").upper()
        counts[sev] = counts.get(sev, 0) + 1
    score = overall_score(findings)
    return {
        "score": score,
        "grade": risk_grade(score),
        "severity": severity_from_cvss(score),
        "counts": counts,
        "total": len(findings),
    }
