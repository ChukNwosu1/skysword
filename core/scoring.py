def calculate_score(findings):
    score = 100

    for finding in findings:
        severity = finding["severity"]

        if severity == "Critical":
            score -= 30
        elif severity == "High":
            score -= 20
        elif severity == "Medium":
            score -= 10

    return max(score, 0)