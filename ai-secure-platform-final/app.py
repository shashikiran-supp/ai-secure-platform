from flask import Flask, request, jsonify, render_template
import re

app = Flask(__name__)

def detect_sensitive_data(line, line_no):
    findings = []
    risk_score = 0

    if re.search(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+', line):
        findings.append({"type": "email", "risk": "low", "line": line_no})
        risk_score += 1

    if "password=" in line:
        findings.append({"type": "password", "risk": "critical", "line": line_no})
        risk_score += 7

    if "api_key=" in line:
        findings.append({"type": "api_key", "risk": "high", "line": line_no})
        risk_score += 5

    if "token=" in line:
        findings.append({"type": "token", "risk": "high", "line": line_no})
        risk_score += 5

    if "exception" in line.lower():
        findings.append({"type": "stack_trace", "risk": "medium", "line": line_no})
        risk_score += 3

    return findings, risk_score


def mask_data(line):
    line = re.sub(r'(password=)\w+', r'\1****', line)
    line = re.sub(r'(api_key=)\w+', r'\1****', line)
    line = re.sub(r'(token=)\w+', r'\1****', line)
    return line


def generate_ai_insights(findings):
    insights = []
    types = [f["type"] for f in findings]

    if "password" in types:
        insights.append("Sensitive credentials exposed in logs")
    if "api_key" in types:
        insights.append("API key exposed - security risk")
    if "stack_trace" in types:
        insights.append("Stack trace reveals internal system details")
    if len(findings) > 5:
        insights.append("Multiple anomalies detected in logs")

    return insights


def analyze_content(content, options):
    lines = content.split("\n")

    all_findings = []
    logs = []
    total_score = 0

    for i, line in enumerate(lines):
        findings, score = detect_sensitive_data(line, i + 1)
        masked_line = mask_data(line) if options.get("mask", True) else line

        logs.append({
            "line": i + 1,
            "content": masked_line,
            "risky": len(findings) > 0
        })

        all_findings.extend(findings)
        total_score += score

    if total_score > 10:
        risk_level = "high"
    elif total_score > 5:
        risk_level = "medium"
    else:
        risk_level = "low"

    insights = generate_ai_insights(all_findings)

    return {
        "summary": "Log contains sensitive credentials and errors",
        "content_type": "logs",
        "findings": all_findings,
        "risk_score": total_score,
        "risk_level": risk_level,
        "action": "masked" if options.get("mask", True) else "none",
        "logs": logs,
        "insights": insights
    }


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    options = {"mask": True}

    file = request.files.get("file")
    content = ""

    if file:
        content = file.read().decode("utf-8")
    else:
        content = request.form.get("content", "")

    result = analyze_content(content, options)
    return jsonify(result)


if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
