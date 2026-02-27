"""
AI Analysis Module — Google Gemini API
Sends suspicious log lines and gets SOC-analyst-style explanations
with MITRE ATT&CK mappings.
"""

import os
import json
import time
import urllib.request
import urllib.error


GEMINI_API_URL = (
    "https://generativelanguage.googleapis.com/v1beta/models/"
    "gemini-1.5-flash:generateContent"
)

SOC_SYSTEM_PROMPT = """You are an expert SOC (Security Operations Center) analyst with 
deep knowledge of MITRE ATT&CK, threat hunting, and incident response.
When given a suspicious log line, you must:
1. Explain what is happening in plain English (2-3 sentences)
2. Assess the severity (CRITICAL/HIGH/MEDIUM/LOW) and justify why
3. Map to MITRE ATT&CK: provide Tactic ID + name, Technique ID + name
4. Give 3 concrete recommended actions for the SOC team
5. Mention any false-positive considerations

Always respond in valid JSON with this exact structure:
{
  "explanation": "...",
  "severity": "HIGH",
  "severity_reason": "...",
  "mitre_tactic": "TA0006 - Credential Access",
  "mitre_technique": "T1110.001 - Password Guessing",
  "recommended_actions": ["action1", "action2", "action3"],
  "false_positive_notes": "..."
}"""


def analyze_with_gemini(log_line: str, context: str = "") -> dict:
    """
    Send a log line to Gemini for SOC analysis.
    Returns a dict with analysis fields, or an error dict.
    """
    api_key = os.environ.get("GEMINI_API_KEY", "")
    if not api_key:
        return {
            "explanation": "⚠️  GEMINI_API_KEY not set. Set it via: export GEMINI_API_KEY=your_key",
            "severity": "N/A",
            "severity_reason": "AI analysis unavailable",
            "mitre_tactic": "N/A",
            "mitre_technique": "N/A",
            "recommended_actions": ["Set GEMINI_API_KEY environment variable to enable AI analysis"],
            "false_positive_notes": "N/A"
        }

    prompt = f"""Analyze this log line as a SOC analyst and map it to MITRE ATT&CK if possible.

LOG LINE:
{log_line}

{f'CONTEXT: {context}' if context else ''}

Respond ONLY with the JSON structure specified. No markdown, no extra text."""

    payload = json.dumps({
        "system_instruction": {
            "parts": [{"text": SOC_SYSTEM_PROMPT}]
        },
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {
            "temperature": 0.2,
            "maxOutputTokens": 1024,
        }
    }).encode('utf-8')

    req = urllib.request.Request(
        f"{GEMINI_API_URL}?key={api_key}",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST"
    )

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            text = data['candidates'][0]['content']['parts'][0]['text']
            # Strip possible markdown fences
            text = text.strip().lstrip('```json').lstrip('```').rstrip('```').strip()
            return json.loads(text)
    except urllib.error.HTTPError as e:
        body = e.read().decode('utf-8')
        return {"explanation": f"Gemini API error {e.code}: {body[:300]}", "severity": "N/A",
                "mitre_tactic": "N/A", "mitre_technique": "N/A",
                "recommended_actions": [], "false_positive_notes": "N/A", "severity_reason": ""}
    except json.JSONDecodeError as e:
        return {"explanation": f"Failed to parse Gemini response as JSON: {e}",
                "severity": "N/A", "mitre_tactic": "N/A", "mitre_technique": "N/A",
                "recommended_actions": [], "false_positive_notes": "N/A", "severity_reason": ""}
    except Exception as e:
        return {"explanation": f"Error calling Gemini: {e}", "severity": "N/A",
                "mitre_tactic": "N/A", "mitre_technique": "N/A",
                "recommended_actions": [], "false_positive_notes": "N/A", "severity_reason": ""}


def analyze_critical_alerts(alerts, max_alerts: int = 5) -> dict:
    """
    Run AI analysis on the top N CRITICAL/HIGH alerts.
    Returns dict of alert_id -> analysis result.
    """
    results = {}
    priority = [a for a in alerts if a.severity in ("CRITICAL", "HIGH")][:max_alerts]

    for alert in priority:
        print(f"  🤖 Asking Gemini about {alert.alert_id} ({alert.rule_name})...")
        analysis = analyze_with_gemini(
            log_line=alert.raw_log,
            context=f"Rule triggered: {alert.rule_name}. Initial severity: {alert.severity}"
        )
        results[alert.alert_id] = analysis
        # Store the full analysis as a formatted string on the alert object
        alert.ai_analysis = json.dumps(analysis, indent=2)
        time.sleep(0.5)  # Be polite to the API

    return results
