from datetime import datetime
from typing import List, Dict

def generate_html_report(results: List[Dict]) -> str:
    """
    Generates a professional HTML security audit report with fault tolerance
    Args:
        results: List of check results (dicts)
    Returns:
        HTML string with styled report
    """
    # Safe timestamp extraction
    timestamp = (
        results[0].get("timestamp", "") 
        if results and isinstance(results[0], dict) 
        else datetime.now().isoformat()
    )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Linux Security Audit Report</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }}
        h1 {{
            color: #2c3e50;
            border-bottom: 2px solid #3498db;
            padding-bottom: 10px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 25px 0;
            box-shadow: 0 0 20px rgba(0,0,0,0.15);
        }}
        th, td {{
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid #dddddd;
        }}
        th {{
            background-color: #3498db;
            color: white;
            text-transform: uppercase;
            font-size: 0.9em;
        }}
        tr:nth-child(even) {{
            background-color: #f3f3f3;
        }}
        tr:hover {{
            background-color: #f1f1f1;
        }}
        .PASS {{
            color: #27ae60;
            font-weight: bold;
        }}
        .FAIL {{
            color: #e74c3c;
            font-weight: bold;
        }}
        .ERROR {{
            color: #f39c12;
            font-weight: bold;
        }}
        .WARN {{
            color: #f1c40f;
            font-weight: bold;
        }}
        .severity-CRITICAL {{
            background-color: #ffdddd;
        }}
        .severity-HIGH {{
            background-color: #ffeedd;
        }}
        .severity-MEDIUM {{
            background-color: #ffffdd;
        }}
        .severity-LOW {{
            background-color: #eeffee;
        }}
        .timestamp {{
            font-style: italic;
            color: #7f8c8d;
            text-align: right;
        }}
        .missing-data {{
            color: #9b59b6;
            font-style: italic;
        }}
    </style>
</head>
<body>
    <h1>Linux Security Audit Report</h1>
    <div class="timestamp">Generated on: {timestamp}</div>
    <table>
        <thead>
            <tr>
                <th>Check ID</th>
                <th>Status</th>
                <th>Severity</th>
                <th>Current Value</th>
                <th>Expected Value</th>
                <th>Remediation</th>
            </tr>
        </thead>
        <tbody>"""

    # Safe results processing
    for result in results if isinstance(results, list) else []:
        if not isinstance(result, dict):
            continue
            
        html += f"""
            <tr class="severity-{result.get('severity', 'MEDIUM').upper()}">
                <td>{result.get('check', '<span class="missing-data">missing-check-id</span>')}</td>
                <td class="{result.get('status', 'ERROR')}">
                    {result.get('status', '<span class="missing-data">ERROR</span>')}
                </td>
                <td>{result.get('severity', '<span class="missing-data">medium</span>')}</td>
                <td>{result.get('value', '<span class="missing-data">N/A</span>')}</td>
                <td>{result.get('expected', '<span class="missing-data">N/A</span>')}</td>
                <td>{result.get('remediation', '<span class="missing-data">None provided</span>')}</td>
            </tr>"""

    html += """
        </tbody>
    </table>
</body>
</html>"""
    return html
