from datetime import datetime

def generate_html_report(results):
    """
    Generates a professional HTML security audit report
    Args:
        results: List of check results (dicts)
    Returns:
        HTML string with styled report
    """
    timestamp = results[0]["timestamp"] if results else datetime.now().isoformat()
    
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
        .severity-CRITICAL {{
            background-color: #ffdddd;
        }}
        .severity-HIGH {{
            background-color: #ffeedd;
        }}
        .timestamp {{
            font-style: italic;
            color: #7f8c8d;
            text-align: right;
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

    for result in results:
        html += f"""
            <tr class="severity-{result.get('severity', 'MEDIUM')}">
                <td>{result['check']}</td>
                <td class="{result['status']}">{result['status']}</td>
                <td>{result.get('severity', 'medium')}</td>
                <td>{result.get('value', 'N/A')}</td>
                <td>{result.get('expected', 'N/A')}</td>
                <td>{result.get('remediation', 'None provided')}</td>
            </tr>"""

    html += """
        </tbody>
    </table>
</body>
</html>"""
    return html
