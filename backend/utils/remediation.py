def get_remediation(finding_category: str) -> dict[str, str]:
    remediation_map = {
        "sqli": {
            "owasp_category": "A03:2021-Injection",
            "fix": "Use parameterized queries or prepared statements. Do not concatenate user input directly into SQL queries.",
            "code_snippet": "cursor.execute('SELECT * FROM users WHERE username = %s', (username,))"
        },
        "xss": {
            "owasp_category": "A03:2021-Injection",
            "fix": "Context-aware output encoding. Sanitize all user input before rendering it in HTML, JavaScript, or attributes.",
            "code_snippet": "import html\nsafe_output = html.escape(user_input)"
        },
        "api": {
            "owasp_category": "API1:2023-Broken Object Level Authorization",
            "fix": "Ensure all API endpoints validate authorization before granting access to specific objects.",
            "code_snippet": "if user.id != requested_resource.owner_id: raise Forbidden()"
        }
    }
    
    # Generic fallback based on detector name or category prefix
    if "sqli" in finding_category.lower():
        return remediation_map["sqli"]
    elif "xss" in finding_category.lower():
        return remediation_map["xss"]
    elif "api" in finding_category.lower():
        return remediation_map["api"]
        
    return {
        "owasp_category": "Unknown",
        "fix": "Review the vulnerability details and apply appropriate security controls.",
        "code_snippet": ""
    }
