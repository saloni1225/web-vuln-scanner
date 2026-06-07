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
        },
        "idor": {
            "owasp_category": "API1:2023-Broken Object Level Authorization",
            "fix": "Enforce server-side authorization checks on every object access. Map user sessions to owned resources via indirect references.",
            "code_snippet": "resource = db.query(Resource).filter_by(id=resource_id, owner_id=current_user.id).first()\nif not resource: raise HTTPException(403)"
        },
        "ssrf": {
            "owasp_category": "A10:2021-Server-Side Request Forgery",
            "fix": "Implement URL allowlists for outbound requests. Block private IP ranges (127.0.0.0/8, 169.254.0.0/16, 10.0.0.0/8). Disable file:// protocol.",
            "code_snippet": "from urllib.parse import urlparse\nimport ipaddress\ndef is_safe_url(url):\n    host = urlparse(url).hostname\n    ip = ipaddress.ip_address(host)\n    return ip.is_global"
        },
        "api_authz": {
            "owasp_category": "API5:2023-Broken Function Level Authorization",
            "fix": "Enforce role-based access control on all API endpoints. Use middleware to validate permissions before handler execution.",
            "code_snippet": "@require_role('admin')\nasync def delete_user(user_id): ..."
        },
        "graphql_authz": {
            "owasp_category": "API1:2023-Broken Object Level Authorization",
            "fix": "Disable introspection in production. Implement field-level authorization, query depth limiting, and complexity analysis.",
            "code_snippet": "schema = graphene.Schema(query=Query, auto_camelcase=False)\n# Disable introspection:\nschema.introspection = False"
        },
        "nosql": {
            "owasp_category": "A03:2021-Injection",
            "fix": "Use parameterized queries. Sanitize user input by rejecting $ prefixed keys. Use MongoDB's strict query mode.",
            "code_snippet": "# Reject operator injection:\nif any(k.startswith('$') for k in user_input.keys()): raise ValueError\ndb.users.find({'username': sanitized_input})"
        },
        "ssti": {
            "owasp_category": "A03:2021-Injection",
            "fix": "Never pass user input directly to template engines. Use sandboxed environments and strict variable allowlists.",
            "code_snippet": "from jinja2.sandbox import SandboxedEnvironment\nenv = SandboxedEnvironment()\ntemplate = env.from_string(safe_template)\nresult = template.render(data=user_data)"
        },
        "xxe": {
            "owasp_category": "A05:2021-Security Misconfiguration",
            "fix": "Disable external entity processing in XML parsers. Use defusedxml (Python), FEATURE_SECURE_PROCESSING (Java).",
            "code_snippet": "import defusedxml.ElementTree as ET\ntree = ET.parse(xml_source)  # Safe by default"
        },
        "smuggling": {
            "owasp_category": "A05:2021-Security Misconfiguration",
            "fix": "Normalize Transfer-Encoding handling. Reject ambiguous CL/TE combinations. Use HTTP/2 end-to-end.",
            "code_snippet": "# Nginx config:\nproxy_http_version 1.1;\nproxy_set_header Connection '';"
        },
        "race": {
            "owasp_category": "A04:2021-Insecure Design",
            "fix": "Implement idempotency keys, database-level locks (SELECT FOR UPDATE), or atomic check-and-update operations.",
            "code_snippet": "# Use database lock:\nwith db.begin():\n    row = db.execute(select(Coupon).where(Coupon.id == coupon_id).with_for_update()).scalar_one()\n    if row.used: raise AlreadyUsed\n    row.used = True"
        },
        "cache_poison": {
            "owasp_category": "A05:2021-Security Misconfiguration",
            "fix": "Include all response-influencing headers in cache keys. Add Vary headers. Strip unrecognized forwarded headers at the edge.",
            "code_snippet": "# Nginx: strip unkeyed headers\nproxy_set_header X-Forwarded-Host '';\nadd_header Vary 'Accept-Encoding, Host';"
        },
        "oauth": {
            "owasp_category": "A07:2021-Identification and Authentication Failures",
            "fix": "Validate redirect_uri against a strict allowlist. Require and verify state parameter. Disable implicit flow; use PKCE.",
            "code_snippet": "ALLOWED_REDIRECTS = {'https://app.example.com/callback'}\nif redirect_uri not in ALLOWED_REDIRECTS: raise InvalidRequest"
        },
        "rce": {
            "owasp_category": "A03:2021-Injection",
            "fix": "Never pass user input to system commands. Use safe APIs (subprocess with shell=False), strict allowlists, and sandboxed execution.",
            "code_snippet": "import subprocess\n# Safe: no shell, explicit args\nresult = subprocess.run(['ping', '-c', '1', validated_host], capture_output=True, shell=False)"
        },
        "deser": {
            "owasp_category": "A08:2021-Software and Data Integrity Failures",
            "fix": "Never deserialize untrusted data. Use safe formats (JSON). Implement HMAC integrity checks on serialized objects.",
            "code_snippet": "import json\n# Use JSON instead of pickle:\ndata = json.loads(user_input)\n# If serialization needed, sign it:\nimport hmac\nsig = hmac.new(secret, payload, 'sha256').hexdigest()"
        },
        "cloud_exposure": {
            "owasp_category": "A05:2021-Security Misconfiguration",
            "fix": "Block access to sensitive files (.env, .git) via web server config. Disable directory listing on cloud storage buckets.",
            "code_snippet": "# Nginx: block sensitive paths\nlocation ~ /\\.(env|git|aws) { deny all; return 404; }"
        },
    }
    
    # Direct match
    key = finding_category.lower()
    if key in remediation_map:
        return remediation_map[key]
    
    # Prefix/substring fallback
    for map_key, value in remediation_map.items():
        if map_key in key or key in map_key:
            return value
        
    return {
        "owasp_category": "Unknown",
        "fix": "Review the vulnerability details and apply appropriate security controls.",
        "code_snippet": ""
    }
