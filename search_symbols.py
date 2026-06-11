with open("backend/api/routes.py", "r", encoding="utf-8") as f:
    content = f.read()

symbols = ["auth_me", "auth_mfa", "enroll_mfa", "verify_mfa", "/auth/me", "requires_mfa"]
for sym in symbols:
    count = content.count(sym)
    print(f"Symbol '{sym}': count={count}")
