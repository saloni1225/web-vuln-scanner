class SessionManager:
    def __init__(self) -> None:
        self.cookies: dict[str, str] = {}
        self.headers: dict[str, str] = {}

    def set_cookie(self, name: str, value: str) -> None:
        self.cookies[name] = value

    def set_header(self, name: str, value: str) -> None:
        self.headers[name] = value

