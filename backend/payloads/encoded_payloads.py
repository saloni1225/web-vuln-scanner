from urllib.parse import quote
import base64


def url_encode(payload: str) -> str:
    return quote(payload, safe="")


def base64_encode(payload: str) -> str:
    return base64.b64encode(payload.encode("utf-8")).decode("ascii")

