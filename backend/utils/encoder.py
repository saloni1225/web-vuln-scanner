import base64
from urllib.parse import quote, unquote


def url_encode(value: str) -> str:
    return quote(value, safe="")


def url_decode(value: str) -> str:
    return unquote(value)


def base64_encode(value: str) -> str:
    return base64.b64encode(value.encode("utf-8")).decode("ascii")


def base64_decode(value: str) -> str:
    return base64.b64decode(value.encode("ascii")).decode("utf-8")

