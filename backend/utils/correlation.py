from contextvars import ContextVar

_correlation_id_ctx_var: ContextVar[str] = ContextVar("correlation_id", default="")

def get_correlation_id() -> str:
    return _correlation_id_ctx_var.get()

def set_correlation_id(correlation_id: str) -> None:
    _correlation_id_ctx_var.set(correlation_id)
