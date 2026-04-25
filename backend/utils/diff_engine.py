from difflib import SequenceMatcher


def similarity(left: str, right: str) -> float:
    return SequenceMatcher(None, left, right).ratio()


def changed_significantly(left: str, right: str, threshold: float = 0.75) -> bool:
    return similarity(left, right) < threshold

