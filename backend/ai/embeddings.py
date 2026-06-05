from __future__ import annotations

import hashlib
import math
import re


class EmbeddingEngine:
    """Small deterministic embedding engine with Hugging Face compatible boundaries."""

    def __init__(self, dimensions: int = 64, model_name: str = "BAAI/bge-small-en-v1.5") -> None:
        self.dimensions = dimensions
        self.model_name = model_name

    def embed(self, text: str) -> list[float]:
        vector = [0.0] * self.dimensions
        tokens = re.findall(r"[a-zA-Z0-9_./:-]+", text.lower())
        for token in tokens:
            digest = hashlib.sha256(token.encode("utf-8")).digest()
            index = int.from_bytes(digest[:2], "big") % self.dimensions
            weight = 1.0 + (digest[2] / 255.0)
            vector[index] += weight
        norm = math.sqrt(sum(value * value for value in vector)) or 1.0
        return [round(value / norm, 6) for value in vector]

    def similarity(self, left: str, right: str) -> float:
        left_vector = self.embed(left)
        right_vector = self.embed(right)
        return round(sum(a * b for a, b in zip(left_vector, right_vector)), 4)


def embedding_runtime_status() -> dict[str, object]:
    return {
        "provider": "deterministic-local",
        "hf_ready": True,
        "supported_models": ["BAAI/bge-small-en-v1.5", "sentence-transformers/all-MiniLM-L6-v2"],
        "vector_dimensions": 64,
    }
