import json
from hashlib import sha256

from pydantic import BaseModel, ConfigDict


class Model(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)


def stable_id(kind: str, *parts: str) -> str:
    return f"{kind}:" + sha256("\0".join(parts).encode()).hexdigest()[:24]


def digest(value) -> str:
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
