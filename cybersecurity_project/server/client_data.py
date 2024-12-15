from dataclasses import dataclass
from typing import List


@dataclass
class ClientData:
    phone_number: str
    messages: List[bytes]
    identity_key: bytes
    signed_key: bytes
    one_time_keys: List[bytes]




