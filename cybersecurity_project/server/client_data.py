from dataclasses import dataclass
from typing import List


@dataclass
class ClientData:
    phone_number: str
    messages: List[bytes] = None
    identity_key: bytes = None
    signed_key: bytes = None
    one_time_keys: List[bytes] = None

    otp_hash: str = None
