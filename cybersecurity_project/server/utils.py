import random
import string


def generate_otp() -> str:
    return ''.join([random.choice(string.digits) for _ in range(6)])


def send_by_secure_channel(number, message):
    print(f"##########\nSending by secure channel to {number}: {message}\n##########")
