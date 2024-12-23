import logging
from http import HTTPStatus

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

from client.request_handler import RequestHandler
from common.api_consts import OTP_HASH_FIELD, PUB_ID_KEY_FIELD, PHONE_NUMBER_FIELD, OTP_FIELD, \
    API_ENDPOINT_REGISTER_NUMBER, API_ENDPOINT_REGISTER_VALIDATE, STATUS_FIELD, STATUS_OK
from common.crypto import CryptoHelper


class ServerAPI:
    def __init__(self, client):
        self.request_handler = RequestHandler()
        self.client = client
        self.logger = logging.getLogger()

    def server_request_otp(self):
        self.logger.info(f"Requesting OTP for {self.client.phone_num}")
        request_data = {PHONE_NUMBER_FIELD: self.client.phone_num}
        response_data, response_code = self.request_handler.request(API_ENDPOINT_REGISTER_NUMBER,
                                                                    data=request_data)
        if not response_code == HTTPStatus.OK:
            self.logger.critical(
                f"Error requesting OTP. error status: {response_code}. error data: {str(response_data)}")
            exit(1)
        self.logger.info(f"OTP request for {self.client.phone_num} was sent")
        otp = response_data[OTP_FIELD]
        self.logger.info(f"##########\nReceived via secure channel to {self.client.phone_num}: {otp}\n##########")
        return otp

    def server_submit_otp_with_id_key(self, otp, pub_id_key: RSAPublicKey):
        self.logger.info("Submitting the received OTP")
        otp_hash = CryptoHelper.hash_with_sha256(otp.encode())
        request_data = {PHONE_NUMBER_FIELD: self.client.phone_num,
                        OTP_HASH_FIELD: otp_hash,
                        PUB_ID_KEY_FIELD: CryptoHelper.pub_key_to_str(pub_id_key)}
        response_data, response_code = self.request_handler.request(API_ENDPOINT_REGISTER_VALIDATE,
                                                                    data=request_data)
        if not response_code == HTTPStatus.OK:
            self.logger.critical(
                f"Error requesting OTP. error status: {response_code}. error data: {str(response_data)}")
            exit(1)
        return response_data[STATUS_FIELD] == STATUS_OK
