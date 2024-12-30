import logging
from http import HTTPStatus

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.x509 import Certificate

from client.request_handler import RequestHandler
from common.api_consts import OTP_HASH_FIELD, ID_KEY_FIELD, PHONE_NUMBER_FIELD, OTP_FIELD, \
    API_ENDPOINT_REGISTER_NUMBER, API_ENDPOINT_REGISTER_VALIDATE, STATUS_FIELD, STATUS_OK, ONETIME_KEYS_FIELD, \
    API_ENDPOINT_USER_KEYS
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

    def server_submit_otp_with_id_key(self, otp, id_key_cert: Certificate):
        self.logger.info("Submitting the received OTP")
        otp_hash = CryptoHelper.hash_data_to_hex(otp.encode())
        request_data = {PHONE_NUMBER_FIELD: self.client.phone_num,
                        OTP_HASH_FIELD: otp_hash,
                        ID_KEY_FIELD: CryptoHelper.cert_to_str(id_key_cert)}
        response_data, response_code = self.request_handler.request(API_ENDPOINT_REGISTER_VALIDATE,
                                                                    data=request_data)
        if not response_code == HTTPStatus.OK:
            self.logger.critical(
                f"Error requesting OTP. error status: {response_code}. error data: {str(response_data)}")
            exit(1)
        return response_data[STATUS_FIELD] == STATUS_OK

    def server_submit_otks(self, pub_otk_dict):
        self.logger.info("Submitting generated OTPs")
        request_data = {PHONE_NUMBER_FIELD: self.client.phone_num,
                        ONETIME_KEYS_FIELD: pub_otk_dict}
        response_data, response_code = self.request_handler.request(API_ENDPOINT_USER_KEYS,
                                                                    data=request_data)
        if not response_code == HTTPStatus.OK:
            self.logger.critical(
                f"Error submitting OTKs. error status: {response_code}. error data: {str(response_data)}")
            exit(1)
        return response_data[STATUS_FIELD] == STATUS_OK
