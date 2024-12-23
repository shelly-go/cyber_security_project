import logging
from http import HTTPStatus

from client.request_handler import RequestHandler
from common.crypto import CryptoHelper


class ServerAPI:
    def __init__(self, client):
        self.request_handler = RequestHandler()
        self.client = client
        self.logger = logging.getLogger()

    def server_request_otp(self):
        self.logger.info(f"Requesting OTP for {self.client.phone_num}")
        request_data = {'phone_number': self.client.phone_num}
        response_data, response_code = self.request_handler.request('/register/number',
                                                                    data=request_data)
        if not response_code == HTTPStatus.OK:
            self.logger.critical(
                f"Error requesting OTP. error status: {response_code}. error data: {str(response_data)}")
            exit(1)
        self.logger.info(f"OTP request for {self.client.phone_num} was sent")
        otp = response_data['otp']
        self.logger.info(f"##########\nReceived via secure channel to {self.client.phone_num}: {otp}\n##########")
        return otp

    def server_submit_otp(self, otp):
        self.logger.info("Submitting the received OTP")
        otp_hash = CryptoHelper.hash_with_sha256(otp.encode())
        request_data = {'phone_number': self.client.phone_num,
                        'otp_hash': otp_hash}
        response_data, response_code = self.request_handler.request('/register/otp',
                                                                    data=request_data)
        if not response_code == HTTPStatus.OK:
            self.logger.critical(
                f"Error requesting OTP. error status: {response_code}. error data: {str(response_data)}")
            exit(1)
        return response_data['status'] == "ok"
