import logging
from http import HTTPStatus

from cryptography.x509 import Certificate

from client.request_handler import RequestHandler
from common.api_consts import OTP_HASH_FIELD, ID_KEY_FIELD, PHONE_NUMBER_FIELD, OTP_FIELD, \
    API_ENDPOINT_REGISTER_NUMBER, API_ENDPOINT_REGISTER_VALIDATE, STATUS_FIELD, STATUS_OK, ONETIME_KEYS_FIELD, \
    API_ENDPOINT_USER_KEYS, TARGET_NUMBER_FIELD, TARGET_NUMBER_SIGNATURE_FIELD, API_ENDPOINT_USER_ID, \
    API_ENDPOINT_MSG_REQUEST, ONETIME_KEY_FIELD, ONETIME_KEY_UUID_FIELD, MESSAGE_PUBLIC_KEY_FIELD, \
    MESSAGE_ENC_MESSAGE_FIELD, \
    MESSAGE_BUNDLE_SIGNATURE_FIELD, API_ENDPOINT_MSG_SEND, PHONE_NUMBER_SIGNATURE_FIELD, MESSAGE_INCOMING_FIELD, \
    MESSAGE_CONF_INCOMING_FIELD, API_ENDPOINT_MSG_INBOX
from common.crypto import CryptoHelper


class ServerAPI:
    def __init__(self, client):
        self.request_handler = RequestHandler()
        self.server_certificate = self.request_handler.server_certificate
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
        self.logger.info("Submitting generated OTKs")
        request_data = {PHONE_NUMBER_FIELD: self.client.phone_num,
                        ONETIME_KEYS_FIELD: pub_otk_dict}
        response_data, response_code = self.request_handler.request(API_ENDPOINT_USER_KEYS,
                                                                    data=request_data)
        if not response_code == HTTPStatus.OK:
            self.logger.critical(
                f"Error submitting OTKs. error status: {response_code}. error data: {str(response_data)}")
            exit(1)
        return response_data[STATUS_FIELD] == STATUS_OK

    def server_request_target_id_key(self, target, target_signature):
        self.logger.info("Requesting target Id-Key")
        request_data = {PHONE_NUMBER_FIELD: self.client.phone_num,
                        TARGET_NUMBER_FIELD: target,
                        TARGET_NUMBER_SIGNATURE_FIELD: target_signature}
        response_data, response_code = self.request_handler.request(API_ENDPOINT_USER_ID,
                                                                    data=request_data)
        if not response_code == HTTPStatus.OK:
            self.logger.critical(
                f"Error requesting Id-Key. error status: {response_code}. error data: {str(response_data)}")
            exit(1)
        target_id_key = CryptoHelper.cert_from_str(response_data[ID_KEY_FIELD])
        return target_id_key

    def server_request_target_otk(self, target, target_signature):
        self.logger.info("Requesting target OTK")
        request_data = {PHONE_NUMBER_FIELD: self.client.phone_num,
                        TARGET_NUMBER_FIELD: target,
                        TARGET_NUMBER_SIGNATURE_FIELD: target_signature}
        response_data, response_code = self.request_handler.request(API_ENDPOINT_MSG_REQUEST,
                                                                    data=request_data)
        if not response_code == HTTPStatus.OK:
            self.logger.critical(
                f"Error requesting OTK. error status: {response_code}. error data: {str(response_data)}")
            exit(1)
        target_otk_uuid, target_otk, target_otk_signature = response_data[ONETIME_KEY_FIELD]
        return target_otk_uuid, target_otk, target_otk_signature

    def server_submit_message_and_ek(self, target, target_otk_uuid, session_pub_key_str, enc_message, bundle_signature):
        self.logger.info("Sending encrypted message")
        request_data = {PHONE_NUMBER_FIELD: self.client.phone_num,
                        TARGET_NUMBER_FIELD: target,
                        ONETIME_KEY_UUID_FIELD: target_otk_uuid,
                        MESSAGE_PUBLIC_KEY_FIELD: session_pub_key_str,
                        MESSAGE_ENC_MESSAGE_FIELD: enc_message,
                        MESSAGE_BUNDLE_SIGNATURE_FIELD: bundle_signature}
        response_data, response_code = self.request_handler.request(API_ENDPOINT_MSG_SEND,
                                                                    data=request_data)
        if not response_code == HTTPStatus.OK:
            self.logger.critical(
                f"Error requesting OTK. error status: {response_code}. error data: {str(response_data)}")
            exit(1)
        return response_data[STATUS_FIELD] == STATUS_OK

    def server_request_inbox(self, phone_num_signature):
        self.logger.info("Sending inbox request")
        request_data = {PHONE_NUMBER_FIELD: self.client.phone_num,
                        PHONE_NUMBER_SIGNATURE_FIELD: phone_num_signature}
        response_data, response_code = self.request_handler.request(API_ENDPOINT_MSG_INBOX,
                                                                    data=request_data)
        if not response_code == HTTPStatus.OK:
            self.logger.critical(
                f"Error requesting OTK. error status: {response_code}. error data: {str(response_data)}")
            exit(1)

        incoming_messages = response_data[MESSAGE_INCOMING_FIELD]
        incoming_confirmations = response_data[MESSAGE_CONF_INCOMING_FIELD]
        return incoming_messages, incoming_confirmations
