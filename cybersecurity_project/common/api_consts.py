PHONE_NUMBER_FIELD = 'phone_number'
PHONE_NUMBER_SIGNATURE_FIELD = 'phone_number_signature'

OTP_FIELD = 'otp'

ID_KEY_FIELD = 'id_key'
ENC_ID_KEY_FIELD = 'enc_id_key'

ONETIME_KEYS_FIELD = 'one_time_keys'
ONETIME_KEY_FIELD = 'one_time_key'
ONETIME_KEY_UUID_FIELD = 'one_time_key_id'
ONETIME_KEY_SHOULD_APPEND_FIELD = 'should_append_keys'

TARGET_NUMBER_FIELD = 'target_number'
TARGET_NUMBER_SIGNATURE_FIELD = 'target_number_signature'

MESSAGE_PUBLIC_KEY_FIELD = 'public_session_key'
MESSAGE_ENC_MESSAGE_FIELD = 'enc_message'
MESSAGE_BUNDLE_SIGNATURE_FIELD = 'bundle_signature'
MESSAGE_HASH_FIELD = 'message_hash'
MESSAGE_INCOMING_FIELD = 'incoming_messages'
MESSAGE_CONF_INCOMING_FIELD = 'incoming_message_confirmations'

STATUS_FIELD = 'status'
ERROR_FIELD = 'error'

STATUS_OK = 'ok'
STATUS_OK_RESPONSE = {STATUS_FIELD: STATUS_OK}
UNSPECIFIED_ERROR = 'Unspecified'

API_ENDPOINT_ROOT = "/"

API_ENDPOINT_REGISTER_NUMBER = "/register/number"
API_ENDPOINT_REGISTER_VALIDATE = "/register/validate"

API_ENDPOINT_USER_KEYS = "/usr/keys"
API_ENDPOINT_USER_ID = "/usr/id"

API_ENDPOINT_MSG_REQUEST = "/msg/request"
API_ENDPOINT_MSG_SEND = "/msg/send"
API_ENDPOINT_MSG_INBOX = "/msg/inbox"
API_ENDPOINT_MSG_CONFIRM = "/msg/confirm"

MAX_USERS = 10
MAX_MSGS = 2
UNAVAILABLE_MAX_ATTEMPTS = 3
UNAVAILABLE_TIME_BETWEEN_ATTEMPTS = 3
