import base64
import struct
import logging
from datetime import datetime
from .errors import *
from urllib.parse import quote_plus
from ecdsa.keys import BadSignatureError

def decode_token(token: str) -> (int, str):
    blob = base64.decodebytes(token.encode())
    
    ts = struct.unpack("<Q", blob[:8])[0]

    return ts, blob[8:]

def validate_token(settings, token: str, url: str):
    try:
        ts, sig = decode_token(token)
    except Exception as e:
        raise InvalidToken() from e 


    logging.debug(f'Decoded token ts: {ts}')

    # Validate signature
    try:
        if not settings.signing_key.get_verifying_key().verify(sig, (url + str(ts)).encode()):
            raise InvalidToken()
    except BadSignatureError as e:
        raise InvalidToken() from e

    # Validate ts
    # 0 ts means token is valid forever
    if ts != 0 and datetime.fromtimestamp(ts) < datetime.now():
        raise ExpiredToken()

def generate_token(settings, url: str, expires: datetime) -> str:
    ts = int(datetime.timestamp(expires))

    logging.debug(f'Generating token for ts: {ts}')

    # Convert int to an 8 bytes LE integer
    bytes = ts.to_bytes(8, 'little')

    # Generate signature (sign url to protect against token reuse)
    bytes += settings.signing_key.sign((url + str(ts)).encode())

    # Base64 encode
    return base64.b64encode(bytes).decode()

def generate_access_url(settings, request, expires: datetime) -> str:
    return request.base_url + '?t=' + quote_plus(generate_token(settings, request.path, expires))
