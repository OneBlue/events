import base64
import struct
import logging
import binascii
from datetime import datetime
from .errors import *
from urllib.parse import quote_plus, unquote_plus
from ecdsa.keys import BadSignatureError

def decode_token(token: str) -> (int, str):
    try:
        blob = base64.decodebytes(token.encode())
        if len(blob) != 56:
            raise RuntimeError(f'Unexpected blob length: {len(blob)})')

    except: # Some browsers will double escape the token.
        blob = base64.decodebytes(unquote_plus(token).encode())
        if len(blob) != 56:
            raise RuntimeError(f'Unexpected blob length: {len(blob)})')


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

def generate_access_url(settings, path: str, expires: datetime) -> str:
    return settings.external_url + path + '?t=' + quote_plus(generate_token(settings, path, expires))
