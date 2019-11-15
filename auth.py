import jwt
import datetime
from constants import *
from typing import Optional


def encode_auth_token(login: str) -> str:
    """
    Generates the Auth Token
    :return: token string
    """
    payload = {
        'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=TOKEN_TTL_MINUTES),
        'iat': datetime.datetime.utcnow(),
        'sub': login
    }
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256').decode("utf-8")


def decode_auth_token(auth_token: str) -> Optional[str]:
    """
    Decodes the auth token
    :param auth_token:
    :return: string
    """
    try:
        payload = jwt.decode(auth_token.encode("utf-8"), SECRET_KEY)
        return payload['sub']
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None
