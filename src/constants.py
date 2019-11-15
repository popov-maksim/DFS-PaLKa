import os

LOGIN_KEY = 'login'
ENCRYPTED_PASS_KEY = 'encrypted_pass'
TOKEN_KEY = 'token'
MESSAGE_KEY = 'message'

TOKEN_TTL_MINUTES = 30

try:
    SECRET_KEY = os.getenv('SECRET_KEY')
except ValueError as e:
    print("Environment variable `SECRET_KEY` is absent.")
