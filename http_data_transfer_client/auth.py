import time

import jwt


TOKEN_EXPIRE_DELAY_OFFSET = 5


def check_expiration(token):
    """Check token expiration, ignoring validation"""
    data = jwt.decode(
        token,
        algorithms=['RS256', 'RS512'],
        options={"verify_signature": False}
    )
    # account for an X second delay over the wire, so expire sooner
    if 'exp' in data and data['exp'] < time.time() + TOKEN_EXPIRE_DELAY_OFFSET:
        raise Exception('token is expired')
