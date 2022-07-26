# FLASK
SECRET_KEY = 'secret-key'

# OPENID OAUTH2 JWT
# https://docs.authlib.org/en/latest/flask/2/openid-connect.html
# https://openid.net/specs/openid-connect-core-1_0.html#IDToken
OAUTH2_JWT_ENABLED = True                # Not implemented
OAUTH2_JWT_KEY = 'secret-key'            # REQUIRED Should be strong
OAUTH2_JWT_ISS = 'https://authlib3.org'  # REQUIRED Should be https, no query/fragment
OAUTH2_JWT_ALG = 'HS256'                 # REQUIRED unless no token ID
OAUTH2_JWT_EXP = 3600                    # REQUIRED