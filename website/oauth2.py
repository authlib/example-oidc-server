from authlib.integrations.flask_oauth2 import (
    AuthorizationServer, ResourceProtector)
from authlib.integrations.sqla_oauth2 import (
    create_query_client_func,
    create_save_token_func,
    create_bearer_token_validator,
)
from authlib.oauth2.rfc6749.grants import (
    AuthorizationCodeGrant as _AuthorizationCodeGrant,
)
from authlib.oidc.core.grants import (
    OpenIDCode as _OpenIDCode,
    OpenIDImplicitGrant as _OpenIDImplicitGrant,
    OpenIDHybridGrant as _OpenIDHybridGrant,
)
from authlib.oidc.core import UserInfo
from werkzeug.security import gen_salt
from .models import db, User
from .models import OAuth2Client, OAuth2AuthorizationCode, OAuth2Token
from flask import current_app



def exists_nonce(nonce, req):
    exists = OAuth2AuthorizationCode.query.filter_by(
        client_id=req.client_id, nonce=nonce
    ).first()
    return bool(exists)


def get_jwt_config():
    if current_app.config.get('OAUTH2_JWT_ENABLED',False) \
    and 'OAUTH2_JWT_KEY' not in current_app.config:
        raise NotImplementedError('"OAUTH2_JWT_KEY" missing from settings')
    return {
        'key': current_app.config.get('OAUTH2_JWT_KEY'),
        'alg': current_app.config.get('OAUTH2_JWT_ALG', 'HS256'),
        'iss': current_app.config.get('OAUTH2_JWT_ISS', 'https://authlib.org'),
        'exp': current_app.config.get('OAUTH2_JWT_EXP', 3600),
    }


def generate_user_info(user, scope):
    return UserInfo(sub=str(user.id), name=user.username)


def save_authorization_code(code, request):
    auth_code = OAuth2AuthorizationCode(
        code=code,
        client_id=request.client.client_id,
        redirect_uri=request.redirect_uri,
        scope=request.scope,
        user_id=request.user.id,
        nonce=request.data.get('nonce'), # MAY have nonce
    )
    db.session.add(auth_code)
    db.session.commit()
    return auth_code


class AuthorizationCodeGrant(_AuthorizationCodeGrant):
    def save_authorization_code(self, code, request):
        return save_authorization_code(code, request)

    def query_authorization_code(self, code, client):
        item = OAuth2AuthorizationCode.query.filter_by(
            code=code, client_id=client.client_id).first()
        if item and not item.is_expired():
            return item

    def delete_authorization_code(self, authorization_code):
        db.session.delete(authorization_code)
        db.session.commit()

    def authenticate_user(self, authorization_code):
        return User.query.get(authorization_code.user_id)


class OpenIDCode(_OpenIDCode):
    def exists_nonce(self, nonce, request):
        return exists_nonce(nonce, request)

    def get_jwt_config(self, grant):
        return get_jwt_config()

    def generate_user_info(self, user, scope):
        return generate_user_info(user, scope)


class ImplicitGrant(_OpenIDImplicitGrant):
    def exists_nonce(self, nonce, request):
        return exists_nonce(nonce, request)

    def get_jwt_config(self, grant):
        return get_jwt_config()

    def generate_user_info(self, user, scope):
        return generate_user_info(user, scope)


class HybridGrant(_OpenIDHybridGrant):
    def save_authorization_code(self, code, request):
        return save_authorization_code(code, request)

    def exists_nonce(self, nonce, request):
        return exists_nonce(nonce, request)

    def get_jwt_config(self):
        return get_jwt_config()

    def generate_user_info(self, user, scope):
        return generate_user_info(user, scope)


authorization = AuthorizationServer()
require_oauth = ResourceProtector()


def config_oauth(app):
    query_client = create_query_client_func(db.session, OAuth2Client)
    save_token = create_save_token_func(db.session, OAuth2Token)
    authorization.init_app(
        app,
        query_client=query_client,
        save_token=save_token
    )

    # support all openid grants
    authorization.register_grant(AuthorizationCodeGrant, [
        OpenIDCode(require_nonce=True),
    ])
    authorization.register_grant(ImplicitGrant)
    authorization.register_grant(HybridGrant)

    # protect resource
    bearer_cls = create_bearer_token_validator(db.session, OAuth2Token)
    require_oauth.register_token_validator(bearer_cls())
