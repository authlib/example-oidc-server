import os
import tempfile
from urllib.parse import urlparse, parse_qs
from authlib.integrations import sqla_oauth2

import pytest
from flask.testing import FlaskClient

from website.app import create_app


@pytest.fixture
def client() -> FlaskClient:
    db_fd, dbfile = tempfile.mkstemp()
    app = create_app({
        'SECRET_KEY': 'secret',
        'SQLALCHEMY_TRACK_MODIFICATIONS': False,
        'SQLALCHEMY_DATABASE_URI': 'sqlite:///' + dbfile,
    })
    app.config['TESTING'] = True
    with app.test_client() as client:
        with app.app_context():
            from website.models import db
            db.create_all()
        yield client
    os.close(db_fd)
    os.unlink(dbfile)

def login(client, username):
    return client.post('/', data=dict(username=username), follow_redirects=True)

def profile(client, name, email):
    return client.post('/edit_user', data=dict(
        name=name,
        email=email
    ), follow_redirects=True)

def test_empty_db(client):
    rv = client.get('/')
    assert b'Login / Signup' in rv.data

def test_login(client):
    rv = login(client, 'admin')
    assert b'Logged in as' in rv.data

def test_create_client(client:FlaskClient):
    from website.models import OAuth2Client

    rv = login(client, 'admin')
    assert b'Logged in as' in rv.data

    rv = profile(client, 'testname', 'foo@bar.spam')
    assert rv.status_code == 200

    rv = client.post('/create_client', data=dict(
        client_name='test',
        client_uri='https://a.b',
        scope='openid profile email',
        redirect_uri='https://a.b/callback',
        grant_type='authorization_code',
        response_type='code',
        token_endpoint_auth_method='client_secret_post'
    ), follow_redirects=True)
    assert 200 == rv.status_code
    assert b'client_id' in rv.data

    oc = OAuth2Client.query.limit(1).first()

    # Authorize
    rv = client.post('/oauth/authorize', query_string=dict(
        response_type='code',
        client_id=oc.client_id,
        redirect_ui='https://a.b/callback',
        scope='openid profile email name perferred_username',
        state='abc'
    ), data={'confirm': 'confirm', 'username': 'admin'})
    assert 302 == rv.status_code
    assert rv.headers['Location'].startswith('https://a.b/callback')
    parsed_url = urlparse(rv.headers['Location'])
    qs = parse_qs(parsed_url.query)
    assert 'state' in qs
    assert qs['state'] == ['abc']
    assert 'code' in qs
    code = qs['code']

    # Get token
    rv = client.post('/oauth/token', data=dict(
        code=code,
        grant_type='authorization_code',
        client_id=oc.client_id,
        client_secret=oc.client_secret,
        redirect_uri='https://a.b/callback'
    ))
    assert 200 == rv.status_code
    # {"access_token": "<stuff>", "expires_in": 864000, "id_token": "<stuff>", "scope": "<stuff>", "token_type": "Bearer"}
    json_token = rv.get_json()
    assert 'access_token' in json_token
    assert 'id_token' in json_token

    # Userinfo
    rv = client.get('/oauth/userinfo', headers=dict(
        Authorization='Bearer ' + json_token['access_token']
    ))
    assert 200 == rv.status_code
    jinfo = rv.get_json()
    assert 'sub' in jinfo
    # extras
    assert 'name' in jinfo
    assert 'email' in jinfo
    assert 'name' in jinfo
    assert 'preferred_username' in jinfo
