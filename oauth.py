from authlib.integrations.flask_client import OAuth

from app import app

oauth = OAuth(app)

# TODO: Move to config
CONF_URL_GOOGLE = 'https://accounts.google.com/.well-known/openid-configuration'
CONF_URL_MICROSOFT = 'https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0/.well-known/openid-configuration'
CONF_URL_ORCID = 'https://sandbox.orcid.org/.well-known/openid-configuration'
CONF_URL_GITLAB = 'https://gitlab.com/.well-known/openid-configuration'

oauth.register(
    name='google',
    server_metadata_url=CONF_URL_GOOGLE,
    client_kwargs={
        'scope': 'openid email profile'
    }
)

oauth.register(
    name='microsoft',
    server_metadata_url=CONF_URL_MICROSOFT,
    client_kwargs={
        'scope': 'openid email profile'
    }
)

oauth.register(
    name='orcid',
    server_metadata_url=CONF_URL_ORCID,
    client_kwargs={
        'scope': 'openid email profile'
    }
)

oauth.register(
    name='gitlab',
    server_metadata_url=CONF_URL_GITLAB,
    client_kwargs={
        'scope': 'openid email profile'
    }
)

# TODO: Gitlab?
# TODO: Twitter?
# TODO: Github?