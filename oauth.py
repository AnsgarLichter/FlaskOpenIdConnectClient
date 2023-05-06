from authlib.integrations.flask_client import OAuth

from app import app

oauth = OAuth(app)


oauth.register(name='google')

oauth.register(name='microsoft')

oauth.register(name='orcid')

oauth.register(name='gitlab')