import os

ENV = 'development'
SQLALCHEMY_DATABASE_URI = "sqlite:///database.db"
SECRET_KEY = "secret"

OIDC_PROVIDER_PROPERTIES_TO_MAP = [
    'username'
]
OIDC_PROVIDER = [
    {
        'providerName': 'google',
        'email': 'email',
        'email_verified': 'email_verified',
        'username': {
            'fields': ['given_name', 'family_name'],
            'separator': ''
        },
        'displayname': {
            'fields': ['given_name', 'family_name'],
            'separator': ' '
        }
    },
    {
        'providerName': 'microsoft',
        'email': 'email',
        'email_verified': '',
        'username': 'preferred_username',
        'displayname': 'name'
    },
    {
        'providerName': 'gitlab',
        'email': 'email',
        'email_verified': 'email_verified',
        'username': 'nickname',
        'displayname': 'name'
    },
    {
        'providerName': 'orcid',
        'email': '',  # TODO: Provide form for user to be able to enter email address
        'email_verified': '',
        'username': {
            'fields': ['given_name', 'family_name'],
            'separator': ''
        },
        'displayname': {
            'fields': ['given_name', 'family_name'],
            'separator': ' '
        }
    }
]

GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.getenv('GOOGLE_CLIENT_SECRET')
GOOGLE_SERVER_METADATA_URL = os.getenv('GOOGLE_SERVER_METADATA_URL')
GOOGLE_CLIENT_KWARGS = {
    'scope': 'openid email profile'
}

MICROSOFT_CLIENT_ID = os.getenv('MICROSOFT_CLIENT_ID')
MICROSOFT_CLIENT_SECRET = os.getenv('MICROSOFT_CLIENT_SECRET')
MICROSOFT_SERVER_METADATA_URL = os.getenv('MICROSOFT_SERVER_METADATA_URL')
MICROSOFT_CLIENT_KWARGS = {
    'scope': 'openid email profile'
}

GITLAB_CLIENT_ID = os.getenv('GITLAB_CLIENT_ID')
GITLAB_CLIENT_SECRET = os.getenv('GITLAB_CLIENT_SECRET')
GITLAB_SERVER_METADATA_URL = os.getenv('GITLAB_SERVER_METADATA_URL')
GITLAB_CLIENT_KWARGS = {
    'scope': 'openid email profile'
}

ORCID_CLIENT_ID = os.getenv('ORCID_CLIENT_ID')
ORCID_CLIENT_SECRET = os.getenv('ORCID_CLIENT_SECRET')
ORCID_SERVER_METADATA_URL = os.getenv('ORCID_SERVER_METADATA_URL')
ORCID_CLIENT_KWARGS = {
    'scope': 'openid email profile'
}
