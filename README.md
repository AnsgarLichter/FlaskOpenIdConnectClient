# FlaskOpenIdConnectClient

This repository contains a proof of concept for an OpenID Connect client in Python with Flask.
This PoC is needed for an university project.

The target is to sign up and login with multiple OIDC providers with a generic implementation.
It must be possible to configure which OIDC properties are mapped to which user properties. In special cases it should be possible to use a plugin hook to override the generic implementation.

## Authlib

This PoC uses [Authlib](https://authlib.org/) as a library to make the implementation easier. Authlib is used because the university
project has already used Authlib for other scenarios.

This proof of concept is inspired by the official [Authlib Flask Demo](https://github.com/authlib/demo-oauth-client/tree/master/flask-google-login).
