from flask import render_template, redirect, session, url_for, Blueprint

# Flask Login
from flask_login import login_required, login_user, logout_user, current_user

from database import db
from oauth import oauth
from bcrypt import bcrypt

from forms.login_form import LoginForm
from forms.sign_up_form import SignUpForm

from models.user import User

blueprint = Blueprint('views', __name__)


@blueprint.route("/")
def welcome():
    return render_template("main.html")


@blueprint.route("/signup", methods=["GET", "POST"])
def signup():
    form = SignUpForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data,
                        password=hashed_password, type="local")

        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for("views.login"))

    return render_template("signup.html", form=form)


@blueprint.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(
            username=form.username.data, type="local").first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)

                return redirect(url_for("views.protected"))

    return render_template("login.html", form=form)


@blueprint.route("/logout", methods=["GET", "POST"])
def logout():
    logout_user()

    return redirect(url_for("views.welcome"))


@blueprint.route("/login/google1")
def login_google():
    redirect_url = url_for("views.authorize_google", _external=True)

    return oauth.google.authorize_redirect(redirect_url)


@blueprint.route("/login/google/authorize1")
def authorize_google():
    token = oauth.google.authorize_access_token()
    print(f"\nToken: {token}\n")

    user_info = token['userinfo']
    user = User.query.filter_by(id=user_info.sub).first()
    if not user:
        user_name = f"{user_info.given_name}{user_info.family_name}"
        user = User(id=user_info.sub, username=user_name, type='google')
        db.session.add(user)
        db.session.commit()

    login_user(user)
    return redirect(url_for("views.protected"))


@blueprint.route("/login/microsoft1")
def login_microsoft():
    redirect_url = url_for("views.authorize_microsoft", _external=True)

    return oauth.microsoft.authorize_redirect(redirect_url)


@blueprint.route("/login/microsoft/authorize1")
def authorize_microsoft():
    token = oauth.microsoft.authorize_access_token()
    print(f"\nToken: {token}\n")

    user_info = token['userinfo']
    user = User.query.filter_by(id=user_info.sub).first()
    if not user:
        user_name = {user_info.name}  # TODO: Make customizable
        user = User(id=user_info.sub, username=user_name, type='microsoft')
        db.session.add(user)
        db.session.commit()

    login_user(user)
    return redirect(url_for("views.protected"))


@blueprint.route("/login/orcid1")
def login_orcid():
    redirect_url = url_for("views.authorize_orcid", _external=True)

    return oauth.orcid.authorize_redirect(redirect_url)


@blueprint.route("/login/orcid/authorize1")
def authorize_orcid():
    token = oauth.orcid.authorize_access_token()

    print(f"\nToken: {token}\n")

    user_info = token['userinfo']
    user = User.query.filter_by(id=user_info.sub).first()
    if not user:
        user_name = f"{user_info.given_name}{user_info.family_name}"
        user = User(id=user_info.sub, username=user_name, type='orcid')
        db.session.add(user)
        db.session.commit()

    login_user(user)
    return redirect(url_for("views.protected"))


@blueprint.route("/login/gitlab1")
def login_gitlab():
    redirect_url = url_for("views.authorize_gitlab", _external=True)

    return oauth.gitlab.authorize_redirect(redirect_url)


@blueprint.route("/login/gitlab/authorize1")
def authorize_gitlab():
    token = oauth.gitlab.authorize_access_token()
    print(f"\nToken: {token}\n")

    user_info = token['userinfo']
    user = User.query.filter_by(id=user_info.sub).first()
    if not user:
        user_name = f"{user_info.given_name}{user_info.family_name}"
        user = User(id=user_info.sub, username=user_name, type='gitlab')
        db.session.add(user)
        db.session.commit()

    login_user(user)
    return redirect(url_for("views.protected"))

# TODO: Add possibilities on signup page to sign up with oidc providers
# TODO: Add configuration possibilities for needed user parameters
# TODO: Add possibility to connect multiple services to 1 account?


@blueprint.route("/signup/<provider>")
def signup_oidc(provider):
    redirect_url = url_for("views.authorize_signup_oidc",
                           _external=True, provider=provider)
    client = oauth.create_client(provider)

    if not client:
        return

    return client.authorize_redirect(redirect_url)

@blueprint.route("/signup/<provider>/authorize")
def authorize_signup_oidc(provider):
    client = oauth.create_client(provider)
    if not client:
        return

    token = client.authorize_access_token()
    print(f"{token}")

    user_info = token['userinfo']
    user = User.query.filter_by(id=user_info.sub).first()
    if user:
        return redirect(url_for("views.login_oidc", provider=provider))

    user_name = user_info.name
    if provider == 'microsoft':
        user_name = user_info['preferred_username']
    elif provider == 'orcid':
        user_name = f"{user_info['given_name']}{user_info['family_name']}"
    elif provider == 'gitlab': # user_info.name does work but is already used in the test example
        user_name = f"{user_name}_gitlab"

    user = User(id=user_info.sub, username=user_name, type=provider)
    db.session.add(user)
    db.session.commit()

    login_user(user)
    return redirect(url_for("views.protected"))

@blueprint.route("/login/<provider>")
def login_oidc(provider):
    redirect_url = url_for("views.authorize_login_oidc",
                           _external=True, provider=provider)

    return oauth.create_client(provider).authorize_redirect(redirect_url)


@blueprint.route("/login/<provider>/authorize")
def authorize_login_oidc(provider):
    client = oauth.create_client(provider)
    token = client.authorize_access_token()

    print(f"\nToken: {token}\n")

    user_info = token['userinfo']
    user = User.query.filter_by(id=user_info.sub).first()
    if not user:
        return redirect(url_for("views.welcome"))

    login_user(user)
    return redirect(url_for("views.protected"))


@blueprint.route("/protected")
@login_required
def protected():
    return render_template("protected.html")
