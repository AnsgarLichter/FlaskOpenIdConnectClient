from flask import render_template, redirect, session, url_for, Blueprint

# Flask Login
from flask_login import login_required, login_user, logout_user, current_user

from database import db
from oauth import oauth
from hash import flask_bcrypt

from forms.login_form import LoginForm
from forms.sign_up_form import SignUpForm

from models.user import User, LocalUser

blueprint = Blueprint('views', __name__)

# TODO: Add configuration possibilities for needed user parameters


@blueprint.route("/")
def welcome():
    return render_template("main.html")


@blueprint.route("/signup", methods=["GET", "POST"])
def signup():
    form = SignUpForm()

    if not form.validate_on_submit():
        return render_template("signup.html", form=form)

    User.create_local_user(
        username=form.username.data,
        password=form.password.data
    )
    db.session.commit()

    return redirect(url_for("views.login"))


@blueprint.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()

    if not form.validate_on_submit():
        return render_template("login.html", form=form)

    local_user = LocalUser.query.join(LocalUser.user).filter_by(
        username=form.username.data,
    ).first()

    if not local_user or not flask_bcrypt.check_password_hash(local_user.password, form.password.data):
        return render_template("login.html", form=form)

    login_user(local_user.user)
    return redirect(url_for("views.protected"))


@blueprint.route("/logout", methods=["GET", "POST"])
def logout():
    logout_user()

    return redirect(url_for("views.welcome"))


@blueprint.route("/delete", methods=["POST"])
def delete_account():
    db.session.delete(current_user)
    db.session.commit()

    return redirect(url_for("views.welcome"))


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
    user = User.query.join(User.connected_providers).filter_by(
        sub=user_info.sub).first()
    if user:
        return redirect(url_for("views.login_oidc", provider=provider))

    user_name = user_info.name
    if provider == 'microsoft':
        user_name = user_info['preferred_username']
    elif provider == 'orcid':
        user_name = f"{user_info['given_name']}{user_info['family_name']}"
    elif provider == 'gitlab':  # user_info.name does work but is already used in the test example
        user_name = f"{user_name}_gitlab"

    user = User.create_oidc_account(
        username=user_name, provider=provider, sub=user_info.sub)
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
    user = User.query.join(User.connected_providers).filter_by(
        sub=user_info.sub).first()
    if not user:
        return redirect(url_for("views.signup"))

    login_user(user)
    return redirect(url_for("views.protected"))


@blueprint.route("/protected")
@login_required
def protected():
    connected_providers = current_user.connected_providers.all()
    providers = [{"name": "google"}, {"name": "microsoft"},
                 {"name": "orcid"}, {"name": "gitlab"}]

    for provider in providers:
        if not next((connected_provider for connected_provider in connected_providers if connected_provider.provider == provider["name"]), None):
            provider['text'] = "Connect"
            provider['url'] = url_for(
                'views.connect_provider', provider=provider["name"])
            continue

        provider['text'] = "Disonnect"
        provider['url'] = url_for(
            'views.disconnect_oidc', provider=provider["name"])

    return render_template(
        "protected.html",
        providers=providers
    )


@blueprint.route("/connect/<provider>")
@login_required
def connect_provider(provider):
    redirect_url = url_for("views.authorize_connect_oidc",
                           _external=True, provider=provider)
    client = oauth.create_client(provider)

    if not client:
        return

    return client.authorize_redirect(redirect_url)


@blueprint.route("/connect/<provider>/authorize")
@login_required
def authorize_connect_oidc(provider):
    client = oauth.create_client(provider)
    token = client.authorize_access_token()

    print(f"\nToken: {token}\n")

    user_info = token['userinfo']
    current_user.connect_oidc_provider(provider, user_info.sub)
    db.session.commit()

    return redirect(url_for("views.protected"))


@blueprint.route("/disconnect/<provider>")
@login_required
def disconnect_oidc(provider):
    client = oauth.create_client(provider)
    if not client:
        return redirect(url_for("views.protected"))

    current_user.disconnect_oidc_provider(provider)
    db.session.commit()

    return redirect(url_for("views.protected"))
