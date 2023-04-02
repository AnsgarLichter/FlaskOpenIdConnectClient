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


@blueprint.route("/login/google")
def login_google():
    redirect_url = url_for("views.authorize_google", _external=True)

    return oauth.google.authorize_redirect(redirect_url)


@blueprint.route("/login/google/authorize")
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


@blueprint.route("/login/microsoft")
def login_microsoft():
    redirect_url = url_for("views.authorize_microsoft", _external=True)

    return oauth.microsoft.authorize_redirect(redirect_url)


@blueprint.route("/login/microsoft/authorize")
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


@blueprint.route("/login/orcid")
def login_orcid():
    redirect_url = url_for("views.authorize_orcid", _external=True)

    return oauth.orcid.authorize_redirect(redirect_url)


@blueprint.route("/login/orcid/authorize")
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


@blueprint.route("/login/gitlab")
def login_gitlab():
    redirect_url = url_for("views.authorize_gitlab", _external=True)

    return oauth.gitlab.authorize_redirect(redirect_url)


@blueprint.route("/login/gitlab/authorize")
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





@blueprint.route("/protected")
@login_required
def protected():
    return render_template("protected.html")
