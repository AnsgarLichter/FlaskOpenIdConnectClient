from app import app
from login_manager import LoginManager
from database import db
from hash import flask_bcrypt

from views import blueprint


app.register_blueprint(blueprint)
