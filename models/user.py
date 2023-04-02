from database import db
from flask_login import UserMixin



class User(db.Model, UserMixin):
    id = db.Column(db.String(80), primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=True)
    type = db.Column(db.String(20), nullable=False)