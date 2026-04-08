from . import db
from flask_login import UserMixin
from sqlalchemy.sql import func

class Verification(db.Model):
    id = db.Column(db.Integer,primary_key=True)
    verified = db.Column(db.Integer)
    date = db.Column(db.DateTime(timezone=True),default=func.now())
    doc = db.Column(db.String(150),unique=True)
    bio = db.Column(db.String(200))
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))


class User(db.Model,UserMixin):
    id = db.Column(db.Integer,primary_key=True)
    email = db.Column(db.String(50),unique=True)
    username = db.Column(db.String(50),unique=True)
    password = db.Column(db.String(50))
    verified = db.relationship("Verification")


class Validlinks(db.Model):
    id = db.Column(db.Integer,primary_key=True)
    email = db.Column(db.String(50))
    validlink = db.Column(db.String(200))