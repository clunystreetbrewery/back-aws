import datetime
from app import db, login_manager, app

from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash
import jwt, json




class Raspberry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    status = db.Column(db.String(10000))
    target_temperature = db.Column(db.Float)

    def __repr__(self):
        return '<Raspberry {}>'.format(self.status)

    def get_status(self):
        return json.loads(self.status)
    def set_status(self, new_status):
        print("new status  ", new_status)
        self.status = json.dumps(new_status)


# TODO: à supprimer
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True)
    email = db.Column(db.String(120), index=True, unique=True)
    password_hash = db.Column(db.String(128))
    #posts = db.relationship('Post', backref='author', lazy='dynamic')

    def __repr__(self):
        return '<User {}>'.format(self.username)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    @staticmethod
    def decode_auth_token(auth_token):
        """
        Decodes the auth token
        :param auth_token:
        :return: integer|string
        """
        try:
            payload = jwt.decode(auth_token, app.config.get('SECRET_KEY'))
            return payload['sub']
        except jwt.ExpiredSignatureError:
            return 'Signature expired. Please log in again.'
        except jwt.InvalidTokenError:
            return 'Invalid token. Please log in again.'



