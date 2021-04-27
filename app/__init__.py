from flask import Flask
from flask_login import LoginManager
from config import Config
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
import os

app = Flask(__name__)

login_manager = LoginManager()
login_manager.init_app(app)


app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
app.config.from_object(Config)

app.config['TEMPERATURES_DB_PASSWORD'] = os.environ.get('TEMPERATURES_DB_PASSWORD')
app.config['RASP_ADDRESS'] = os.environ.get('RASP_ADDRESS')
app.config['RASP_PORT'] = os.environ.get('RASP_PORT')



db = SQLAlchemy(app)
migrate = Migrate(app, db)


from app import routes, models
