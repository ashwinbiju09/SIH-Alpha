from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from flask_migrate import Migrate

UPLOAD_FOLDER = 'E:/SIH/media/Documents'
ALLOWED_EXTENSIONS = {'pdf'}

app = Flask(__name__)
app.config['SECRET_KEY'] = '9d8a35ab13e1eaf1d5c6754197be0b67'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///application.db'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
migrate = Migrate(app, db,render_as_batch=True)

login_manager.login_view = 'login'

from application import routes
