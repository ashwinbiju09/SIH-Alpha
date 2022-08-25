import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from flask_migrate import Migrate
from flask_mail import Mail
from flask_wtf.csrf import CSRFProtect


app = Flask(__name__)
app.config['SECRET_KEY'] = '9d8a35ab13e1eaf1d5c6754197be0b67'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///application.db'


db = SQLAlchemy(app)
bcrypt_1 = Bcrypt(app)
login_manager = LoginManager(app)
migrate = Migrate(app, db,render_as_batch=True)
csrf =  CSRFProtect(app)

login_manager.login_view = 'login'

app.config['MAIL_SERVER'] = 'smtp.googlemail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = '20eucs018@skcet.ac.in'
app.config['MAIL_PASSWORD'] = 'Ashwin11@'
app.config['MAIL_USE_SSL'] = False

mail = Mail(app)

app.config['APP_URL'] = 'http://127.0.0.1:5000'

from application import routes
