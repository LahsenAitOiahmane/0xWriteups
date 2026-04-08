from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
import random
import string
from werkzeug.security import generate_password_hash

db = SQLAlchemy()
DB_NAME = "database.db"

def create_random_string(length):
    letters = string.ascii_letters + string.digits
    return "".join(random.choice(letters) for i in range(length))

def create_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = create_random_string(16).encode("utf-8").hex()
    app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{DB_NAME}"
    db.init_app(app)
    
    from .views import views
    from .auth import auth

    app.register_blueprint(views,url_prefix="/")
    app.register_blueprint(auth,url_prefix="/")

    from .models import User , Verification , Validlinks
    
    with app.app_context():
        db.create_all()
    
    login_manager = LoginManager()
    login_manager.login_view = "auth.login"
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(id):
        return User.query.get(int(id))

    with app.app_context():
        if not User.query.filter_by(username="admin").first():
            admin_user = User(email=str(create_random_string(8).encode("utf-8").hex()) + "@master.guild", username="admin", password=generate_password_hash(create_random_string(8).encode("utf-8").hex()))
            db.session.add(admin_user)
            db.session.commit()

    return app