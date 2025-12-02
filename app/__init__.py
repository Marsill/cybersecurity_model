from flask import Flask
from flask_jwt_extended import JWTManager
from app.extensions import db, migrate
from app.models import create_default_roles
import os


def create_app():
    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URI', 'sqlite:///data.db')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'change-me')

    db.init_app(app)
    migrate.init_app(app, db)
    JWTManager(app)

    with app.app_context():
        db.create_all()
        create_default_roles()

    from app.routes.auth_routes import bp as auth_bp
    app.register_blueprint(auth_bp, url_prefix='/auth')
    from app.routes.access_control_routes import bp as access_bp
    app.register_blueprint(access_bp, url_prefix='/access')

    return app
