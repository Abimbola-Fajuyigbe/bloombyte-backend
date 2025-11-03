from flask import Flask
from app.extensions import db, bcrypt, jwt
from app.routes.auth_routes import auth

def create_app():
    app = Flask(__name__)

    app.config['SECRET_KEY'] = 'super-secret-key'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///bloombyte.db'
    app.config['JWT_SECRET_KEY'] = 'bloombyte-jwt-secret'

    db.init_app(app)
    bcrypt.init_app(app)
    jwt.init_app(app)
    
    app.register_blueprint(auth, url_prefix='/auth')

    with app.app_context():
        db.create_all()

    return app
