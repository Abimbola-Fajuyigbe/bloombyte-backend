from flask import Blueprint, request, jsonify
from app.extensions import db
from app.models import User
from flask_jwt_extended import create_access_token, jwt_required
from itsdangerous import URLSafeTimedSerializer, SignatureExpired

auth = Blueprint('auth', __name__)

s = URLSafeTimedSerializer("secret-reset-key")

# ---------- SIGN UP ----------
@auth.route('/signup', methods=['POST'])
def signup():
    if not request.is_json:
        return jsonify({'error': 'Content-Type must be application/json'}), 415
    
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    if not all ([username, email, password]):
        return jsonify({'error': 'Username, email, and password are required'}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({'error': 'Email already registered'}), 400

    new_user = User(username=username, email=email)
    new_user.set_password(password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'User registered successfully!'}), 201


# ---------- LOGIN ----------
@auth.route('/login', methods=['POST'])

def login():
    if not request.is_json:
        return jsonify({'error': 'Content-Type must be application/json'}), 415
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    if not all ([email, password]):
        return jsonify({'error': 'Email and password are required'}), 400

    user = User.query.filter_by(email=email).first()
    if not user or not user.check_password(password):
        return jsonify({'error': 'Invalid credentials'}), 401

    token = create_access_token(identity=user.id)
    return jsonify({'message': 'Login successful!', 'access_token': token}), 200


# ---------- FORGOT PASSWORD ----------
@auth.route('/forgot-password', methods=['POST'])
def forgot_password():
    if not request.is_json:
        return jsonify({'error': 'Content-Type must be application/json'}), 415
    data = request.get_json()
    email = data.get('email')
    if not email:
        return jsonify({'error': 'Email is required'}), 400
    
    reset_url = data.get('reset_url')
    if not reset_url:
        return jsonify({'error': 'reset-url is required'})

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'error': 'Email not found'}), 404

    token = s.dumps(email, salt='password-reset-salt')
    reset_link = f"{reset_url}?token={token}"

    # In a real app, send via email. For now, return as JSON:
    return jsonify({'reset_link': reset_link}), 200


# ---------- RESET PASSWORD ----------
@auth.route('/reset-password/<token>', methods=['POST'])
def reset_password(token):
    try:
        email = s.loads(token, salt='password-reset-salt', max_age=3600)
    except SignatureExpired:
        return jsonify({'error': 'Token expired'}), 400
    if not request.is_json:
        return jsonify({'error': 'Content-Type must be application/json'}), 415

    data = request.get_json()
    new_password = data.get('new_password')

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'error': 'User not found'}), 404

    user.set_password(new_password)
    db.session.commit()

    return jsonify({'message': 'Password reset successful!'}), 200
