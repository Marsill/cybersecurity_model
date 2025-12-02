from flask import Blueprint, request, jsonify, current_app
from datetime import datetime, timedelta
import re

from app.extensions import db
from app.models import User, Role
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity

from app.utils.otp import generate_otp_secret, verify_totp
from app.utils.logging import log_action

bp = Blueprint('auth', __name__)

def _valid_password(pw: str) -> bool:
    if not pw or len(pw) < 8:
        return False
    if not re.search(r"[a-z]", pw):
        return False
    if not re.search(r"[A-Z]", pw):
        return False
    if not re.search(r"\d", pw):
        return False
    return True

@bp.route('/register', methods=['POST'])
def register():
    data = request.get_json() or {}
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    if not username or not email or not password:
        return jsonify({'msg': 'username, email and password required'}), 400

    if not _valid_password(password):
        return jsonify({'msg': 'Password does not meet policy'}), 400

    if User.query.filter((User.username == username) | (User.email == email)).first():
        return jsonify({'msg': 'User exists'}), 400

    role = Role.query.filter_by(name='Employee').first()
    if not role:
        role = Role(name='Employee')
        db.session.add(role)
        db.session.commit()

    user = User(username=username, email=email, role_id=role.id)
    user.set_password(password)
    user.otp_secret = generate_otp_secret()
    db.session.add(user)
    db.session.commit()

    log_action(username=username, user_id=user.id, action='register', ip=request.remote_addr)
    return jsonify({'msg': 'registered', 'user_id': user.id}), 201

@bp.route('/register-with-captcha', methods=['POST'])
def register_with_captcha():
    data = request.get_json() or {}
    token = data.get('recaptcha_token')
    if not token:
        return jsonify({'msg': 'recaptcha token required'}), 400
    return register()

@bp.route('/login', methods=['POST'])
def login():
    data = request.get_json() or {}
    username = data.get('username')
    password = data.get('password')
    otp = data.get('otp')

    user = User.query.filter((User.username == username) | (User.email == username)).first()
    if not user:
        return jsonify({'msg': 'Invalid credentials'}), 401

    if user.locked_until and user.locked_until > datetime.utcnow():
        return jsonify({'msg': 'Account locked'}), 403

    if not user.check_password(password):
        user.increment_failed_attempts()
        if user.failed_login_attempts >= 5:
            user.lock_account(datetime.utcnow() + timedelta(minutes=15))
            return jsonify({'msg': 'Account locked due to too many attempts'}), 403
        return jsonify({'msg': 'Invalid credentials'}), 401

    if user.otp_secret:
        if not otp or not verify_totp(user.otp_secret, str(otp)):
            return jsonify({'msg': 'OTP required or invalid'}), 401

    user.failed_login_attempts = 0
    db.session.add(user)
    db.session.commit()

    access = create_access_token(identity=str(user.id))
    log_action(username=user.username, user_id=user.id, action='login', ip=request.remote_addr)
    return jsonify({'access_token': access}), 200

@bp.route('/me', methods=['GET'])
@jwt_required()
def me():
    uid = get_jwt_identity()
    user = User.query.get(uid)
    if not user:
        return jsonify({'msg': 'Not found'}), 404
    return jsonify({'id': user.id, 'username': user.username, 'email': user.email, 'role': user.role.name}), 200

@bp.route('/enable-otp', methods=['POST'])
@jwt_required()
def enable_otp():
    uid = get_jwt_identity()
    user = User.query.get(uid)
    if not user:
        return jsonify({'msg': 'Not found'}), 404

    if not user.otp_secret:
        user.otp_secret = generate_otp_secret()

    db.session.add(user)
    db.session.commit()

    uri = f"otpauth://totp/CyberSecurityModel:{user.username}?secret={user.otp_secret}&issuer=CyberSecurityModel"
    return jsonify({'otp_uri': uri}), 200

@bp.route('/assign-role', methods=['POST'])
@jwt_required()
def assign_role():
    data = request.get_json() or {}
    target_id = data.get('user_id')
    role_name = data.get('role')

    if not target_id or not role_name:
        return jsonify({'msg': 'user_id and role required'}), 400

    requester = User.query.get(get_jwt_identity())
    if not requester or requester.role.name != 'Admin':
        return jsonify({'msg': 'Forbidden'}), 403

    user = User.query.get(target_id)
    if not user:
        return jsonify({'msg': 'user not found'}), 404

    role = Role.query.filter_by(name=role_name).first()
    if not role:
        role = Role(name=role_name)
        db.session.add(role)
        db.session.commit()

    user.role_id = role.id
    db.session.add(user)
    db.session.commit()

    log_action(username=requester.username, user_id=requester.id, action=f'assign_role:{role_name} to {user.username}', ip=request.remote_addr)
    return jsonify({'msg': 'role assigned'}), 200

@bp.route('/change-password', methods=['POST'])
@jwt_required()
def change_password():
    data = request.get_json() or {}
    current_pw = data.get('current_password')
    new_pw = data.get('new_password')

    if not current_pw or not new_pw:
        return jsonify({'msg': 'current_password and new_password required'}), 400

    if not _valid_password(new_pw):
        return jsonify({'msg': 'New password does not meet policy'}), 400

    uid = get_jwt_identity()
    user = User.query.get(uid)
    if not user:
        return jsonify({'msg': 'User not found'}), 404

    if not user.check_password(current_pw):
        user.increment_failed_attempts()
        return jsonify({'msg': 'Current password is incorrect'}), 401

    user.set_password(new_pw)
    user.failed_login_attempts = 0
    user.locked_until = None
    db.session.add(user)
    db.session.commit()

    log_action(username=user.username, user_id=user.id, action='change_password', ip=request.remote_addr)
    return jsonify({'msg': 'password changed'}), 200
