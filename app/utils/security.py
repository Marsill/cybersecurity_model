from functools import wraps
from datetime import datetime, time
from flask import request, jsonify
from flask_jwt_extended import get_jwt_identity, verify_jwt_in_request
from app.models import User, Role, Permission


def get_current_user():
	try:
		verify_jwt_in_request(optional=True)
		identity = get_jwt_identity()
		if not identity:
			return None
		return User.query.get(identity)
	except Exception:
		return None

def role_required(role_name):
	def decorator(fn):
		@wraps(fn)
		def wrapper(*args, **kwargs):
			user = get_current_user()
			if not user or not user.role or user.role.name != role_name:
				return jsonify({"msg": "Forbidden - role required"}), 403
			return fn(*args, **kwargs)
		return wrapper
	return decorator

def permission_required(permission_name):
	def decorator(fn):
		@wraps(fn)
		def wrapper(*args, **kwargs):
			user = get_current_user()
			if not user:
				return jsonify({"msg": "Authentication required"}), 401
			perms = [p.name for p in (user.role.permissions or [])]
			if permission_name not in perms:
				return jsonify({"msg": "Forbidden - permission required"}), 403
			return fn(*args, **kwargs)
		return wrapper
	return decorator

def sensitivity_required(min_label):
	order = {"Public": 0, "Internal": 1, "Confidential": 2}
	def decorator(fn):
		@wraps(fn)
		def wrapper(*args, **kwargs):
			user = get_current_user()
			if not user:
				return jsonify({"msg": "Authentication required"}), 401
			user_level = order.get(user.sensitivity or "Public", 0)
			required_level = order.get(min_label, 0)
			if user_level < required_level:
				return jsonify({"msg": "Forbidden - sensitivity level too low"}), 403
			return fn(*args, **kwargs)
		return wrapper
	return decorator

def time_rule(earliest: time, latest: time):
	def decorator(fn):
		@wraps(fn)
		def wrapper(*args, **kwargs):
			now = datetime.utcnow().time()
			if not (earliest <= now <= latest):
				return jsonify({"msg": "Access disallowed by time-based rule"}), 403
			return fn(*args, **kwargs)
		return wrapper
	return decorator

