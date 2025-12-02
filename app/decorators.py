from functools import wraps
from flask_jwt_extended import get_jwt_identity, jwt_required
from app.models import User

def role_required(role_name):
    def wrapper(fn):
        @wraps(fn)
        @jwt_required()
        def decorator(*args, **kwargs):
            user_id = get_jwt_identity()
            user = User.query.get(user_id)
            if not user or user.role.name != role_name:
                return {"msg": "Access denied"}, 403
            return fn(*args, **kwargs)
        return decorator
    return wrapper
