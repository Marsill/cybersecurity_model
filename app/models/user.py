from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

# Use the single SQLAlchemy instance from extensions to avoid multiple-db instances
from app.extensions import db

# Association table for many-to-many between roles and permissions
role_permissions = db.Table(
    'role_permissions',
    db.Column('role_id', db.Integer, db.ForeignKey('roles.id'), primary_key=True),
    db.Column('permission_id', db.Integer, db.ForeignKey('permissions.id'), primary_key=True)
)


# Role model for RBAC
class Role(db.Model):
    __tablename__ = "roles"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.String(255))

    users = db.relationship("User", backref="role", lazy=True)
    permissions = db.relationship('Permission', secondary=role_permissions, back_populates='roles')


# Permission model
class Permission(db.Model):
    __tablename__ = 'permissions'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.String(255))

    roles = db.relationship('Role', secondary=role_permissions, back_populates='permissions')


# User model
class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(128), unique=True, nullable=False)
    password_hash = db.Column(db.Text, nullable=False)  # TEXT to avoid length issues
    role_id = db.Column(db.Integer, db.ForeignKey("roles.id"), nullable=False)
    # Account security fields
    failed_login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)
    email_verified = db.Column(db.Boolean, default=False)
    otp_secret = db.Column(db.String(32), nullable=True)

    # Optional attributes for ABAC
    department = db.Column(db.String(50))
    employment_status = db.Column(db.String(50))  
    location = db.Column(db.String(50))

    # Sensitivity label for MAC
    sensitivity = db.Column(db.String(50), default="Public") 

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Password hashing
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def lock_account(self, until_datetime):
        self.locked_until = until_datetime
        self.failed_login_attempts = 0
        db.session.add(self)
        db.session.commit()

    def increment_failed_attempts(self):
        self.failed_login_attempts = (self.failed_login_attempts or 0) + 1
        db.session.add(self)
        db.session.commit()


class AuditLog(db.Model):
    __tablename__ = 'audit_logs'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    username = db.Column(db.String(128), nullable=True)
    action = db.Column(db.String(256))
    ip_address = db.Column(db.String(45))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref='audit_logs')


def create_default_roles():
    roles = ["Admin", "Manager", "Employee"]
    for r in roles:
        if not Role.query.filter_by(name=r).first():
            role = Role(name=r)
            db.session.add(role)
    db.session.commit()
