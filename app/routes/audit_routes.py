from flask import Blueprint, jsonify
from app.models import AuditLog
from app.utils.logging import _get_fernet
from app.utils.security import role_required
import os

bp = Blueprint('audit', __name__)

@bp.route('/logs/db')
@role_required('Admin')
def logs_db():
	entries = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(200).all()
	out = []
	for e in entries:
		out.append({
			'id': e.id,
			'username': e.username,
			'user_id': e.user_id,
			'action': e.action,
			'ip': e.ip_address,
			'timestamp': e.timestamp.isoformat() if e.timestamp else None
		})
	return jsonify(out)

@bp.route('/logs/file')
@role_required('Admin')
def logs_file():
	path = os.path.join(os.path.dirname(__file__), '..', 'instance', 'audit.log.enc')
	if not os.path.exists(path):
		return jsonify({'msg': 'no file'}), 404
	f = _get_fernet()
	out = []
	with open(path, 'rb') as fh:
		for line in fh:
			line = line.strip()
			if not line:
				continue
			try:
				dec = f.decrypt(line)
				out.append(dec.decode())
			except Exception:
				out.append(None)
	return jsonify(out)

