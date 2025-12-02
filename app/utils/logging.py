import os
import json
from cryptography.fernet import Fernet
from datetime import datetime
from app.extensions import db
from app.models import AuditLog

# Load or create a file-based encryption key (for demo only). In production store securely.
KEY_PATH = os.path.join(os.path.dirname(__file__), "..", "instance", "log_key.key")

def _ensure_key():
	path = os.path.abspath(KEY_PATH)
	if not os.path.exists(path):
		k = Fernet.generate_key()
		os.makedirs(os.path.dirname(path), exist_ok=True)
		with open(path, "wb") as f:
			f.write(k)
		return k
	with open(path, "rb") as f:
		return f.read()


def _get_fernet():
	key = _ensure_key()
	return Fernet(key)


def log_action(username=None, user_id=None, action=None, ip=None):
	# write to DB audit log
	entry = AuditLog(user_id=user_id, username=username, action=action, ip_address=ip, timestamp=datetime.utcnow())
	db.session.add(entry)
	db.session.commit()

	# also append to encrypted log file
	f = _get_fernet()
	out_path = os.path.join(os.path.dirname(__file__), "..", "instance", "audit.log.enc")
	payload = json.dumps({
		"timestamp": datetime.utcnow().isoformat(),
		"username": username,
		"user_id": user_id,
		"action": action,
		"ip": ip
	}).encode()
	token = f.encrypt(payload)
	with open(out_path, "ab") as fh:
		fh.write(token + b"\n")
