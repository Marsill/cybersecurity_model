import os
import shutil
from datetime import datetime
from cryptography.fernet import Fernet


KEY_PATH = os.path.join(os.path.dirname(__file__), '..', 'instance', 'backup_key.key')


def _ensure_key():
    path = os.path.abspath(KEY_PATH)
    if not os.path.exists(path):
        k = Fernet.generate_key()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'wb') as f:
            f.write(k)
        return k
    with open(path, 'rb') as f:
        return f.read()


def create_backup(db_path='data.db', out_dir=None):
    if out_dir is None:
        out_dir = os.path.join(os.path.dirname(__file__), '..', 'backups')
    os.makedirs(out_dir, exist_ok=True)
    ts = datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
    tmp_copy = os.path.join(out_dir, f'db_{ts}.sqlite')
    shutil.copy2(db_path, tmp_copy)
    # encrypt
    key = _ensure_key()
    f = Fernet(key)
    with open(tmp_copy, 'rb') as fh:
        data = fh.read()
    enc = f.encrypt(data)
    out_path = os.path.join(out_dir, f'db_{ts}.sqlite.enc')
    with open(out_path, 'wb') as fh:
        fh.write(enc)
    os.remove(tmp_copy)
    return out_path
