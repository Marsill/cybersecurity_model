from flask import Blueprint, jsonify
from datetime import time
from app.utils.security import role_required, permission_required, sensitivity_required, time_rule

bp = Blueprint('access', __name__)


@bp.route('/protected/admin')
@role_required('Admin')
def admin_only():
	return jsonify({'msg': 'admin area'})


@bp.route('/protected/finance')
@permission_required('view_financials')
def view_financials():
	return jsonify({'msg': 'financials'})


@bp.route('/protected/confidential')
@sensitivity_required('Confidential')
def confidential():
	return jsonify({'msg': 'confidential data'})


@bp.route('/protected/time')
@time_rule(time(8, 0), time(18, 0))
def within_hours():
	return jsonify({'msg': 'within allowed hours'})
