import pyotp

def generate_otp_secret():
	return pyotp.random_base32()

def get_totp(secret):
	if not secret:
		return None
	return pyotp.TOTP(secret)

def verify_totp(secret, token):
	totp = get_totp(secret)
	if not totp:
		return False
	return totp.verify(token, valid_window=1)

def provisioning_uri(secret, username, issuer_name="CyberSecurityModel"):
	totp = get_totp(secret)
	return totp.provisioning_uri(name=username, issuer_name=issuer_name)
