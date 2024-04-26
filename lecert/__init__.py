import os
from datetime import datetime, timedelta
from contextlib import contextmanager
import shutil

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
import josepy as jose
import OpenSSL

from acme import challenges
from acme import client
from acme import crypto_util
from acme import messages


KEY_SIZE = 2048
DIRECTORY_URL = 'https://acme-v02.api.letsencrypt.org/directory'
ACME_CHALLENGE_DIR_NAME = '__acme-challenge__'



def get_validation_path(certs_dir, challenge_token):
	validation_dir = os.path.join(certs_dir, ACME_CHALLENGE_DIR_NAME, challenge_token)
	if os.path.exists(validation_dir):
		return validation_dir


def _time_to_get_cert(cert_path, cert_lifetime):
	if os.path.exists(cert_path):
		created = os.path.getctime(cert_path)
		if datetime.now() - datetime.fromtimestamp(created) < timedelta(days=cert_lifetime):
			return False
	
	return True


def _backup_saving(file_path, data):
	old_file_path = file_path + '.old'
	if os.path.exists(file_path):
		if os.path.exists(old_file_path):
			os.remove(old_file_path)

		os.rename(file_path, old_file_path)

	try:
		with open(file_path, 'w') as _file:
			_file.write(data)
	except:
		if os.path.exists(old_file_path):
			os.rename(old_file_path, file_path)

		return False
	
	return True


def _select_http01_challb(auths):
	for chall_body in auths.body.challenges:
		if isinstance(chall_body.chall, challenges.HTTP01):
			return chall_body


def _generate_privkey_pem():
	pkey = OpenSSL.crypto.PKey()
	pkey.generate_key(OpenSSL.crypto.TYPE_RSA, KEY_SIZE)
	return OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, pkey)


def _accept_challenges(acme_challenge_dir, client_acme, order):
	# Select HTTP-01 within offered challenges by the CA server
	for challb in [_select_http01_challb(i) for i in order.authorizations]:
		# The certificate is ready to be used in the variable "fullchain_pem".
		response, validation = challb.response_and_validation(client_acme.net.key)

		challenge_token = challb.chall.encode('token')
		challenge_token_path = os.path.join(acme_challenge_dir, challenge_token) # must be available by "/.well-known/acme-challenge/<challenge_token>"
		with open(challenge_token_path, 'w') as challenge_token_file:
			challenge_token_file.write(validation)

		# Let the CA server know that we are ready for the challenge.
		client_acme.answer_challenge(challb, response)


def _save_cert(privkey_path, cert_path, privkey_pem, finalized_order):
	if not _backup_saving(privkey_path, privkey_pem.decode()):  # saving privkey.pem file
		return False

	if not _backup_saving(cert_path, finalized_order.fullchain_pem): # saving cert.pem file
		return False
	
	return True


@contextmanager
def _get_acme_challenge_dir(certs_dir):
	acme_challenge_dir = os.path.join(certs_dir, ACME_CHALLENGE_DIR_NAME)
	try:
		os.makedirs(acme_challenge_dir, exist_ok=True)

		yield acme_challenge_dir
	finally:
		shutil.rmtree(acme_challenge_dir, ignore_errors=True)


@contextmanager
def _get_client_acme(email):
	# Create client_acme and register account and accept TOS
	acc_key = jose.JWKRSA(key=rsa.generate_private_key(public_exponent=65537, key_size=KEY_SIZE, backend=default_backend()))

	net = client.ClientNetwork(acc_key)
	directory = messages.Directory.from_json(net.get(DIRECTORY_URL).json())
	client_acme = client.ClientV2(directory, net)
	regr = client_acme.new_account(messages.NewRegistration.from_data(email=email, terms_of_service_agreed=True))
	try:
		yield client_acme
	finally:
		client_acme.deactivate_registration(regr)



def get_cert(certs_dir, email, domains, www=True, cert_lifetime=30, timeout=150, force=False, privkey_file_name='privkey.pem', cert_file_name='cert.pem'):
	"""Obtains a new certificate from Let's Encrypt.

	Args:
		certs_dir (str): The directory where the certificates are stored.
		email (str): The email address of the account.
		domains (list): The list of domains to include in the certificate.
		www (bool): Whether to include the www subdomain in the certificate.
		cert_lifetime (int): The lifetime of the certificate in days.
		timeout (int): The timeout in seconds for the certificate issuance process.
		force (bool): Whether to force the certificate issuance even if the current certificate is still valid.
		privkey_file_name (str): The name of the private key file.
		cert_file_name (str): The name of the certificate file.

	Returns:
		bool: True if the certificate was obtained successfully, False otherwise.
	"""
	privkey_path = os.path.join(certs_dir, privkey_file_name)
	cert_path = os.path.join(certs_dir, cert_file_name)

	if not force and not _time_to_get_cert(cert_path, cert_lifetime): # force or checking __created__ file
		return

	try:
		with _get_client_acme(email) as client_acme:
			# Create private key
			privkey_pem = _generate_privkey_pem()
			
			if www:
				domains += [f'www.{i}' for i in domains]
			csr_pem = crypto_util.make_csr(privkey_pem, domains)

			# Issue certificate
			order = client_acme.new_order(csr_pem)

			with _get_acme_challenge_dir(certs_dir) as acme_challenge_dir:
				_accept_challenges(acme_challenge_dir, client_acme, order)

				# Wait for challenge status and then issue a certificate.
				finalized_order = client_acme.poll_and_finalize(order, datetime.now() + timedelta(seconds=timeout))

			return _save_cert(privkey_path, cert_path, privkey_pem, finalized_order)
	except:
		return False