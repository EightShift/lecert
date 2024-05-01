# lecert

Lecert is a Python module for obtaining SSL certificates from Let\'s Encrypt for self-service projects.

## Installation
```
pip install lecert
```

## Usage
To obtain a new certificate, simply call the get_cert function:
```
import lecert

certs_dir = './certs'
email = 'example@domain.com
domains = ['example.com', 'example.org']

result = lecert.get_cert(certs_dir, email, domains)
```

The get_cert function will create a private key and CSR, issue a certificate from Let's Encrypt, and save the certificate and private key to the specified directory.

To make the contents of the ACME challenge directory available, you can add the following route to your web application:

```
from flask import Flask, send_file, abort

app = Flask(__name__)

@app.route('/.well-known/acme-challenge/<challenge_token>')
def acme_challenge(challenge_token):
	validation_path = lecert.get_validation_path(certs_dir, challenge_token)
	if not validation_path:
		return abort(404)
	
	return send_file(validation_path)
```

## Options
The get_cert function takes the following optional arguments:
- www: Whether to include the www subdomain in the certificate.
- cert_lifetime: The lifetime of the certificate in days.
- timeout: The timeout in seconds for the certificate issuance process.
- force: Whether to force the certificate issuance even if the current certificate is still valid.
- privkey_file_name: The name of the private key file.
- cert_file_name: The name of the certificate file.
- backup_time_format: Time format for backup directories.


## Example
The following example shows how to use LeCert to obtain and maintain SSL certificates for a small web application:
```
import lecert
import schedule
import time

certs_dir = './certs'
domains = ['example.com', 'example.org']
email = 'example@domain.com

def get_cert_job():
	result = lecert.get_cert(certs_dir, email, domains)
	if result:
		print('Certificate obtained successfully.')
	else:
		print('Error obtaining certificate.')

# Schedule the certificate renewal job to run everyday
schedule.every().day.do(get_cert_job)

# Start the scheduler
while True:
	schedule.run_pending()
	time.sleep(1)
```
This example will automatically obtain a new certificate everyday and save it to the certs directory. The contents of the ACME challenge directory will be made available at /.well-known/acme-challenge/<challenge_token>.

## License
This project is licensed under the MIT License