import os
from events.collection import Collection
from requests.auth import HTTPBasicAuth
from ecdsa import SigningKey

# List of collections to serve
collections = {'1': Collection('https://example.com', HTTPBasicAuth('username', 'password'))}

# Http port
port = 8000

# Host to serve on
host = '127.0.0.1'

# Format for human readable dates
time_format = '%Y-%m-%d %H:%M:%S'

# Address to send emails from
email_from = 'events@example.com'

# Smtp server address
smtp_server = 'smtp.example.com'

# Smtp server port
smtp_port = 587

# Secret key, used for csrf tokens
secret_key = os.urandom(32)

# Number of events to show in the homepage
recent_count = 20

# External url to this server
external_url = 'http://127.0.0.1:8000'

# Signing key for tokens
# Generate with:
# from ecdsa import SigningKey
# SigningKey.generate().to_pem()

signing_key = SigningKey.from_pem('-----BEGIN EC PRIVATE KEY-----\ ...')

# Method to determine whether a request has admin access
# (check for credentials, or headers that could be set by a proxy server)
def is_admin(request):
    return False

