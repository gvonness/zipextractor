import uuid

DEBUG = False
TESTING = False
SECRET_KEY = str(uuid.uuid4())
USERNAME = str(uuid.uuid4())
PASSWORD = str(uuid.uuid4())

NAME = 'zipextractor'

# database

SQLALCHEMY_DATABASE_URI = 'sqlite:////tmp/zipextractor_job_store.db'

# webserver host and port

HOST = '0.0.0.0'
PORT = 8822

# logging

#FROM_EMAIL = 'server-error@example.com'
#ADMINS = ['yourname@example.com']  # where to send emails

LOG_FILE = '/tmp/zipextractor_service.log'
STDERR = True