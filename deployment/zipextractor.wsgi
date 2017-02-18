import os
import sys
import hashlib

activate_this = os.path.join('/usr/lib/ckan/zipextractor/bin/activate_this.py')
execfile(activate_this, dict(__file__=activate_this))

import ckanserviceprovider.web as web
os.environ['JOB_CONFIG'] = '/etc/ckan/zipextractor/zipextractor_settings.py'
web.init()

import zipextractor.jobs as jobs

application = web.app