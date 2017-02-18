# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import json
import locale
import logging
import os
import re
import shutil
import socket
import tempfile
import time
import urllib2
import urlparse
import uuid
import zipfile
from datetime import datetime

import requests
from ckanserviceprovider import job, util

if not locale.getlocale()[0]:
    locale.setlocale(locale.LC_ALL, '')

DOWNLOAD_TIMEOUT = 30


class HTTPError(util.JobError):
    """Exception that's raised if a job fails due to an HTTP problem."""

    def __init__(self, message, status_code, request_url, response):
        """Initialise a new HTTPError.
        :param message: A human-readable error message
        :type message: string
        :param status_code: The status code of the errored HTTP response,
            e.g. 500
        :type status_code: int
        :param request_url: The URL that was requested
        :type request_url: string
        :param response: The body of the errored HTTP response as unicode
            (if you have a requests.Response object then response.text will
            give you this)
        :type response: unicode
        """
        super(HTTPError, self).__init__(message)
        self.status_code = status_code
        self.request_url = request_url
        self.response = response

    def as_dict(self):
        """Return a JSON-serializable dictionary representation of this error.
        Suitable for ckanserviceprovider to return to the client site as the
        value for the "error" key in the job dict.
        """
        if self.response and len(self.response) > 200:
            response = self.response[:200] + '...'
        else:
            response = self.response
        return {
            "message": self.message,
            "HTTP status code": self.status_code,
            "Requested URL": self.request_url,
            "Response": response,
        }


def get_url(action, ckan_url):
    """
    Get url for ckan action
    """
    if not urlparse.urlsplit(ckan_url).scheme:
        ckan_url = 'http://' + ckan_url.lstrip('/')
    ckan_url = ckan_url.rstrip('/')
    return '{ckan_url}/api/3/action/{action}'.format(
        ckan_url=ckan_url, action=action)


def check_response(response, request_url, who, good_status=(201, 200), ignore_no_success=False):
    """
    Checks the response and raises exceptions if something went terribly wrong
    :param who: A short name that indicated where the error occurred
                (for example "CKAN")
    :param good_status: Status codes that should not raise an exception
    """
    if not response.status_code:
        raise HTTPError(
            'Spatial Ingestor received an HTTP response with no status code',
            status_code=None, request_url=request_url, response=response.text)

    message = '{who} bad response. Status code: {code} {reason}. At: {url}.'
    try:
        if not response.status_code in good_status:
            json_response = response.json()
            if not ignore_no_success or json_response.get('success'):
                try:
                    message = json_response["error"]["message"]
                except Exception:
                    message = message.format(
                        who=who, code=response.status_code,
                        reason=response.reason, url=request_url)
                raise HTTPError(
                    message, status_code=response.status_code,
                    request_url=request_url, response=response.text)
    except ValueError as err:
        message = message.format(
            who=who, code=response.status_code, reason=response.reason,
            url=request_url, resp=response.text[:200])
        raise HTTPError(
            message, status_code=response.status_code, request_url=request_url,
            response=response.text)


def ckan_command(command_name, data_dict, ckan_dict):
    url = get_url(command_name, ckan_dict['ckan_url'])
    r = requests.post(url,
                      data=json.dumps(data_dict),
                      headers={'Content-Type': 'application/json',
                               'Authorization': ckan_dict['api_key']}
                      )
    check_response(r, url, 'CKAN')

    return r.json()['result']


def validate_input(input):
    # Especially validate metdata which is provided by the user
    if not 'metadata' in input:
        raise util.JobError('Metadata missing')
    if not 'api_key' in input:
        raise util.JobError('CKAN API key missing')

    required_metadata_keys = {
        'resource_id',
        'ckan_url',
        'max_zip_resource_filesize',
        'target_zip_formats'
    }

    missing_metadata_keys = required_metadata_keys - set(input['metadata'].keys())

    if missing_metadata_keys:
        raise util.JobError('Missing metadata keys: {0}'.format(missing_metadata_keys))


def date_str_to_datetime(date_str):
    '''Convert ISO-like formatted datestring to datetime object.

    This function converts ISO format date- and datetime-strings into
    datetime objects.  Times may be specified down to the microsecond.  UTC
    offset or timezone information may **not** be included in the string.

    Note - Although originally documented as parsing ISO date(-times), this
           function doesn't fully adhere to the format.  This function will
           throw a ValueError if the string contains UTC offset information.
           So in that sense, it is less liberal than ISO format.  On the
           other hand, it is more liberal of the accepted delimiters between
           the values in the string.  Also, it allows microsecond precision,
           despite that not being part of the ISO format.
    '''

    time_tuple = re.split('[^\d]+', date_str, maxsplit=5)

    # Extract seconds and microseconds
    if len(time_tuple) >= 6:
        m = re.match('(?P<seconds>\d{2})(\.(?P<microseconds>\d{6}))?$',
                     time_tuple[5])
        if not m:
            raise ValueError('Unable to parse %s as seconds.microseconds' %
                             time_tuple[5])
        seconds = int(m.groupdict().get('seconds'))
        microseconds = int(m.groupdict(0).get('microseconds'))
        time_tuple = time_tuple[:5] + [seconds, microseconds]

    return datetime(*map(int, time_tuple))


def get_zip_input_format(resource):
    check_string = resource.get('__extras', {}).get('format',
                                                    resource.get('format', resource.get('url', ''))).upper()
    if check_string.endswith("ZIP"):
        return 'ZIP'
    else:
        return None


def is_zip_resource(resource):
    # Only ingest if the right format
    return get_zip_input_format(resource) is not None


# Expands and breaks up a zip file pointed to by the url.
# - Nested Zip files are not immediately expanded. They are saved as zipped resources, with the zip_extract
#   flag set, causing a recursion on the CKAN application level.
# - Sub directories are re-zipped _if_ they contain one or more interesting files/sub-directories
#   and are in a directory with at least one other interesting file/sub-directory
# - Individual, interesting files are moved to the target directory, as needed for upload.
def zip_expand(resource, data, logger):
    def interesting_or_directory(file_name):
        return any([file_name.lower().endswith("." + x.lower()) for x in data['target_zip_formats']] + [
            file_name.endswith("/")])

    def zip_dir(path, zip_handle):
        for root, dirs, files in os.walk(path):
            for f_name in files:
                full_path = os.path.join(root, f_name)
                zip_handle.write(full_path, full_path.replace(path.lstrip('\/'), '').lstrip('\/'))

    def num_interesting_in_dir(dir):
        res = 0
        for root, dirs, files in os.walk(dir):
            for f_name in files:
                if interesting_or_directory(f_name):
                    res += 1

        return res

    def process_contents(dir, target_dir, prefix):
        for root, dirs, files in os.walk(dir):
            num_interest_in_level = 0
            for f_name in files:
                num_interest_in_level += 1
                new_name = prefix + '_' + f_name
                logger.info("Renaming {0} to {1}".format(f_name, new_name))
                try:
                    shutil.move(os.path.join(dir, f_name), os.path.join(target_dir, new_name))
                except:
                    raise util.JobError("Failed to move file {0} to {1}".format(f_name, new_name))
            for sub_dir in dirs:
                if num_interesting_in_dir(os.path.join(root, sub_dir)) > 0:
                    num_interest_in_level += 1
            for sub_dir in dirs:
                if num_interesting_in_dir(os.path.join(root, sub_dir)) > 1 and num_interest_in_level > 1:
                    new_name = prefix + '_' + sub_dir + '.zip'
                    logger.info("{0} is a non-trivial sub-directory; zipping up as {1}".format(sub_dir, new_name))

                    try:
                        zip_file = zipfile.ZipFile(os.path.join(target_dir, new_name), 'w',
                                                   zipfile.ZIP_DEFLATED)
                        zip_dir(os.path.join(root, sub_dir), zip_file)
                        zip_file.close()
                    except:
                        raise util.JobError("Failed to zip up directory {0}".format(sub_dir))

                    logger.info("Successfully zipped up sub-directory {0}".format(sub_dir))
                elif num_interesting_in_dir(os.path.join(root, sub_dir)) > 0:
                    logger.info("{0} is a trivial sub-directory; recursing past...".format(sub_dir))

                    # The directory only contains one sub_directory with interesting files. There is no
                    # point compressing this sub directory, so we recurse down into it
                    process_contents(os.path.join(root, sub_dir), target_dir, prefix + '_' + sub_dir)

                try:
                    shutil.rmtree(os.path.join(root, sub_dir))
                except:
                    raise util.JobError("Failed to remove directory {0}".format(sub_dir))

            # Break after one iteration, as any sub-directories will be either Zipped (and recursed into on
            # the application level) or directly recursed into
            break

    tempdir = tempfile.mkdtemp()

    try:
        tempname = '{0}.{1}'.format(uuid.uuid1(), 'zip')

        logger.info('Fetching from: {0}'.format(resource.get('url')))

        try:
            request = urllib2.Request(resource.get('url'))

            if resource.get('url_type') == 'upload':
                request.add_header('Authorization', data['api_key'])

            response = urllib2.urlopen(request, timeout=DOWNLOAD_TIMEOUT)
        except urllib2.HTTPError as e:
            raise HTTPError(
                "SpatialIngestor received a bad HTTP response when trying to download "
                "the data file", status_code=e.code,
                request_url=resource.get('url'), response=e.read())

        except urllib2.URLError as e:
            if isinstance(e.reason, socket.timeout):
                raise util.JobError('Connection timed out after %ss' %
                                    DOWNLOAD_TIMEOUT)
            else:
                raise HTTPError(
                    message=str(e.reason), status_code=None,
                    request_url=resource.get('url'), response=None)

        tempfilepath = os.path.join(tempdir, tempname)

        try:
            with open(tempfilepath, 'wb') as out_file:
                out_file.write(response.read())
        except Exception, e:
            raise util.JobError(
                "Failed to copy file to {0} with exception {1}".format(os.path.join(tempdir, tempname), str(e)))

        try:
            z = zipfile.ZipFile(tempfilepath)
        except zipfile.BadZipfile:
            raise util.JobError("{0} is not a valid zip file".format(resource['url']))

        try:
            file_counter = 0
            for entry in z.infolist():
                if interesting_or_directory(entry.filename) and entry.file_size <= data['max_zip_resource_filesize']:
                    z.extract(entry, path=tempdir)
                    file_counter += 1

            try:
                os.remove(tempfilepath)
            except:
                raise util.JobError("Failed to remove temporary zip file".format(tempfilepath))

            logger.info("Successfully extracted {0} files from {1}".format(file_counter, tempfile))
            logger.info("Processing extracted files")

            process_contents(tempdir, tempdir, resource['name'].split('.', 1)[0])
        except Exception:
            raise util.JobError("Failed to extract files from {0}".format(resource['url']))
    except Exception, e:
        try:
            shutil.rmtree(tempdir)
        except:
            pass
        raise

    return tempdir


def ingest_dir(resource, data, logger):
    for file_name in os.listdir(data['resource_dir']):
        new_res = {'package_id': resource['package_id'],
                   'url': 'http://blank',
                   'last_modified': datetime.utcnow().isoformat(),
                   'zip_child_of': resource['id'],
                   'parent_resource_url': resource['url']}

        file_path = os.path.join(data['resource_dir'], file_name)
        new_res['name'] = file_name.split('.', 1)[0]
        new_res['format'] = file_name.split('.')[-1].lower()
        if is_zip_resource(new_res):
            new_res['zip_extract'] = True

        logger.info("Creating new resource {0}".format(new_res['name']))

        try:
            url = get_url('resource_create', data['ckan_url'])
            r = requests.post(url,
                              data=json.dumps(new_res),
                              headers={'Content-Type': 'application/json',
                                       'Authorization': data['api_key']},
                              files=[('upload', open(file_path, 'rb'))])
            check_response(r, url, 'CKAN')
            new_res = r.json()['result']

            logger.info("Successfully created resource {0}".format(new_res['name']))

            count_offset = 0
            for service in ['Datapusher', 'Zipextractor']:
                lservicestr = service.lower()
                logger.info("Checking if {0} has been triggered for resource {1}".format(lservicestr, new_res['name']))
                service_working = True
                service_present = True
                poll_time = 10
                count = 0 - count_offset
                count_offset = 1 if count_offset == 0 else count_offset
                last_update_checked = False
                while service_working and service_present:
                    count += 1
                    if count % poll_time == 0:
                        try:
                            service_task = ckan_command('task_status_show', {
                                'entity_id': new_res['id'],
                                'task_type': lservicestr,
                                'key': lservicestr}, data)
                            service_working = service_task.get('state', '') in ['pending', 'submitting']
                            if service_working and not last_update_checked:
                                logger.info(
                                    "{0} processing resource, will wait until it completes before continuing...".format(
                                        service))
                                if 'last_updated' not in service_task or (datetime.utcnow() - date_str_to_datetime(
                                        service_task['last_updated'])).total_seconds() > 3600:
                                    logger.info("{0} is in a stale pending state, re-submitting job...".format(service))
                                    ckan_command('{0}_submit'.format(lservicestr), {
                                        'resource_id': new_res['id']
                                    }, data)
                                last_update_checked = True
                        except:
                            service_present = False

                    time.sleep(1)
                else:
                    if service_present:
                        logger.info(
                            "{0} has finished pushing resource, continuing with Zip extraction...".format(service))


        except:
            logger.info("Failed to create child resource {0}, continuing...".format(new_res['name']))


@job.async
def zip_extract(task_id, input):
    handler = util.StoringHandler(task_id, input)
    logger = logging.getLogger(task_id)
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)

    validate_input(input)

    data = input['metadata']
    data['api_key'] = input['api_key']

    logger.info('Retrieving resource information')

    resource = ckan_command('resource_show', {'id': data['resource_id']}, data)

    logger.info('Expanding Zip resource {0}'.format(resource['name']))

    data['resource_dir'] = zip_expand(resource, data, logger)

    try:
        logger.info("Creating resource for sub-files of {0}".format(resource['id']))

        ingest_dir(resource, data, logger)

        logger.info("Successfully created all child resources of {0}".format(resource['id']))
    finally:
        try:
            shutil.rmtree(data['resource_dir'])
        except:
            pass
