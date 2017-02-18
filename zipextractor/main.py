import argparse
import os

from ckanserviceprovider import web

from zipextractor import jobs

# check whether jobs have been imported properly
assert jobs.spatial_ingest
assert jobs.spatial_purge


def serve():
    web.init()
    web.app.run(web.app.config.get('HOST'), web.app.config.get('PORT'))


def serve_test():
    web.init()
    return web.app.test_client()


def main():
    argparser = argparse.ArgumentParser(
        description='Service that allows for the automatic splitting out of resources from an uploaded Zip file.',
        epilog='''"Service that allows for the automatic splitting out of resources from an uploaded Zip file."''')

    argparser.add_argument('config', metavar='CONFIG', type=file,
                           help='configuration file')
    args = argparser.parse_args()

    os.environ['JOB_CONFIG'] = os.path.abspath(args.config.name)
    serve()


if __name__ == '__main__':
    main()