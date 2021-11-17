import logging
import os
import shutil

from utility.convenience import VERBOSE

logger = logging.getLogger('Cleaner')


def google_play_remnants(sha256, directory):
    directory = os.path.join(os.path.abspath(directory), 'apk')
    if not os.path.isdir(directory):
        logger.info(f'Apk directory for {sha256} is not a directory: {directory}')
    else:
        logger.log(VERBOSE, f'Deleting {directory} created by {sha256}')
        shutil.rmtree(directory, ignore_errors=True)


def androzoo_remnants(sha256, directory):
    directory = os.path.abspath(directory)
    if directory.startswith('/tmp/'):
        logger.log(VERBOSE, f'Deleting {directory} created by {sha256}')
        shutil.rmtree(directory, ignore_errors=True)
