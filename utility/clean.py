import logging
import os
import shutil

logger = logging.getLogger('Cleaner')


def google_play_remnants(sha256, directory):
    directory = os.path.join(os.path.abspath(directory), 'apk')
    if not os.path.isdir(directory):
        logger.debug(f'Apk directory for {sha256} is not a directory: {directory}')
    else:
        logger.debug(f'Deleting {directory} created by {sha256}')
        shutil.rmtree(directory, ignore_errors=True)


def androzoo_remnants(sha256, directory):
    directory = os.path.abspath(directory)
    if directory.startswith('/tmp/'):
        logger.debug(f'Deleting {directory} created by {sha256}')
        shutil.rmtree(directory, ignore_errors=True)


def fdroid_remnants(sha256, directory):
    try:
        file = os.path.join(directory, sha256)
        os.remove(file)
    except Exception as e:
        logger.error(f'Failed to delete F-Droid remnants for {sha256}: {repr(e)}')