import fnmatch
import logging
import os
import shlex
from subprocess import check_output, CalledProcessError

import database
from API.Objects import App


def store_gplay_apk_info(sha256, directory):
    logger = logging.getLogger('protobuf')
    try:
        pain = os.path.join(directory, fnmatch.filter(os.listdir(directory), '*.pain')[0])
    except IndexError:
        logger.error(f'Did not find .pain file in {directory}')
        return
    try:
        size = os.path.getsize(pain)
        app = App.from_file(pain)
    except Exception as error:
        logger.error(f'Protobuf could not handle {sha256}: {repr(error)}')
        return
    database.store_google_play_app(sha256, app.upload_date(), size, app.package_name(), app.version_code(),
                                   app.developer(), app.category_name(), app.average_rating(), app.downloads(),
                                   True if app.contains_ads() else False)


def store_fdroid_apk_info(sha256, directory):
    logger = logging.getLogger('fdroid')
    try:
        with open(os.path.join(directory, sha256), 'r') as file:
            package_name, version = file.read().strip().split('(')
            version = version.split(')')[0]
        database.store_fdroid_app(sha256, package_name, version)
    except ValueError:
        logger.error(f'Failed to get name and version for {sha256}')
        database.store_fdroid_hash(sha256)

