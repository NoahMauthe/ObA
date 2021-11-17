import fnmatch
import logging
import os

import database
from API.Objects import App


def store_apk_info(sha256, directory):
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
