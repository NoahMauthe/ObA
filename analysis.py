import logging
import os
import time

import database
from manager import GplayManager, AndrozooManager, FDroidManager
from utility.convenience import VERBOSE, STATUS
from vt_manager import Active


def init_logging(arguments):
    logging.addLevelName(VERBOSE, "VERBOSE")
    logging.addLevelName(STATUS, "STATUS")
    loglevel = logging.INFO
    logging.getLogger('androguard').setLevel(logging.FATAL)
    logging.getLogger('dad').setLevel(logging.FATAL)
    if arguments.loglevel == 'debug':
        loglevel = logging.DEBUG
    elif arguments.loglevel == 'verbose':
        loglevel = VERBOSE
    console_formatter = logging.Formatter(
        '[{levelname:^10}] {{{name:^13}}}\t{message}', style='{')
    console_handler = logging.StreamHandler()
    console_handler.setLevel(loglevel)
    console_handler.setFormatter(console_formatter)
    root = logging.getLogger()
    root.setLevel(logging.NOTSET)
    root.addHandler(console_handler)
    if arguments.logfile:
        file_handler = logging.FileHandler(os.path.abspath(arguments.logfile))
        file_handler.setLevel(loglevel)
        file_handler.setFormatter(
            logging.Formatter('{asctime}\t[{levelname}] {{{name}}}\t{message}',
                              style='{'))
        root.addHandler(file_handler)
    if arguments.db:
        database.db_string = arguments.db
    else:
        database.db_string = 'dbname=malware user=postgres host=0.0.0.0'
    logging.getLogger('postgreSQL').info(
        f'Using dbstring "{database.db_string}".')


def androzoo_analysis(args):
    manager = AndrozooManager()
    manager.run(args)


def gplay_analysis(args):
    manager = GplayManager()
    manager.run(args)


def fdroid_analysis(args):
    manager = FDroidManager()
    manager.run(args)


def vt_queries(args):
    manager = Active(args.vt, args.quota)
    logger = logging.getLogger('VirusTotal')
    logger.setLevel(logging.NOTSET)
    while True:
        entries = list(
            database.access(
                'SELECT DISTINCT s.sha256 FROM vt_samples as s LEFT OUTER JOIN vt as r ON s.sha256 = r.sha256 LEFT OUTER JOIN errors as e ON s.sha256 = e.sha256 WHERE e.sha256 is NULL and r.sha256 is NULL;'
            ))
        if len(entries) == 0:
            logger.info("Finished processing all apks, exiting now.")
            break
        logger.info(
            f'Found {len(entries)} apks with unfinished virustotal queries.')
        for entry in entries:
            manager.offer(entry[0])
            time.sleep(10)
        logger.info(manager.info())
