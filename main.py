import logging
import os
import sys

from utility import argument_parser
import database
from utility.convenience import VERBOSE, STATUS
from manager import Manager


def init_logging(arguments):
    logging.addLevelName(VERBOSE, "VERBOSE")
    logging.addLevelName(STATUS, "STATUS")
    loglevel = logging.INFO
    logging.getLogger('androguard').setLevel(logging.FATAL)
    logging.getLogger('dad').setLevel(logging.FATAL)
    if arguments.debug:
        loglevel = logging.DEBUG
    else:
        if arguments.verbose:
            loglevel = VERBOSE
    console_formatter = logging.Formatter('[{levelname:^10}] {{{name:^13}}}\t{message}', style='{')
    console_handler = logging.StreamHandler()
    console_handler.setLevel(loglevel)
    console_handler.setFormatter(console_formatter)
    root = logging.getLogger()
    root.setLevel(logging.NOTSET)
    root.addHandler(console_handler)
    if arguments.logfile:
        file_handler = logging.FileHandler(os.path.abspath(arguments.logfile))
        file_handler.setLevel(loglevel)
        file_handler.setFormatter(logging.Formatter('{asctime}\t[{levelname}] {{{name}}}\t{message}', style='{'))
        root.addHandler(file_handler)


def main():
    args = argument_parser.parse_args()
    init_logging(args)
    # TODO move the database creation to external script
    if args.createdb:
        database.create()
        database.populate(args.csv)
        sys.exit(0)
    manager = Manager(args)
    manager.run()


if __name__ == '__main__':
    main()
    sys.exit(0)
