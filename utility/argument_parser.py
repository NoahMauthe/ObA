import argparse
import sys

import database


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--verbose', action='store_true', help='Enables verbose logging')
    parser.add_argument('--debug', action='store_true', help='Enables debug output, prioritized over --verbose')
    parser.add_argument('--logfile', type=str, help='Specifies the logfile to use. Will append, not overwrite')
    parser.add_argument('--createdb', action='store_true', default=False,
                        help='Create the database instead of running the analysis.')
    if '--createdb' in sys.argv:
        parser.add_argument('csv', type=str, help='The csv file to create the database from.')
        return parser.parse_args()
    parser.add_argument('--db', type=str, help='Changes the default database string')
    source_group = parser.add_mutually_exclusive_group(required=True)
    source_group.add_argument('--androzoo', type=str, help='Specifies location of androzoo API Key')
    source_group.add_argument('--local', type=str, help='Specifies the basepath for all local files')
    parser.add_argument('--queries', type=str, help='Specifies a file containing partial SQL queries that determine'
                                                    ' which files will be analyzed', default=None)
    parser.add_argument('--vt', type=str, help='Specifies location of VirusTotal API Key', default=None)
    parser.add_argument('--vt-quota', dest='quota', type=int, help='Specifies the VirusTotal API quota already used',
                        default=0)
    parser.add_argument('--model', dest='model', type=str, help='Specifies the path to a model for anomaly detection',
                        default=None)
    args = parser.parse_args()
    if args.db:
        database.db_string = args.db
    else:
        database.db_string = 'dbname=malware user=postgres host=0.0.0.0'
    return args
