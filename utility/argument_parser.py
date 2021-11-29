import argparse
import os

from analysis import androzoo_analysis, gplay_analysis
from database import create_db


def parse_args():
    parent = argparse.ArgumentParser(add_help=False, description='Obfuscation Analysis Tool')
    parent.add_argument('--loglevel', choices=['info', 'verbose', 'debug'], default='info',
                        help='Specifies the global log level.')
    parent.add_argument('--logfile', type=str, help='Specifies the logfile to use. Will append, not overwrite')
    parent.add_argument('--db', type=str, help='Changes the default database string')
    parent.add_argument('--worker', type=int, help='Changes the number of workers used.',
                        default=len(os.sched_getaffinity(0)))
    parser = argparse.ArgumentParser()
    parser.add_argument('--version', action='store_true', help='Displays the version number and exits')
    subparsers = parser.add_subparsers()
    create = subparsers.add_parser('createdb', help='Creates the database containing information gathered from'
                                                    ' the androzoo dataset.', parents=[parent])
    create.add_argument('--local', type=str, default=None, help='specifies a local csv file to use instead of '
                                                                'downloading a new one.')
    create.set_defaults(func=create_db)
    create.add_argument('--sample', action='store_true', default=False, help='If set, creates a random sample and saves'
                                                                             ' it to "file". Otherwise the contents of'
                                                                             ' "file" will be read and saved to db.')
    create.add_argument('file', help='The file to take the samples from / store the samples in.')
    androzoo = subparsers.add_parser('androzoo', help='Runs the analysis on apps from the androzoo dataset.',
                                     parents=[parent])
    androzoo.add_argument('--repeat', action='store_true', help='If set, the queries read from file will be retried if'
                                                                ' they have all been processed.\n'
                                                                'WARNING: Make sure your queries filter out already'
                                                                'processed applications when using this options,'
                                                                'otherwise the analysis will run indefinitely',
                          default=False)
    androzoo.add_argument('--vt', type=str, help='Specifies location of VirusTotal API Key', default=None)
    androzoo.add_argument('--vt-quota', dest='quota', type=int, help='Specifies the VirusTotal API quota already used',
                          default=0)
    androzoo.add_argument('key', type=str, help='Specifies the location of the androzoo key file.')
    androzoo.add_argument('queries', type=str, help='Specifies a file containing SQL queries that determine which files'
                                                    ' will be analyzed')
    androzoo.set_defaults(func=androzoo_analysis)
    gplay = subparsers.add_parser('gplay', help='Runs the analysis on local apps from the GooglePlay dataset.',
                                  parents=[parent])
    gplay.add_argument('root', type=str, help='Specifies the directory root of all .apk files.')
    gplay.set_defaults(func=gplay_analysis)
    return parser.parse_args()
