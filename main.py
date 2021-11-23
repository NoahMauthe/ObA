import sys

from analysis import init_logging
from utility import argument_parser

VERSION = "1.0.1"


def main():
    args = argument_parser.parse_args()
    if args.version:
        print(f'Obfuscation Analysis version {VERSION}')
        return
    init_logging(args)
    args.func(args)


if __name__ == '__main__':
    main()
    sys.exit(0)
