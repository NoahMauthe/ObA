import sys

from analysis import init_logging
from utility import argument_parser


def main():
    args = argument_parser.parse_args()
    init_logging(args)
    args.func(args)


if __name__ == '__main__':
    main()
    sys.exit(0)
