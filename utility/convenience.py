import hashlib
import logging
import math
import os
import shlex
import sys
from subprocess import check_output

ENTROPY_THRESHOLD = 7.2
VERBOSE = 15
STATUS = 30
TIMEOUT = 900
WORKER_COUNT = 0
MAX_MEM = 5500000000
MAX_RETRIES = 5

byte_list = bytes([i for i in range(0, 256)])


def sha256sum(filename):
    with open(filename, 'rb') as file:
        return hashlib.sha256(file.read()).hexdigest()


def filter_type(filetype):
    types = {'PNG', 'Targa', 'TrueType', 'Android binary XML', 'JPEG', 'SVG', 'HTML', 'XML', 'ASCII text'}
    for t in types:
        if filetype.startswith(t):
            return False
    return True


def convert_time(nanoseconds):
    seconds = nanoseconds // 1000000000
    minutes = seconds // 60
    seconds = seconds - minutes * 60
    hours = minutes // 60
    minutes = minutes - hours * 60
    days = hours // 24
    hours = hours - days * 24
    return f'{days:>2d}d {hours:>2d}h {minutes:>2d}m {seconds:>2d}s'


def convert_small_time(nanoseconds):
    milliseconds = nanoseconds // 1000000
    seconds = milliseconds // 1000
    milliseconds = milliseconds - seconds * 1000
    return f'{seconds:>3d}s {milliseconds:>3d}ms'


def extract(apk_path):
    """

    Parameters
    ----------
    apk_path

    Returns
    -------

    """
    tmpdir = os.path.dirname(os.path.realpath(apk_path))
    check_output(shlex.split(f'nice -n 15 unzip -o -d apk -qq {apk_path}'), cwd=tmpdir)
    return os.path.join(tmpdir, 'apk')


def shannon_entropy(file_content):
    """
    Taken from https://github.com/trufflesecurity/truffleHog/blob/dev/truffleHog/truffleHog.py
    """
    if not file_content:
        return 0
    entropy = 0
    for x in byte_list:
        p_x = float(file_content.count(x)) / len(file_content)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy


def file_info(filename):
    with open(filename, 'rb') as file:
        content = file.read()
    sha256 = hashlib.sha256(content).hexdigest()
    entropy = shannon_entropy(content)
    size = os.path.getsize(filename)
    return entropy, sha256, size


def log_psycopg2_exception(err, logger=None):
    if logger is None:
        logger = logging.getLogger('psycopg2')
    err_type, err_obj, traceback = sys.exc_info()
    line = traceback.tb_lineno
    logger.error(f'{err} in line {line}\n'
                 f'traceback:\t{traceback}\n'
                 f'type:\t\t{err_type}\n'
                 f'diag:\t\t{err.diag}\n'
                 f'code:\t\t{err.pgcode}')


def bin_name(size):
    if size == 0:
        return 'bin_empty'
    return f'bin_{min(int((math.log2(size) * 100) // 17), 100)}'


def timeout_handler(*_):
    raise TimeoutError
