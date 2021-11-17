import os
import shlex
import tempfile
from subprocess import check_output, CalledProcessError

from utility import clean
import database
from apk_managers.abstract import ApkManager
from utility.exceptions import NoMoreApks, DownloadFailed
from utility.convenience import VERBOSE


class AndrozooApkManager(ApkManager):

    def __init__(self, api_key, queries, queue):
        super().__init__(queue)
        with open(api_key, 'r') as key:
            self.key = key.read().strip()
        with open(queries, 'r') as q:
            self.queries = iter(q.read().strip().split(os.linesep))
        self.query = None
        self.apks = iter([])

    def next_apk(self):
        try:
            sha256 = next(self.apks)
            directory = self.download(sha256)
            return sha256, directory, None, clean.androzoo_remnants
        except StopIteration:
            self.next_query()
            return self.next_apk()
        except DownloadFailed:
            return self.next_apk()

    def next_query(self):
        if self.query:
            self.logger.info(f'Finished processing the following query:\n\t{self.query}')
        try:
            self.query = next(self.queries)
            self.logger.info(f'Previous query had no more apks, continuing with the following query:\n\t{self.query}')
            self.apks = iter([row[0] for row in database.access(self.query)])
        except StopIteration:
            raise NoMoreApks

    def download(self, sha256):
        tmpdir = tempfile.mkdtemp()
        self.logger.log(VERBOSE, f'Downloading {sha256}')
        try:
            check_output(shlex.split(
                f'curl -s -S -O --remote-header-name -G -d apikey={self.key} -d sha256={sha256}'
                f' https://androzoo.uni.lu/api/download'), cwd=tmpdir)
        except CalledProcessError as e:
            self.logger.error(f'{sha256} failed downloading.')
            database.full_error(sha256, f'Failed downloading with code {e.returncode}: {e.stderr}')
            raise DownloadFailed
        return tmpdir
