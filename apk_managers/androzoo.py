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

    def __init__(self, api_key, queries, queue, workers, repeat):
        super().__init__(queue, workers)
        with open(api_key, 'r') as key:
            self.key = key.read().strip()
        with open(queries, 'r') as q:
            self.queries = iter(q.read().strip().split(os.linesep))
        self.query_file = queries
        self.query = None
        self.apks = iter([])
        self.query_yield = 0
        self.repeat = repeat

    def next_apk(self):
        """Retrieves the next apk from the androzoo dataset.

        Queries the database for a set of apks, which is then cached and iterated upon
        until all apks are exhausted. Then, a new query will automatically be constructed
        so the process of apk retrieval can continue seemlessly.

        Returns
        -------
        str
            sha256 identifier of the apk.
        str
            The directory the apk was saved to.
        method
            Always none. Can specify a preprocessing function.
        method
            The function to execute after the analysis in order to clean any
            unnecessary overhead from disk.
        """
        try:
            sha256 = next(self.apks)
            if not sha256:
                return self.next_apk()
            self.query_yield += 1
            directory = self.download(sha256)
            return sha256, directory, None, clean.androzoo_remnants
        except StopIteration:
            self.next_query()
            return self.next_apk()
        except DownloadFailed:
            return self.next_apk()

    def next_query(self):
        """Upon the exhaustion of the apk list returned by the previous query,
        generate a new query to retrieve more apks.

        Does not return a value, instead the new query will be saved as self.query
        in order to allow for a stateful processing.
        """
        if self.query:
            self.logger.info(
                f'Finished processing the following query:\n\t{self.query}')
        try:
            self.query = next(self.queries)
            self.logger.info(
                f'Previous query had no more apks, continuing with the following query:\n\t{self.query}'
            )
            self.apks = iter([row[0] for row in database.access(self.query)])
            return
        except StopIteration:
            if not self.repeat or self.query_yield == 0:
                raise NoMoreApks
            if self.query_yield == 0:
                self.logger.info(
                    'Previous iteration had no new apks, stopping loop.')
                raise NoMoreApks
        self.logger.info('Rerunning all queries to look for new results.')
        with open(self.query_file, 'r') as q:
            self.queries = iter(q.read().strip().split(os.linesep))
        self.query_yield = 0

    def download(self, sha256):
        """Given an apk identifier, downloads the apk from the androzoo dataset.

        Parameters
        ----------
        sha256: str
            The sha256 identifier of the application.

        Returns
        -------
        str
            The directory the apk was saved to.
        """
        tmpdir = tempfile.mkdtemp()
        self.logger.log(VERBOSE, f'Downloading {sha256}')
        try:
            check_output(shlex.split(
                f'curl -s -S -O --remote-header-name -G -d apikey={self.key} -d sha256={sha256}'
                f' https://androzoo.uni.lu/api/download'), cwd=tmpdir)
        except CalledProcessError as e:
            self.logger.error(f'{sha256} failed downloading.')
            database.full_error(
                sha256,
                f'Failed downloading with code {e.returncode}: {e.stderr}')
            raise DownloadFailed
        return tmpdir
