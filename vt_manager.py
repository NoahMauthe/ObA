import logging
import os.path
import shlex
from multiprocessing import Manager as VariableManager
from multiprocessing import RLock
from subprocess import check_output, CalledProcessError, STDOUT
from time import monotonic_ns

import database
from utility.convenience import convert_time

DAILY_LIMIT = 500


class VTManager:

    def __init__(self, _=None, quota=0):
        self.logger = logging.getLogger('VirusTotal')
        self.logger.setLevel(logging.NOTSET)
        self.lock = RLock()
        self.vm = VariableManager()
        self.quota = self.vm.Value(int, quota)
        self.start = self.vm.Value(int, monotonic_ns())

    def offer(self, sha256):
        pass

    def info(self):
        with self.lock:
            return f'Used {(min(self.quota.get(), 500) / DAILY_LIMIT) * 100:6.2f}% (' \
                   f'{min(self.quota.get(), DAILY_LIMIT)})'


class Dummy(VTManager):

    def info(self):
        return 'Not running'


class Active(VTManager):

    def __init__(self, keyfile, quota):
        super().__init__(keyfile, quota)
        self.logger.info(f'Using keyfile {keyfile}')
        with open(os.path.abspath(keyfile), 'r') as file:
            self.key = file.read().strip()

    def offer(self, sha256):
        if not self.check_quota():
            return
        self.logger.info(f'Querying VirusTotal for {sha256}')
        try:
            output = check_output(shlex.split(
                f"curl -s -S --request GET --url https://www.virustotal.com/api/v3/files/{sha256}"
                f" --header 'x-apikey: {self.key}'"),
                                  stderr=STDOUT).decode('UTF-8')
            database.store_vt(sha256, output)
        except CalledProcessError as error:
            database.store_vt_error(sha256, error.stdout)

    def check_quota(self):
        with self.lock:
            self.quota.set(self.quota.get() + 1)
            if self.quota.get() <= DAILY_LIMIT:
                return True
            elif self.quota.get() == DAILY_LIMIT + 1:
                self.logger.info(
                    f'Reached daily limit of {DAILY_LIMIT} queries.')
                self.start.set(monotonic_ns() + 86400000000000)
            elif monotonic_ns() > self.start.get():
                self.logger.info('Virustotal query quota reset.')
                self.quota.set(1)
                return True
            elif self.quota.get() % 100 == 0:
                self.logger.info(
                    f'Quota limit reached, still waiting for'
                    f'{convert_time(self.start.get() - monotonic_ns())}')
            return False
