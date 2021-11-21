import logging
from multiprocessing import Process

from utility.convenience import WORKER_COUNT
from utility.exceptions import NoMoreApks


class ApkManager(Process):

    def __init__(self, queue):
        super().__init__()
        self.queue = queue
        self.logger = logging.getLogger('ApkManager')
        self.logger.setLevel(logging.NOTSET)

    def run(self):
        while True:
            try:
                self.queue.put(self.next_apk())
            except NoMoreApks:
                self.logger.info(f'No more apks left, exiting now.')
                for i in range(WORKER_COUNT):
                    self.queue.put(None)
                break
        self.logger.info('Finished.')

    def next_apk(self):
        raise NotImplemented('This class is not meant to be used directly.')
