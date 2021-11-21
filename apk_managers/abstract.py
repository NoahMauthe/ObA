import logging
from multiprocessing import Process

from utility.exceptions import NoMoreApks


class ApkManager(Process):

    def __init__(self, queue, workers):
        super().__init__()
        self.queue = queue
        self.logger = logging.getLogger('ApkManager')
        self.logger.setLevel(logging.NOTSET)
        self.workers = workers

    def run(self):
        while True:
            try:
                self.queue.put(self.next_apk())
            except NoMoreApks:
                self.logger.info(f'No more apks left, exiting now.')
                for i in range(self.workers):
                    self.queue.put(None)
                break
        self.logger.info('Finished.')

    def next_apk(self):
        raise NotImplemented('This class is not meant to be used directly.')
