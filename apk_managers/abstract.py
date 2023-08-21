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
        """Starts the manager in an endless loop to supply apk files for the analysis.
        Can be stopped by throwing a utility.exceptions.NoMoreApks Error.
        """

        while True:
            try:
                self.queue.put(self.next_apk())
            except NoMoreApks:
                self.logger.info('No more apks left, exiting now.')
                for i in range(self.workers):
                    self.queue.put(None)
                break
        self.logger.info('Finished.')

    def next_apk(self):
        """Returns the next apk from a predetermined set of apks.
        Details thereof depend on the source of the apks and the corresponding implementation,
        this method is just a dummy.
        """
        raise NotImplementedError(
            'This class is not meant to be used directly.')
