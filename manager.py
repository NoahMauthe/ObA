import logging
import os
import signal
import sys
from multiprocessing import Manager as VariableManager, Queue, RLock, current_process
from time import monotonic_ns, sleep

import database
from apk_managers.local import LocalApkManager
from apk_managers.androzoo import AndrozooApkManager
from utility.convenience import convert_time, VERBOSE, STATUS, WORKER_COUNT
from vt_manager import Dummy, Active
from worker import Worker


class Manager:

    def __init__(self, args):
        self.args = args
        self.logger = logging.getLogger('Manager')
        self.logger.setLevel(logging.NOTSET)
        signal.signal(signal.SIGINT, self.handle_interrupt)
        self.vt_manager = None
        self.apk_manager = None
        self.lock = RLock()
        self.workers = {}
        self.vm = VariableManager()
        self.remove = self.vm.list()
        self.total = self.vm.Value(int, 0)
        self.failed = self.vm.Value(int, 0)
        self.timeout = self.vm.Value(int, 0)
        self.success = self.vm.Value(int, 0)
        self.memory = self.vm.Value(int, 0)
        self.stopped = self.vm.Value(bool, False)
        self.start_time = self.vm.Value(int, monotonic_ns())

    def init(self):
        database.create()
        queue = Queue(WORKER_COUNT)
        self.vt_manager = Dummy()
        if self.args.local:
            self.apk_manager = LocalApkManager(self.args.local, queue)
        else:
            self.apk_manager = AndrozooApkManager(self.args.androzoo, self.args.queries, queue)
            if self.args.vt:
                self.vt_manager = Active(self.args.vt, self.args.quota)
        self.apk_manager.start()
        self.start_workers(self.args.model)

    def start_workers(self, model):
        for i in range(WORKER_COUNT):
            name = f'Worker {"0" if i < 10 else ""}{i}'
            worker = Worker(name, self.apk_manager.queue, self, model)
            self.workers[name] = worker
            worker.start()
            self.logger.log(VERBOSE, f'Started {name}')
        self.logger.log(STATUS, f'Running analysis with {len(self.workers)} workers.')

    def handle_interrupt(self, *_):
        if current_process().name != 'MainProcess':
            return
        self.logger.info(f'Received interrupt, initiating shutdown.')
        self.shutdown()

    def shutdown(self):
        self.apk_manager.terminate()
        self.apk_manager.join()
        self.logger.info('Stopped ApkManager.')
        for w in self.workers:
            self.workers[w].terminate()
        self.logger.info(f'Sent termination signal to all workers, waiting for them to exit.')
        for w in self.workers:
            self.workers[w].join()
        self.verbose_status()
        self.logger.info(f'All done, exiting now.')
        sys.exit(0)

    def run(self):
        self.init()
        to_sleep = max(1, 60 - ((monotonic_ns() - self.start_time.get()) // 1000000000))
        sleep(to_sleep)
        while True:
            try:
                with self.lock:
                    if self.stopped.get():
                        self.logger.info('was stopped.')
                        break
                self.verbose_status()
                self.restart_dead_processes()
                sleep(60)
            except Exception as error:
                self.logger.error(f'Main thread encountered an error: {repr(error)}')
        self.shutdown()

    def stop(self, name):
        self.logger.info(f'Manager was stopped by {name}.')
        with self.lock:
            self.stopped.set(True)

    def report_error(self):
        self.failed.set(self.failed.get() + 1)
        self.total.set(self.total.get() + 1)
        self.log_status()

    def report_success(self):
        self.success.set(self.success.get() + 1)
        self.total.set(self.total.get() + 1)
        self.log_status()

    def report_memory(self):
        self.memory.set(self.memory.get() + 1)
        self.total.set(self.total.get() + 1)
        self.log_status()

    def report_timeout(self):
        self.timeout.set(self.timeout.get() + 1)
        self.total.set(self.total.get() + 1)
        self.log_status()

    def close(self, name):
        with self.lock:
            self.remove.append(name)

    def log_status(self):
        if self.total.get() % 10 == 0:
            self.logger.log(STATUS, f'Analyzed {self.total.get()} apks.')
        else:
            self.logger.debug(f'Analyzed {self.total.get()} apks.')

    def verbose_status(self):
        with self.lock:
            total = self.total.get()
            percent = max(1, total)
            s = f'\n\t##### STATUS {"#" * 20}\n\n' \
                f'\tTime elapsed:\t{convert_time(monotonic_ns() - self.start_time.get()):>17}\n' \
                f'\tVirusTotal:\t{self.vt_manager.info():>17}\n\n' \
                f'\tSuccess:  {self.success.get():>12,d} ({self.success.get() / percent * 100:>6.2f}%)\n' \
                f'\tTimeout:  {self.timeout.get():>12,d} ({self.timeout.get() / percent * 100:>6.2f}%)\n' \
                f'\tFailed:   {self.failed.get():>12,d} ({self.failed.get() / percent * 100:>6.2f}%)\n' \
                f'\tMemory:   {self.memory.get():>12,d} ({self.memory.get() / percent * 100:>6.2f}%)\n' \
                f'\t{"-" * 33}\n' \
                f'\tTotal:    {total:>11,d}\n\n' \
                '\t' + '#' * 33
            self.logger.log(STATUS, s)

    def restart_dead_processes(self):
        with self.lock:
            while len(self.remove) > 0:
                name = self.remove.pop()
                worker = self.workers[name]
                worker.terminate()
                worker.join()
                worker.close()
                self.workers[name] = None
                new_worker = Worker(name, self.apk_manager.queue, self, self.args.model)
                self.workers[name] = new_worker
                new_worker.start()
                self.logger.info(f'Restarted {name} with pid {new_worker.pid}')
            for name, worker in self.workers.items():
                if worker:
                    if worker.is_alive():
                        continue
                    worker.terminate()
                    worker.join()
                    worker.close()
                self.workers[name] = None
                new_worker = Worker(name, self.apk_manager.queue, self)
                self.workers[name] = new_worker
                new_worker.start()
                self.logger.info(f'Restarted {name} with pid {new_worker.pid}')
