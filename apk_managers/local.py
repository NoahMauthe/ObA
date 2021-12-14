import fnmatch
import glob
import os
from itertools import repeat

import database
from apk_managers.abstract import ApkManager
from compatibility.stores import store_gplay_apk_info, store_fdroid_apk_info
from utility import clean
from utility.convenience import sha256sum
from utility.exceptions import NoMoreApks


class GplayApkManager(ApkManager):

    def __init__(self, path, queue, workers):
        super().__init__(queue, workers)
        apks = fnmatch.filter(glob.iglob(os.path.join(path, '**'), recursive=True), '*.apk')
        done = set(e[0] for e in database.access('SELECT sha256 from results UNION SELECT sha256 from errors;'))
        self.logger.info(f'Found {len(done)} already processed apks.')
        dirs = [os.path.dirname(apk) for apk in apks]
        hashes = [sha256sum(apk) for apk in apks]
        apks = []
        for h, d, c, r in zip(hashes, dirs, repeat(store_gplay_apk_info), repeat(clean.google_play_remnants)):
            if h not in done:
                apks.append((h, d, c, r))
        self.logger.info(f'Initialized with {len(apks)} apks.')
        self.apks = iter(apks)

    def next_apk(self):
        try:
            return next(self.apks)
        except StopIteration:
            raise NoMoreApks


class FDroidApkManager(ApkManager):

    def __init__(self, path, queue, workers):
        super().__init__(queue, workers)
        apk_names = fnmatch.filter(glob.iglob(os.path.join(path, '**'), recursive=True), '*.apk')
        done = set(e[0] for e in database.access('SELECT sha256 from results UNION SELECT sha256 from errors;'))
        self.logger.info(f'Found {len(done)} already processed apks.')
        dirs = [os.path.dirname(apk) for apk in apk_names]
        hashes = [sha256sum(apk) for apk in apk_names]
        apks = []
        for h, d, c, r, n in zip(hashes, dirs, repeat(store_fdroid_apk_info), repeat(clean.fdroid_remnants), apk_names):
            if h not in done:
                apks.append((h, d, c, r))
                with open(os.path.join(path, h), 'w') as file:
                    file.write(n.split('.apk')[0] + '\n')
        self.logger.info(f'Initialized with {len(apk_names)} apks.')
        self.apks = iter(apks)

    def next_apk(self):
        try:
            return next(self.apks)
        except StopIteration:
            raise NoMoreApks
