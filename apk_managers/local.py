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
    """Manager for apks crawled from Google Play.

    ### DISCLAIMER ###

    This Manager will only work for the file structure generated by our crawler
    from a previous project. If you intend to use this analysis tool on your own
    data, please write a custom Manager.
    The __init__ method of this one can serve you as a template, which is why it
    is excessively documented, the next_apk method can remain identical.
    """

    def __init__(self, path, queue, workers):
        # Initialize the base ApkManager
        super().__init__(queue, workers)
        # Find all apks, starting at the specified root
        apks = fnmatch.filter(
            glob.iglob(os.path.join(os.path.expanduser(os.path.abspath(path)),
                                    '**'),
                       recursive=True), '*.apk')
        # Build set of already processed apks (in case the analysis was interrupted
        done = set(e[0] for e in database.access(
            'SELECT sha256 from results UNION SELECT sha256 from errors;'))
        self.logger.info(f'Found {len(done)} already processed apks.')
        # Compute directories for each apk. This has to be a list as order matters
        dirs = [os.path.dirname(apk) for apk in apks]
        # Compute sha256 identifier for each apk. This has to be a list as order matters
        hashes = [sha256sum(apk) for apk in apks]
        apks = []
        # Build a list of tuples, each of them containing (in order)
        # - sha265 identifier of the apk (str)
        # - directory the apk is located in (str)
        # - function to execute before analysis of the apk (function)
        #   -> In our case, this transfers the metadata into the database from a protobuf file
        # - function to execute after the analysis of the apk (function)
        #   -> In our case, this removes obsolete data (e.g. from decompiling) to save on disk space
        #
        # You should use the previously computed set (done) as a filter to avoid repeat work
        for h, d, c, r in zip(hashes, dirs, repeat(store_gplay_apk_info),
                              repeat(clean.google_play_remnants)):
            if h not in done:
                apks.append((h, d, c, r))
        self.logger.info(f'Initialized with {len(apks)} apks.')
        # Initialize the list of apks with the precomputed list of tuples.
        self.apks = iter(apks)

    def next_apk(self):
        """Retrieve the next apk from the Google Play dataset.

        Returns
        -------
        str
            The sha256 identifier of the apk.
        str
            The directory the apk resides in.
        function
            The function to execute pre-analysis
        function
            The function to execute post-analysis
        """
        try:
            return next(self.apks)
        except StopIteration:
            raise NoMoreApks


class FDroidApkManager(ApkManager):
    """Manager for F-Droid apks.

    In case you want to analyze your own data, please refer to GplayApkManager as
    a reference implementation that is well documented.
    """

    def __init__(self, path, queue, workers):
        super().__init__(queue, workers)
        self.logger.info(path)
        apk_paths = fnmatch.filter(
            glob.iglob(os.path.join(os.path.expanduser(os.path.abspath(path)),
                                    '**'),
                       recursive=True), '*.apk')
        done = set(e[0] for e in database.access(
            'SELECT sha256 from results UNION SELECT sha256 from errors;'))
        self.logger.info(f'Found {len(done)} already processed apks.')
        dirs = [os.path.dirname(apk) for apk in apk_paths]
        hashes = [sha256sum(apk) for apk in apk_paths]
        apks = []
        for h, d, c, r, p in zip(hashes, dirs, repeat(store_fdroid_apk_info),
                                 repeat(clean.fdroid_remnants), apk_paths):
            if h not in done:
                apks.append((h, d, c, r))
                with open(os.path.join(os.path.dirname(p), h), 'w') as file:
                    file.write(p.split('/')[-1].split('.apk')[0] + '\n')
        self.logger.info(f'Initialized with {len(apks)} apks.')
        self.apks = iter(apks)

    def next_apk(self):
        """Retrieve the next apk from the F-Droid dataset.

        Returns
        -------
        str
            The sha256 identifier of the apk.
        str
            The directory the apk resides in.
        function
            The function to execute pre-analysis
        function
            The function to execute post-analysis
        """
        try:
            return next(self.apks)
        except StopIteration:
            raise NoMoreApks
