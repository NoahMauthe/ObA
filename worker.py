import fnmatch
import gzip
import logging
import os
import pickle
import signal
import time
from multiprocessing import Process
from resource import getrlimit, RLIMIT_AS, setrlimit
from subprocess import SubprocessError, check_output, CalledProcessError, DEVNULL

import numpy as np
from androguard.decompiler.dad.decompile import DvMethod
from androguard.misc import AnalyzeAPK

import database
from cfganomaly.cfganomaly import CfgAnomaly
from method_parser import MethodParser, ParserError
from utility.convenience import timeout_handler, extract, file_info, bin_name, VERBOSE, TIMEOUT, filter_type, MAX_MEM


class Worker(Process):

    def __init__(self, name, apks, manager, model):
        super(Worker, self).__init__()
        self.name = name
        self.apks = apks
        self.logger = logging.getLogger(self.name)
        self.logger.setLevel(logging.NOTSET)
        self.success = 0
        self.parser_failed = 0
        self.decompiler_failed = 0
        self.method_invocations = {}
        self.current_sha256 = None
        self.manager = manager
        self.anomaly_detector = None
        self.model = model

    def run(self):
        signal.signal(signal.SIGALRM, timeout_handler)
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        soft, hard = getrlimit(RLIMIT_AS)
        self.logger.log(VERBOSE, f'Initial memory limit was {soft}, {hard}. Restricting to {MAX_MEM}, {MAX_MEM * 1.5}')
        setrlimit(RLIMIT_AS, (MAX_MEM, MAX_MEM * 1.5))
        while True:
            apk_info = self.apks.get()
            if not apk_info:
                self.logger.info(f'Got empty apk. Assuming end of work and shutting down.')
                break
            sha256, directory, pre, post = apk_info
            try:
                self.logger.debug(f'Starting analysis of {sha256}.')
                if pre:
                    pre(sha256, directory)
                signal.alarm(TIMEOUT)
                self.analyze(sha256, directory)
                signal.alarm(0)
                self.manager.vt_manager.offer(sha256)
                self.manager.report_success()
            except TimeoutError:
                signal.alarm(0)
                self.logger.error(f'{sha256} timed out after {TIMEOUT}s.')
                self.manager.report_timeout()
                database.record_timeout(sha256, f'Timed out after {TIMEOUT}s.')
            except MemoryError:
                self.method_invocations = {}
                error = 'ran out of memory'
                self.logger.error(f'{sha256} {error}.')
                self.manager.report_memory()
                database.full_error(sha256, error)
                self.manager.close(self.name)
                break
            except Exception as error:
                self.logger.error(f'{sha256} encountered an unexpected error: {repr(error)}.')
                self.manager.report_error()
                database.full_error(sha256, f'Encountered an unexpected error: {repr(error)}')
            if post:
                post(sha256, directory)
        self.manager.stop()
        self.logger.info('Finished.')

    def reset(self, sha256):
        self.current_sha256 = sha256
        self.method_invocations = dict()
        self.success = 0
        self.parser_failed = 0
        self.decompiler_failed = 0

    def analyze(self, sha256, directory):
        self.reset(sha256)
        apk_path = os.path.join(directory, fnmatch.filter(os.listdir(directory), '*.apk')[0])
        self.check_packer(apk_path)
        application, dex, analysis = AnalyzeAPK(apk_path)
        self.check_xref(application, analysis)
        self.check_files(application, apk_path)
        self.check_methods(analysis)

    def check_packer(self, apk_path):
        try:
            output = check_output(['apkid', '-j', apk_path], stderr=DEVNULL).decode('UTF-8')
            database.store_apkid_result(self.current_sha256, output)
        except CalledProcessError as error:
            self.logger.error(f'{self.current_sha256}:\t apkid error:\t{repr(error)}')
            database.apkid_error(self.current_sha256, repr(error), error.stderr)
        except RuntimeError as error:
            self.logger.error(f'{self.current_sha256}:\t apkid error:\t{repr(error)}')
            database.apkid_error(self.current_sha256, repr(error), '')
        except KeyboardInterrupt:
            pass

    def check_xref(self, application, analysis):
        library_loads = self.check_library_loads(analysis)
        dex_loader_access = self.check_dex_loader_access(analysis)
        class_loader_access = self.check_class_loader_access(analysis)
        reflection_access, reflection_invocations = self.check_reflection_calls(analysis)
        total = sum([1 if not method.is_external() else 0 for method in analysis.get_methods()])
        self.logger.log(VERBOSE, f'Found {total} methods in total for {self.current_sha256},'
                                 f'{self.success + self.parser_failed + self.decompiler_failed} of which'
                                 f' used a critical method, {self.decompiler_failed} of which failed '
                                 f'decompilation and {self.parser_failed} failed parsing')
        permissions = list(set(application.get_permissions()))
        database.store_result(self.current_sha256, permissions, library_loads, dex_loader_access, class_loader_access,
                              reflection_access, reflection_invocations, total, self.success, self.parser_failed,
                              self.decompiler_failed)

    def check_library_loads(self, analysis):
        library_loads = {
            "Ljava/lang/System;": ["load", "loadLibrary"],
            "Ljava/lang/Runtime;": ["load", "loadLibrary"],
            "Lcom/getkeepsafe/relinker/ReLinker;": ["loadLibrary"],
            "Lcom/getkeepsafe/relinker/ReLinkerInstance;": ["loadLibrary"],
            "Lcom/getkeepsafe/relinker/SystemLibraryLoader;": ["loadPath"],
        }
        total = 0
        loaded_libs = dict()
        for class_name in library_loads:
            for method_name in library_loads[class_name]:
                for method in analysis.find_methods(classname=class_name, methodname=method_name):
                    callees = self.extract_calls(method)
                    total += len(callees)
                    for callee in callees:
                        invocations = self.extract_invocations(callee)
                        for args in invocations.get(class_name, {}).get(method_name, []):
                            loaded_libs[args[-1]] = loaded_libs.get(args[-1], 0) + 1
        database.store_library_access(self.current_sha256, loaded_libs)
        return total

    def check_dex_loader_access(self, analysis):
        dex_loaders = {
            "Ldalvik/system/BaseDexClassLoader;": 0,
            "Ldalvik/system/DexClassLoader;": 0,
            "Ldalvik/system/InMemoryDexClassLoader;": 0,
            "Ldalvik/system/PathClassLoader;": 0,
            "Ldalvik/system/DelegateLastClassLoader;": 0,
        }
        total = 0
        for class_name in dex_loaders:
            class_ = analysis.classes.get(class_name, None)
            if not class_:
                self.logger.debug(f'No access to {class_name} found in {self.current_sha256}.')
                continue
            for method in class_.get_methods():
                count = len(self.extract_calls(method))
                dex_loaders[class_name] += count
                total += count
        database.store_dex_loader_access(self.current_sha256, dex_loaders)
        return total

    def check_class_loader_access(self, analysis):
        class_loaders = {
            "Ljava/lang/ClassLoader;": ["defineClass",
                                        "loadClass",
                                        "findClass",
                                        "findSystemClass",
                                        "getClassLoadingLock"],
            "Ljava/security/SecureClassLoader;": ["defineClass"],
            "Ljava/net/URLClassLoader;": ["findClass"],
        }
        total = 0
        loaded_classes = dict()
        for class_name in class_loaders:
            for method_name in class_loaders[class_name]:
                for method in analysis.find_methods(classname=class_name, methodname=method_name):
                    callees = self.extract_calls(method)
                    for callee in callees:
                        invocations = self.extract_invocations(callee)
                        for args in invocations.get(class_name, {}).get(method_name, []):
                            loaded_classes[args[1]] = loaded_classes.get(args[1], 0) + 1
                            total += 1
        database.store_class_loader_access(self.current_sha256, loaded_classes)
        return total

    def check_reflection_calls(self, analysis):
        total = 0
        reflected_classes = dict()
        reflected_methods = dict()
        reflection_api_accesses = dict()
        reflection_classes = list(analysis.find_classes(name='Ljava/lang/reflect/*', no_external=False)) + \
                             list(analysis.find_classes(name='Ljava/lang/Class;', no_external=False))
        self.logger.debug(f'Found {len(reflection_classes)} reflection classes.')
        for class_ in reflection_classes:
            for method in class_.get_methods():
                calls = len(self.extract_calls(method))
                reflection_api_accesses[class_.name] = reflection_api_accesses.get(class_.name, 0) + calls
                total += calls
        triples = [('Ljava/lang/Class;', 'forName', 1), ('Ljava/lang/Object;', 'getClass', 0)]
        for class_name, method_name, index in triples:
            for method in analysis.find_methods(classname=class_name, methodname=method_name):
                for caller in self.extract_calls(method):
                    for args in self.extract_invocations(caller).get(class_name, {}).get(method_name, []):
                        reflected_classes[args[index]] = reflected_classes.get(args[index], 0) + 1
        class_name = 'Ljava/lang/Class;'
        method_name = 'getMethod'
        for method in analysis.find_methods(classname=class_name, methodname=method_name):
            for caller in self.extract_calls(method):
                for args in self.extract_invocations(caller).get(class_name, {}).get(method_name, []):
                    class_ = reflected_methods.get(args[0], {})
                    class_[args[1]] = class_.get(args[1], 0) + 1
                    reflected_methods[args[0]] = class_
        invocations_count = sum(len(self.extract_calls(method)) for method in analysis.find_methods(
            classname='Ljava/lang/reflect/Method;', methodname='invoke'))
        database.store_reflection_information(self.current_sha256, reflected_classes, reflected_methods)
        return total, invocations_count

    def check_files(self, application, apk_path):
        start = time.monotonic_ns()
        try:
            extracted = extract(apk_path)
        except (SubprocessError, RuntimeError) as e:
            self.logger.error(f'{self.current_sha256} failed unzipping:\n{repr(e)}')
            database.partial_error(self.current_sha256, repr(e))
            return
        files = []
        for filename, file_type in self.filter_files(application):
            entropy, sha256, size = file_info(os.path.join(extracted, filename))
            files.append((sha256, entropy, file_type, size))
        database.store_files(self.current_sha256, files)
        duration = time.monotonic_ns() - start
        self.logger.log(VERBOSE, f'Checking all files took {duration / 1000000:.2f}ms')

    def filter_files(self, application):
        filtered = 0
        for filename, filetype in application.get_files_types().items():
            if filter_type(filetype):
                yield filename, filetype
            else:
                filtered += 1
        self.logger.debug(f'Removed {filtered} files by filtering.')

    def extract_calls(self, method):
        calls = set(call for _, call, _ in method.get_xref_from())
        self.logger.debug(f'{method.full_name} was called {len(calls)} times')
        return calls

    def check_methods(self, analysis):
        bins = dict()
        methods = [method for method in analysis.get_methods() if not method.is_external()]
        for method in methods:
            bin_id = bin_name(method.get_length())
            bins[bin_id] = bins.get(bin_id, 0) + 1
        database.store_method_sizes(self.current_sha256, bins)
        self.detect_anomalies(methods)

    def detect_anomalies(self, method_analyses, cutoff_score=-0.30):
        if self.anomaly_detector is None:
            # Initialize anomaly detector, only needs to be done once in practice
            if self.model is None:
                return
            with gzip.open(self.model, 'rb') as f:
                model = pickle.load(f)
            self.anomaly_detector = CfgAnomaly(model)

        scores = self.anomaly_detector.get_anomaly_scores(method_analyses)

        # Print methods whose anomaly scores fall under the threshold
        # (i.e., the most anomalous methods)
        indices = np.flatnonzero(scores < cutoff_score)
        anomalies = {}
        for i in indices:
            anomalies[str(method_analyses[i].full_name)] = scores[i]
        self.logger.log(VERBOSE, f'Found {len(indices)} anomalies')
        database.store_anomalies(self.current_sha256, anomalies)
        database.store_anomaly_overview(self.current_sha256, len(indices),
                                        sum(1 if score == 1.0 else 0 for score in scores))

    def extract_invocations(self, method):
        method_invocations = self.method_invocations.get(method, {})
        if method_invocations:
            return method_invocations
        try:
            dv = DvMethod(method)
            dv.process(doAST=True)
            parser = MethodParser()
            method_invocations = parser.parse(dv.get_ast())
            self.success += 1
        except ParserError as error:
            self.parser_failed += 1
            self.logger.log(VERBOSE, f'{method.full_name} failed parsing: {repr(error)}')
        except Exception as error:
            self.logger.log(VERBOSE, f'{method.full_name} failed decompilation: {repr(error)}')
            self.decompiler_failed += 1
        self.method_invocations[method] = method_invocations
        return method_invocations
