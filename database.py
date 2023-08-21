import csv
import gzip
import json
import logging
import os
import pprint
import random
import shlex
import shutil
import sys
import tempfile
import time
from subprocess import check_output, CalledProcessError

import psycopg2 as db

from compatibility.json import Encoder
from utility.convenience import convert_time, log_psycopg2_exception
from utility.exceptions import DatabaseRetry

logger = logging.getLogger('postgreSQL')
logger.setLevel(logging.NOTSET)

db_string = None


def download_csv():
    tmpdir = tempfile.mkdtemp()
    logger.info('Downloading csv file containing the androzoo database.')
    start = time.monotonic_ns()
    try:
        check_output(shlex.split(
            'curl -s -S -o "androzoo.csv.gz" https://androzoo.uni.lu/static/lists/latest.csv.gz'
        ), cwd=tmpdir)
    except CalledProcessError as error:
        logger.fatal('Failed to download csv file, exiting now.')
        sys.exit(repr(error))
    logger.info(
        f'Downloading took {convert_time(time.monotonic_ns() - start)}')
    return os.path.join(tmpdir, 'androzoo.csv.gz')


def populate(filepath, db_connection):
    """Populates the database with the contents of a .csv file.

    The intended use is with a description of the AndroZoo dataset (https://androzoo.uni.lu/),
    but any csv file with the correct columns will work.
    Please refer to https://androzoo.uni.lu/lists for a documentation on the format.

    Parameters
    ----------
    filepath : str
        The path to a csv file containing the information to populate the database with.
    db_connection : db.Connection

    Returns
    -------
    int
        Number of rows in the table after population.
    """
    if filepath is None or filepath == '':
        logger.fatal('No input file found.')
        sys.exit('No input file found.')
    if not os.path.isfile(filepath):
        logger.fatal(f'File "{filepath}" not found.')
        sys.exit(f'File "{filepath}" not found.')
    cursor = db_connection.cursor()
    try:
        cursor.execute(
            "CREATE TABLE androzoo_apks (sha256 varchar PRIMARY KEY, dex_date date, apk_size int,"
            " pkg_name varchar, version_code int, vt_detection int, vt_date date, dex_size int,"
            " markets varchar[]);")
        db_connection.commit()
        logger.info('Successfully created table "androzoo_apks"')
    except db.Error:
        db_connection.rollback()
        cursor.execute("SELECT sha256 FROM androzoo_apks;")
        apks = cursor.rowcount
        logger.info(
            f'Table "androzoo_apks" was already present with {apks} rows but will be updated with new apks.'
        )
        cursor.execute("DROP TABLE androzoo_apks;")
        cursor.execute(
            "CREATE TABLE androzoo_apks (sha256 varchar PRIMARY KEY, dex_date date, apk_size int,"
            " pkg_name varchar, version_code int, vt_detection int, vt_date date, dex_size int,"
            " markets varchar[]);")
        db_connection.commit()
        logger.info('Successfully recreated table "androzoo_apks"')
    start = time.monotonic_ns()
    with gzip.open(filepath, 'rt') as csv_file:
        count = 0
        for row in csv.DictReader(csv_file, skipinitialspace=True):
            if ',' in row['sha256']:
                continue
            cursor.execute(
                "INSERT INTO androzoo_apks (sha256, dex_date, apk_size, pkg_name, version_code, vt_detection, vt_date,"
                " dex_size, markets) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s) ON CONFLICT DO NOTHING;",
                (row['sha256'], row['dex_date'], int(row['apk_size'])
                 if row['apk_size'] else None, row['pkg_name'],
                 int(row['vercode']) if row['vercode'] else None,
                 int(row['vt_detection']) if row['vt_detection'] else None,
                 row['vt_scan_date'] if row['vt_scan_date'] else None,
                 int(row['dex_size']) if row['dex_size'] else None,
                 [market for market in row['markets'].split('|')]))
            count += 1
            if count % 10000 == 0:
                logger.info(
                    f'Completed {count} rows. Took {convert_time(time.monotonic_ns() - start)}'
                )
    db_connection.commit()
    cursor.execute("SELECT sha256 FROM androzoo_apks;")
    size = cursor.rowcount
    cursor.close()
    logger.info(
        f'Successfully populated "androzoo_apks" with {size} rows. Took'
        f' {convert_time(time.monotonic_ns() - start)}.')
    try:
        directory = os.path.dirname(csv_file)
        if directory.startswith('/tmp'):
            shutil.rmtree(directory, ignore_errors=True)
            logger.info('Successfully removed csv file after population.')
        else:
            logger.info(
                f'{directory} is not a tmp-directory, skipping removal.')
    except Exception as error:
        logger.error(f'Removing csv file failed: {repr(error)}')
    return size


def create_random_sample(file_path, db_connection):
    sample_size = 250
    bins = ['>30'] + [f'={num}' for num in range(30, 9, -1)]
    cursor = db_connection.cursor()
    with open(file_path, 'w') as file:
        for cmp in bins:
            cursor.execute(
                f"SELECT sha256 FROM androzoo_apks WHERE vt_detection{cmp};")
            sample = random.sample(
                k=min(sample_size, cursor.rowcount),
                population=[row[0] for row in cursor.fetchall()])
            for s in sample:
                file.write(f'{s}\n')
    cursor.close()


def store_random_sample(file_path, db_connection):
    cursor = db_connection.cursor()
    try:
        cursor.execute("CREATE TABLE vt_samples (sha256 varchar PRIMARY KEY);")
    except db.Error:
        db_connection.rollback()
        cursor.execute("SELECT sha256 FROM vt_samples;")
        logger.error(
            f'"vt_samples" already existed with {cursor.rowcount} rows, replacing with new random sample.'
        )
        cursor.close()
        cursor.execute("DROP TABLE vt_samples;")
        cursor.execute("CREATE TABLE vt_samples (sha256 varchar PRIMARY KEY);")
        db_connection.commit()
    with open(file_path, 'r') as file:
        inserted = 0
        for line in file:
            cursor.execute("INSERT INTO vt_samples (sha256) VALUES (%s);",
                           ((line.strip(), )))
            inserted += 1
        logger.info(f'Inserted {inserted} rows into "vt_samples"')
    db_connection.commit()
    cursor.close()


def create_db(args):
    try:
        db_connection = db.connect(db_string)
    except db.Error as error:
        logger.fatal(
            f'Could not establish a connection to the database: {repr(error)}')
        sys.exit(error)
    if args.local:
        csv_file = os.path.abspath(args.local)
        if not os.path.isfile(csv_file):
            sys.exit(f'Specified file {csv_file} is not a file!')
    else:
        csv_file = download_csv()
    populate(csv_file, db_connection)
    file_path = os.path.abspath(args.file)
    if args.sample:
        create_random_sample(file_path, db_connection)
    store_random_sample(file_path, db_connection)
    db_connection.close()


def create():
    """Function to create the table underlying the analysis.

    Sufficient to be called once, but it is safe to be called multiple times.

    Returns
    -------
    int
        The number of rows in the table.
    """
    try:
        db_connection = db.connect(db_string)
    except db.Error as error:
        log_psycopg2_exception(error, logger)
        logger.fatal('Could not establish a connection to the database.')
        sys.exit('Could not establish a connection to the database.')
    cursor = db_connection.cursor()
    try:
        cursor.execute(
            "CREATE TABLE google_play_apks (sha256 varchar PRIMARY KEY, dex_date date, apk_size int,"
            " pkg_name varchar, version_code int, author varchar, category varchar, stars double precision,"
            " downloads varchar, has_ads bool);")
        db_connection.commit()
        logger.info('Successfully created table "google_play_apks"')
    except db.Error:
        db_connection.rollback()
        cursor.execute("SELECT sha256 FROM google_play_apks;")
        apks = cursor.rowcount
        logger.info(
            f'Table "google_play_apks" was already present with {apks} rows')
    try:
        cursor.execute(
            "CREATE TABLE results (sha256 varchar PRIMARY KEY, permissions varchar[], libs int,"
            " dex_loader int, class_loader int, reflection int, reflection_invocation int,"
            " methods_total int, methods_success int, methods_decompiler_fail int,"
            " methods_parser_fail int, analyzed int, anomalies int, skipped int);"
        )
        db_connection.commit()
        logger.info('Successfully created table "results"')
    except db.Error:
        db_connection.rollback()
        cursor.execute("SELECT sha256 FROM results;")
        logger.info(
            f'Table "results" was already present with {cursor.rowcount} rows')
    try:
        cursor.execute(
            "CREATE TABLE files (sha256 varchar, origin varchar, name varchar, entropy double precision,"
            " magic varchar, size int, PRIMARY KEY (sha256, origin));")
        db_connection.commit()
        logger.info('Successfully created table "files"')
    except db.Error:
        db_connection.rollback()
        cursor.execute("SELECT sha256 FROM files;")
        logger.info(
            f'Table "files" was already present with {cursor.rowcount} rows')
    try:
        cursor.execute(
            "CREATE TABLE apkid (sha256 varchar PRIMARY KEY, apkid json, error varchar);"
        )
        db_connection.commit()
        logger.info('Successfully created table "apkid"')
    except db.Error:
        db_connection.rollback()
        cursor.execute("SELECT sha256 FROM apkid;")
        logger.info(
            f'Table "apkid" was already present with {cursor.rowcount} rows')
    try:
        cursor.execute(
            "CREATE TABLE vt (sha256 varchar PRIMARY KEY, vt json, error varchar);"
        )
        db_connection.commit()
        logger.info('Successfully created table "vt"')
    except db.Error:
        db_connection.rollback()
        cursor.execute("SELECT sha256 FROM vt;")
        logger.info(
            f'Table "vt" was already present with {cursor.rowcount} rows')
    try:
        cursor.execute(
            "CREATE TABLE errors (sha256 varchar PRIMARY KEY, error varchar, partial bool);"
        )
        db_connection.commit()
        logger.info('Successfully created table "errors"')
    except db.Error:
        db_connection.rollback()
        cursor.execute("SELECT sha256 FROM errors;")
        logger.info(
            f'Table "errors" was already present with {cursor.rowcount} rows')
    try:
        cursor.execute(
            "CREATE TABLE accessed_classes (sha256 varchar PRIMARY KEY, libraries json,"
            " loaded_classes json);")
        db_connection.commit()
        logger.info('Successfully created table "accessed_classes"')
    except db.Error:
        db_connection.rollback()
        cursor.execute("SELECT sha256 FROM accessed_classes;")
        logger.info(
            f'Table "accessed_classes" was already present with {cursor.rowcount} rows'
        )
    try:
        cursor.execute(
            "CREATE TABLE reflection (sha256 varchar PRIMARY KEY, reflected_classes json,"
            " reflected_methods json);")
        db_connection.commit()
        logger.info('Successfully created table "reflection"')
    except db.Error:
        db_connection.rollback()
        cursor.execute("SELECT sha256 FROM reflection;")
        logger.info(
            f'Table "reflection" was already present with {cursor.rowcount} rows'
        )
    try:
        cursor.execute(
            "CREATE TABLE anomalies (sha256 varchar PRIMARY KEY, anomalies json);"
        )
        db_connection.commit()
        logger.info('Successfully created table "anomalies"')
    except db.Error:
        db_connection.rollback()
        cursor.execute("SELECT sha256 FROM anomalies;")
        logger.info(
            f'Table "anomalies" was already present with {cursor.rowcount} rows'
        )
    try:
        cursor.execute(
            "CREATE TABLE dex_loaders (sha256 varchar PRIMARY KEY, BaseDex int, Dex int, InMemory int,"
            " Path int, DelegateLast int);")
        db_connection.commit()
        logger.info('Successfully created table "dex_loaders"')
    except db.Error:
        db_connection.rollback()
        cursor.execute("SELECT sha256 FROM dex_loaders;")
        logger.info(
            f'Table "dex_loaders" was already present with {cursor.rowcount} rows'
        )
    try:
        cursor.execute(
            "CREATE TABLE fdroid (sha256 varchar PRIMARY KEY, name varchar, version int);"
        )
        db_connection.commit()
        logger.info('Successfully created table "fdroid"')
    except db.Error:
        db_connection.rollback()
        cursor.execute("SELECT sha256 FROM fdroid;")
        logger.info(
            f'Table "fdroid" was already present with {cursor.rowcount} rows')
    cursor.close()
    db_connection.close()


def access(query, args=None, db_connection=None):
    if db_connection is None:
        try:
            db_connection = db.connect(db_string)
        except db.Error as error:
            logger.fatal('Could not establish a connection to the database.')
            return
    cursor = db_connection.cursor()
    if args:
        cursor.execute(query, args)
    else:
        cursor.execute(query)
    for row in cursor:
        yield row
    db_connection.commit()


def store_result(sha256,
                 permissions,
                 libraries,
                 dex_loaders,
                 class_loaders,
                 reflection_access,
                 reflection_invocations,
                 method_count,
                 methods_success,
                 method_parser_failed,
                 method_decompiler_failed,
                 db_connection=None):
    if db_connection is None:
        try:
            db_connection = db.connect(db_string)
        except db.Error as error:
            logger.fatal('Could not establish a connection to the database.')
            raise DatabaseRetry(error, store_result, sha256, permissions,
                                libraries, dex_loaders, class_loaders,
                                reflection_access, reflection_invocations,
                                method_count, methods_success,
                                method_parser_failed, method_decompiler_failed)
    cursor = db_connection.cursor()
    try:
        cursor.execute(
            "INSERT INTO results (sha256, permissions, libs, dex_loader, class_loader, reflection,"
            " reflection_invocation, methods_total, methods_success, methods_decompiler_fail,"
            " methods_parser_fail) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) ON CONFLICT"
            " DO NOTHING;",
            (sha256, permissions, libraries, dex_loaders, class_loaders,
             reflection_access, reflection_invocations, method_count,
             methods_success, method_decompiler_failed, method_parser_failed))
        db_connection.commit()
        cursor.close()
    except db.Error as error:
        db_connection.rollback()
        cursor.close()
        raise DatabaseRetry(error, store_result, sha256, permissions,
                            libraries, dex_loaders, class_loaders,
                            reflection_access, reflection_invocations,
                            method_count, methods_success,
                            method_parser_failed, method_decompiler_failed)


def store_vt(sha256, vt_data, db_connection=None):
    if db_connection is None:
        try:
            db_connection = db.connect(db_string)
        except db.Error as error:
            logger.error('Could not establish a connection to the database.')
            raise DatabaseRetry(error, store_vt, sha256, vt_data)
    cursor = db_connection.cursor()
    try:
        cursor.execute(
            "INSERT INTO vt (sha256, vt) VALUES (%s, %s) ON CONFLICT DO NOTHING;",
            (sha256, vt_data))
        db_connection.commit()
        cursor.close()
    except db.Error as error:
        db_connection.rollback()
        cursor.close()
        raise DatabaseRetry(error, store_vt, sha256, vt_data)


def store_vt_error(sha256, error, db_connection=None):
    if db_connection is None:
        try:
            db_connection = db.connect(db_string)
        except db.Error as error:
            logger.error('Could not establish a connection to the database.')
            raise DatabaseRetry(error, store_vt_error, sha256, error)
    cursor = db_connection.cursor()
    try:
        cursor.execute(
            "INSERT INTO vt (sha256, error) VALUES (%s, %s) ON CONFLICT DO NOTHING;",
            (sha256, error))
        db_connection.commit()
        cursor.close()
    except db.Error as error:
        db_connection.rollback()
        cursor.close()
        raise DatabaseRetry(error, store_vt_error, sha256, error)


def store_google_play_app(sha256,
                          dex_date,
                          size,
                          pkg_name,
                          version,
                          author,
                          category,
                          stars,
                          downloads,
                          has_ads,
                          db_connection=None):
    if db_connection is None:
        try:
            db_connection = db.connect(db_string)
        except db.Error as error:
            logger.error('Could not establish a connection to the database.')
            raise DatabaseRetry(error, store_google_play_app, sha256, dex_date,
                                size, pkg_name, version, author, category,
                                stars, downloads, has_ads)
    cursor = db_connection.cursor()
    try:
        cursor.execute(
            "INSERT INTO google_play_apks (sha256, dex_date, apk_size, pkg_name, version_code, author,"
            " category, stars, downloads, has_ads) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s) ON"
            " CONFLICT DO NOTHING;",
            (sha256, dex_date, size, pkg_name, version, author, category,
             stars, downloads, has_ads))
        db_connection.commit()
        cursor.close()
    except db.Error as error:
        db_connection.rollback()
        cursor.close()
        raise DatabaseRetry(error, store_google_play_app, sha256, dex_date,
                            size, pkg_name, version, author, category, stars,
                            downloads, has_ads)


def store_library_access(sha256, loaded_libs, db_connection=None):
    logger.debug(
        f'{sha256} loads the following libs:\n{pprint.pformat(loaded_libs)}')
    if db_connection is None:
        try:
            db_connection = db.connect(db_string)
        except db.Error as error:
            logger.error('Could not establish a connection to the database.')
            raise DatabaseRetry(error, store_library_access, sha256,
                                loaded_libs)
    cursor = db_connection.cursor()
    try:
        cursor.execute(
            "INSERT INTO accessed_classes (sha256, libraries) VALUES (%s, %s) ON CONFLICT DO NOTHING;",
            (sha256, json.dumps(loaded_libs)))
        db_connection.commit()
        cursor.close()
    except db.Error as error:
        db_connection.rollback()
        cursor.close()
        raise DatabaseRetry(error, store_library_access, sha256, loaded_libs)


def store_dex_loader_access(sha256, dex_loaders, db_connection=None):
    logger.debug(
        f'{sha256} uses the following dex_loaders:\n{pprint.pformat(dex_loaders)}'
    )
    if db_connection is None:
        try:
            db_connection = db.connect(db_string)
        except db.Error as error:
            logger.error('Could not establish a connection to the database.')
            raise DatabaseRetry(error, store_dex_loader_access, sha256,
                                dex_loaders)
    cursor = db_connection.cursor()
    try:
        cursor.execute(
            "INSERT INTO dex_loaders (sha256, BaseDex, Dex, InMemory, Path, DelegateLast) VALUES"
            " (%s, %s, %s, %s, %s, %s) ON CONFLICT DO NOTHING;",
            (sha256, dex_loaders["Ldalvik/system/BaseDexClassLoader;"],
             dex_loaders["Ldalvik/system/DexClassLoader;"],
             dex_loaders["Ldalvik/system/InMemoryDexClassLoader;"],
             dex_loaders["Ldalvik/system/PathClassLoader;"],
             dex_loaders["Ldalvik/system/DelegateLastClassLoader;"]))
        db_connection.commit()
        cursor.close()
    except db.Error as error:
        db_connection.rollback()
        cursor.close()
        raise DatabaseRetry(error, store_dex_loader_access, sha256,
                            dex_loaders)


def full_error(sha256, error_str, partial=False, db_connection=None):
    if db_connection is None:
        try:
            db_connection = db.connect(db_string)
        except db.Error as error:
            logger.error('Could not establish a connection to the database.')
            raise DatabaseRetry(error, full_error, sha256, error_str, partial)
    cursor = db_connection.cursor()
    try:
        cursor.execute(
            "INSERT INTO errors (sha256, error, partial) VALUES (%s, %s, %s) ON CONFLICT DO NOTHING;",
            (sha256, error_str, partial))
        db_connection.commit()
        cursor.close()
    except db.Error as error:
        db_connection.rollback()
        cursor.close()
        raise DatabaseRetry(error, full_error, sha256, error_str, partial)


def store_apkid_result(sha256, apkid, db_connection=None):
    if db_connection is None:
        try:
            db_connection = db.connect(db_string)
        except db.Error as error:
            logger.error('Could not establish a connection to the database.')
            raise DatabaseRetry(error, store_apkid_result, sha256, apkid)
    cursor = db_connection.cursor()
    try:
        cursor.execute(
            "INSERT INTO apkid (sha256, apkid) VALUES (%s, %s) ON CONFLICT DO NOTHING;",
            (sha256, apkid))
        db_connection.commit()
        cursor.close()
    except db.Error as error:
        db_connection.rollback()
        cursor.close()
        raise DatabaseRetry(error, store_apkid_result, sha256, apkid)


def apkid_error(sha256, error, error_text, db_connection=None):
    if db_connection is None:
        try:
            db_connection = db.connect(db_string)
        except db.Error as error:
            logger.error('Could not establish a connection to the database.')
            raise DatabaseRetry(error, apkid_error, sha256, error, error_text)
    cursor = db_connection.cursor()
    try:
        if error_text:
            error_str = error + ':\t' + error_text
        else:
            error_str = error
        cursor.execute(
            "INSERT INTO apkid (sha256, error) VALUES (%s, %s) ON CONFLICT DO NOTHING;",
            (sha256, error_str))
        db_connection.commit()
        cursor.close()
    except db.Error as error:
        db_connection.rollback()
        cursor.close()
        raise DatabaseRetry(error, apkid_error, sha256, error, error_text)


def store_class_loader_access(sha256, loaded_classes, db_connection=None):
    logger.debug(
        f'{sha256} loads the following classes:\n{pprint.pformat(loaded_classes)}'
    )
    if db_connection is None:
        try:
            db_connection = db.connect(db_string)
        except db.Error as error:
            logger.error('Could not establish a connection to the database.')
        raise DatabaseRetry(error, store_class_loader_access, sha256,
                            loaded_classes)
    cursor = db_connection.cursor()
    try:
        cursor.execute(
            "UPDATE accessed_classes SET loaded_classes = %s WHERE sha256 = %s;",
            (json.dumps(loaded_classes), sha256))
        db_connection.commit()
        cursor.close()
    except db.Error as error:
        db_connection.rollback()
        cursor.close()
        raise DatabaseRetry(error, store_class_loader_access, sha256,
                            loaded_classes)


def store_files(sha256, files, db_connection=None):
    if db_connection is None:
        try:
            db_connection = db.connect(db_string)
        except db.Error as error:
            logger.error('Could not establish a connection to the database.')
            raise DatabaseRetry(error, store_files, sha256, files)
    cursor = db_connection.cursor()
    try:
        for file_sha256, file_name, entropy, magic, size in files:
            cursor.execute(
                "INSERT INTO files (sha256, origin, name, entropy, magic, size) VALUES"
                "(%s, %s, %s, %s, %s, %s) ON CONFLICT DO NOTHING;",
                (file_sha256, sha256, file_name, entropy, magic, size))
        db_connection.commit()
        cursor.close()
    except db.Error as error:
        db_connection.rollback()
        cursor.close()
        raise DatabaseRetry(error, store_files, sha256, files)


def record_timeout(sha256, error, db_connection=None):
    full_error(sha256, error, False, db_connection)


def partial_error(sha256, error, db_connection=None):
    full_error(sha256, error, True, db_connection)


def store_anomalies(sha256, anomalies, db_connection=None):
    if db_connection is None:
        try:
            db_connection = db.connect(db_string)
        except db.Error as error:
            logger.error('Could not establish a connection to the database.')
            raise DatabaseRetry(error, store_anomalies, sha256, anomalies)
    cursor = db_connection.cursor()
    try:
        cursor.execute(
            "INSERT INTO anomalies (sha256, anomalies) VALUES (%s, %s) ON CONFLICT DO NOTHING;",
            (sha256, json.dumps(anomalies)))
        db_connection.commit()
        cursor.close()
    except db.Error as error:
        cursor.close()
        db_connection.rollback()
        raise DatabaseRetry(error, store_anomalies, sha256, anomalies)


def store_reflection_information(sha256,
                                 reflected_classes,
                                 reflected_methods,
                                 db_connection=None):
    logger.debug(
        f'{sha256} uses the following classes for reflection\n{pprint.pformat(reflected_classes)}'
    )
    if db_connection is None:
        try:
            db_connection = db.connect(db_string)
        except db.Error as error:
            logger.error('Could not establish a connection to the database.')
            raise DatabaseRetry(error, store_reflection_information, sha256,
                                reflected_classes, reflected_methods)
    cursor = db_connection.cursor()
    try:
        cursor.execute(
            "INSERT INTO reflection (sha256, reflected_classes, reflected_methods) VALUES (%s, %s, %s)"
            " ON CONFLICT DO NOTHING;",
            (sha256, json.dumps(reflected_classes, cls=Encoder),
             json.dumps(reflected_methods, cls=Encoder)))
        db_connection.commit()
        cursor.close()
    except db.Error as error:
        db_connection.rollback()
        cursor.close()
        raise DatabaseRetry(error, store_reflection_information, sha256,
                            reflected_classes, reflected_methods)


def store_anomaly_overview(sha256,
                           analyzed,
                           anomalies,
                           skipped,
                           db_connection=None):
    if db_connection is None:
        try:
            db_connection = db.connect(db_string)
        except db.Error as error:
            logger.error('Could not establish a connection to the database.')
            raise DatabaseRetry(error, store_anomaly_overview, sha256,
                                analyzed, anomalies, skipped)
    cursor = db_connection.cursor()
    try:
        cursor.execute(
            "UPDATE results SET (analyzed, anomalies, skipped) = (%s, %s, %s) WHERE sha256 = %s;",
            (analyzed, anomalies, skipped, sha256))
        db_connection.commit()
        cursor.close()
    except db.Error as error:
        db_connection.rollback()
        cursor.close()
        raise DatabaseRetry(error, store_anomaly_overview, sha256, analyzed,
                            anomalies, skipped)


def store_fdroid_app(sha256, package_name, version, db_connection=None):
    if db_connection is None:
        try:
            db_connection = db.connect(db_string)
        except db.Error as error:
            logger.error('Could not establish a connection to the database.')
            raise DatabaseRetry(error, store_fdroid_app, sha256, package_name,
                                version)
    cursor = db_connection.cursor()
    try:
        cursor.execute(
            "INSERT INTO fdroid (sha256, name, version) VALUES (%s, %s, %s) ON CONFLICT DO NOTHING;",
            (sha256, package_name, int(version)))
        db_connection.commit()
        cursor.close()
    except db.Error as error:
        db_connection.rollback()
        cursor.close()
        raise DatabaseRetry(error, store_fdroid_app, sha256, package_name,
                            version)


def store_fdroid_hash(sha256):
    store_fdroid_app(sha256, None, None)
