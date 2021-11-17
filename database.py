import csv
import json
import logging
import os
import pprint
import sys
import time

import psycopg2 as db

import utility.convenience
from compatibility.json import Encoder

logger = logging.getLogger('postgreSQL')
logger.setLevel(logging.NOTSET)

db_string = 'dbname=malware user=postgres host=0.0.0.0'


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
    except db.Error:
        logger.fatal('Could not establish a connection to the database.')
        sys.exit('Could not establish a connection to the database.')
    cursor = db_connection.cursor()
    try:
        cursor.execute("CREATE TABLE androzoo_apks (sha256 varchar PRIMARY KEY, dex_date date, apk_size int,"
                       " pkg_name varchar, version_code int, vt_detection int, vt_date date, dex_size int,"
                       " markets varchar[]);")
        db_connection.commit()
        logger.info('Successfully created table "androzoo_apks"')
    except db.Error:
        db_connection.rollback()
        cursor.execute("SELECT sha256 FROM androzoo_apks;")
        apks = cursor.rowcount
        logger.info(f'Table "androzoo_apks" was already present with {apks} rows')
    try:
        cursor.execute("CREATE TABLE google_play_apks (sha256 varchar PRIMARY KEY, dex_date date, apk_size int,"
                       " pkg_name varchar, version_code int, author varchar, category varchar, stars double precision,"
                       " downloads varchar, has_ads bool);")
        db_connection.commit()
        logger.info('Successfully created table "google_play_apks"')
    except db.Error:
        db_connection.rollback()
        cursor.execute("SELECT sha256 FROM google_play_apks;")
        apks = cursor.rowcount
        logger.info(f'Table "google_play_apks" was already present with {apks} rows')
    try:
        cursor.execute("CREATE TABLE results (sha256 varchar PRIMARY KEY, permissions varchar[], libs int,"
                       " dex_loader int, class_loader int, reflection int, reflection_invocation int,"
                       " methods_total int, methods_success int, methods_decompiler_fail int,"
                       " methods_parser_fail int, anomalies int, skipped int);")
        db_connection.commit()
        logger.info('Successfully created table "results"')
    except db.Error:
        db_connection.rollback()
        cursor.execute("SELECT sha256 FROM results;")
        logger.info(f'Table "results" was already present with {cursor.rowcount} rows')
    try:
        cursor.execute("CREATE TABLE files (sha256 varchar, origin varchar, name varchar, entropy double precision,"
                       " magic varchar, size int, PRIMARY KEY (sha256, origin));")
        db_connection.commit()
        logger.info('Successfully created table "files"')
    except db.Error:
        db_connection.rollback()
        cursor.execute("SELECT sha256 FROM files;")
        logger.info(f'Table "files" was already present with {cursor.rowcount} rows')
    try:
        cursor.execute("CREATE TABLE apkid (sha256 varchar PRIMARY KEY, apkid json, error varchar);")
        db_connection.commit()
        logger.info('Successfully created table "apkid"')
    except db.Error:
        db_connection.rollback()
        cursor.execute("SELECT sha256 FROM apkid;")
        logger.info(f'Table "apkid" was already present with {cursor.rowcount} rows')
    try:
        cursor.execute("CREATE TABLE vt (sha256 varchar PRIMARY KEY, vt json, error varchar);")
        db_connection.commit()
        logger.info('Successfully created table "vt"')
    except db.Error:
        db_connection.rollback()
        cursor.execute("SELECT sha256 FROM vt;")
        logger.info(f'Table "vt" was already present with {cursor.rowcount} rows')
    try:
        cursor.execute("CREATE TABLE errors (sha256 varchar PRIMARY KEY, error varchar, partial bool);")
        db_connection.commit()
        logger.info('Successfully created table "errors"')
    except db.Error:
        db_connection.rollback()
        cursor.execute("SELECT sha256 FROM errors;")
        logger.info(f'Table "errors" was already present with {cursor.rowcount} rows')
    try:
        cursor.execute("CREATE TABLE accessed_classes (sha256 varchar PRIMARY KEY, libraries json,"
                       " loaded_classes json);")
        db_connection.commit()
        logger.info('Successfully created table "accessed_classes"')
    except db.Error:
        db_connection.rollback()
        cursor.execute("SELECT sha256 FROM accessed_classes;")
        logger.info(f'Table "accessed_classes" was already present with {cursor.rowcount} rows')
    try:
        cursor.execute("CREATE TABLE reflection (sha256 varchar PRIMARY KEY, reflected_classes json,"
                       " reflected_methods json);")
        db_connection.commit()
        logger.info('Successfully created table "reflection"')
    except db.Error:
        db_connection.rollback()
        cursor.execute("SELECT sha256 FROM reflection;")
        logger.info(f'Table "reflection" was already present with {cursor.rowcount} rows')
    try:
        cursor.execute("CREATE TABLE anomalies (sha256 varchar PRIMARY KEY, anomalies json);")
        db_connection.commit()
        logger.info('Successfully created table "anomalies"')
    except db.Error:
        db_connection.rollback()
        cursor.execute("SELECT sha256 FROM anomalies;")
        logger.info(f'Table "anomalies" was already present with {cursor.rowcount} rows')
    try:
        cursor.execute("CREATE TABLE dex_loaders (sha256 varchar PRIMARY KEY, BaseDex int, Dex int, InMemory int,"
                       " Path int, DelegateLast int);")
        db_connection.commit()
        logger.info('Successfully created table "dex_loaders"')
    except db.Error:
        db_connection.rollback()
        cursor.execute("SELECT sha256 FROM dex_loaders;")
        logger.info(f'Table "errors" was already present with {cursor.rowcount} rows')
    try:
        cursor.execute("CREATE TABLE method_bins (sha256 varchar PRIMARY KEY, bin_empty int, bin_1 int, bin_2 int,"
                       " bin_3 int, bin_4 int, bin_5 int, bin_6 int, bin_7 int, bin_8 int, bin_9 int, bin_10 int,"
                       " bin_11 int, bin_12 int, bin_13 int, bin_14 int, bin_15 int, bin_16 int, bin_17 int,"
                       " bin_18 int, bin_19 int, bin_20 int, bin_21 int, bin_22 int, bin_23 int, bin_24 int,"
                       " bin_25 int, bin_26 int, bin_27 int, bin_28 int, bin_29 int, bin_30 int, bin_31 int,"
                       " bin_32 int, bin_33 int, bin_34 int, bin_35 int, bin_36 int, bin_37 int, bin_38 int,"
                       " bin_39 int, bin_40 int, bin_41 int, bin_42 int, bin_43 int, bin_44 int, bin_45 int,"
                       " bin_46 int, bin_47 int, bin_48 int, bin_49 int, bin_50 int, bin_51 int, bin_52 int,"
                       " bin_53 int, bin_54 int, bin_55 int, bin_56 int, bin_57 int, bin_58 int, bin_59 int,"
                       " bin_60 int, bin_61 int, bin_62 int, bin_63 int, bin_64 int, bin_65 int, bin_66 int,"
                       " bin_67 int, bin_68 int, bin_69 int, bin_70 int, bin_71 int, bin_72 int, bin_73 int,"
                       " bin_74 int, bin_75 int, bin_76 int, bin_77 int, bin_78 int, bin_79 int, bin_80 int,"
                       " bin_81 int, bin_82 int, bin_83 int, bin_84 int, bin_85 int, bin_86 int, bin_87 int,"
                       " bin_88 int, bin_89 int, bin_90 int, bin_91 int, bin_92 int, bin_93 int, bin_94 int,"
                       " bin_95 int, bin_96 int, bin_97 int, bin_98 int, bin_99 int, bin_100 int);")
        db_connection.commit()
        logger.info('Successfully created table "method_bins"')
    except db.Error:
        db_connection.rollback()
        cursor.execute("SELECT sha256 FROM method_bins;")
        logger.info(f'Table "method_bins" was already present with {cursor.rowcount} rows')
    cursor.close()
    db_connection.close()


def populate(filepath):
    """Populates the database with the contents of a .csv file.

    The intended use is with a description of the AndroZoo dataset (https://androzoo.uni.lu/),
    but any csv file with the correct columns will work.
    Please refer to https://androzoo.uni.lu/lists for a documentation on the format.

    Parameters
    ----------
    filepath : str
        The path to a csv file containing the information to populate the database with.

    Returns
    -------
    int
        Number of rows in the table after population.
    """
    if filepath is None or filepath == '':
        logger.error('No input file found.')
        sys.exit('No input file found.')
    if not os.path.isfile(filepath):
        logger.error(f'File "{filepath}" not found.')
        sys.exit(f'File "{filepath}" not found.')
    try:
        db_connection = db.connect(db_string)
    except db.Error:
        logger.error('Could not establish a connection to the database.')
        sys.exit('Could not establish a connection to the database.')
    cursor = db_connection.cursor()
    start = time.time()
    with open(filepath, 'r') as csv_file:
        for row in csv.DictReader(csv_file, skipinitialspace=True):
            cursor.execute(
                "INSERT INTO androzoo_apks (sha256, dex_date, apk_size, pkg_name, version_code, vt_detection, vt_date,"
                " dex_size, markets) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s);",
                (row['sha256'],
                 row['dex_date'],
                 int(row['apk_size']) if row['apk_size'] else None,
                 row['pkg_name'],
                 int(row['vercode']) if row['vercode'] else None,
                 int(row['vt_detection']) if row['vt_detection'] else None,
                 row['vt_scan_date'] if row['vt_scan_date'] else None,
                 int(row['dex_size']) if row['dex_size'] else None,
                 [market for market in row['markets'].split('|')]))
    db_connection.commit()
    cursor.execute("SELECT * FROM androzoo_apks;")
    size = cursor.rowcount
    cursor.close()
    db_connection.close()
    logger.info(f'Successfully populated "apks" with {size} rows. Took {time.time() - start}s')
    return size


def access(query, args=None):
    try:
        db_connection = db.connect(db_string)
    except db.Error:
        logger.fatal('Could not establish a connection to the database.')
        sys.exit('Could not establish a connection to the database.')
    cursor = db_connection.cursor()
    if args:
        cursor.execute(query, args)
    else:
        cursor.execute(query)
    for row in cursor:
        yield row
    db_connection.commit()


def store_result(sha256, permissions, libraries, dex_loaders, class_loaders, reflection_access, reflection_invocations,
                 method_count, methods_success, method_parser_failed, method_decompiler_failed):
    try:
        db_connection = db.connect(db_string)
    except db.Error:
        logger.fatal('Could not establish a connection to the database.')
        sys.exit('Could not establish a connection to the database.')
    cursor = db_connection.cursor()
    try:
        cursor.execute("INSERT INTO results (sha256, permissions, libs, dex_loader, class_loader, reflection,"
                       " reflection_invocation, methods_total, methods_success, methods_decompiler_fail,"
                       " methods_parser_fail) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) ON CONFLICT"
                       " DO NOTHING;",
                       (sha256, permissions, libraries, dex_loaders, class_loaders, reflection_access,
                        reflection_invocations, method_count, methods_success, method_decompiler_failed,
                        method_parser_failed))
        db_connection.commit()
        return
    except db.Error as error:
        db_connection.rollback()
        logger.fatal(f'Could not store results for {sha256}: {repr(error)}')


def store_vt(sha256, vt_data):
    try:
        db_connection = db.connect(db_string)
    except db.Error:
        logger.error('Could not establish a connection to the database.')
        return
    cursor = db_connection.cursor()
    try:
        cursor.execute("INSERT INTO vt (sha256, vt) VALUES (%s, %s) ON CONFLICT DO NOTHING;",
                       (sha256, vt_data))
        db_connection.commit()
    except db.Error:
        db_connection.rollback()
        logger.fatal(f'Could not store VirusTotal data for {sha256}')


def store_vt_error(sha256, error):
    try:
        db_connection = db.connect(db_string)
    except db.Error:
        logger.error('Could not establish a connection to the database.')
        return
    cursor = db_connection.cursor()
    try:
        cursor.execute("INSERT INTO vt (sha256, error) VALUES (%s, %s) ON CONFLICT DO NOTHING;",
                       (sha256, error))
        db_connection.commit()
    except db.Error:
        db_connection.rollback()
        logger.fatal(f'Could not store VirusTotal error for {sha256}')


def store_method_sizes(sha256, bins):
    try:
        db_connection = db.connect(db_string)
    except db.Error:
        logger.error('Could not establish a connection to the database.')
        return
    cursor = db_connection.cursor()
    try:
        cursor.execute("INSERT INTO method_bins (sha256, bin_empty, bin_1, bin_2, bin_3, bin_4, bin_5, bin_6, bin_7,"
                       " bin_8, bin_9, bin_10, bin_11, bin_12, bin_13, bin_14, bin_15, bin_16, bin_17, bin_18, bin_19,"
                       " bin_20, bin_21, bin_22, bin_23, bin_24, bin_25, bin_26, bin_27, bin_28, bin_29, bin_30,"
                       " bin_31, bin_32, bin_33, bin_34, bin_35, bin_36, bin_37, bin_38, bin_39, bin_40, bin_41,"
                       " bin_42, bin_43, bin_44, bin_45, bin_46, bin_47, bin_48, bin_49, bin_50, bin_51, bin_52,"
                       " bin_53, bin_54, bin_55, bin_56, bin_57, bin_58, bin_59, bin_60, bin_61, bin_62, bin_63,"
                       " bin_64, bin_65, bin_66, bin_67, bin_68, bin_69, bin_70, bin_71, bin_72, bin_73, bin_74,"
                       " bin_75, bin_76, bin_77, bin_78, bin_79, bin_80, bin_81, bin_82, bin_83, bin_84, bin_85,"
                       " bin_86, bin_87, bin_88, bin_89, bin_90, bin_91, bin_92, bin_93, bin_94, bin_95, bin_96,"
                       " bin_97, bin_98, bin_99, bin_100) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,"
                       " %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,"
                       " %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,"
                       " %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,"
                       " %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) ON CONFLICT"
                       " DO NOTHING;",
                       tuple([sha256] + [bins.get('bin_empty', 0)] +
                             list(bins.get(f'bin_{num}', 0) for num in range(1, 101))))
        db_connection.commit()
    except db.Error as error:
        db_connection.rollback()
        logger.error(error)
        logger.fatal(f'Could not store method sizes for {sha256}')


def store_google_play_app(sha256, dex_date, size, pkg_name, version, author, category, stars, downloads, has_ads):
    try:
        db_connection = db.connect(db_string)
    except db.Error:
        logger.error('Could not establish a connection to the database.')
        return
    cursor = db_connection.cursor()
    try:
        cursor.execute("INSERT INTO google_play_apks (sha256, dex_date, apk_size, pkg_name, version_code, author,"
                       " category, stars, downloads, has_ads) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s) ON"
                       " CONFLICT DO NOTHING;",
                       (sha256, dex_date, size, pkg_name, version, author, category, stars, downloads, has_ads))
        db_connection.commit()
    except db.Error as error:
        db_connection.rollback()
        logger.fatal(f'Could not store app info for Google Play app {sha256}')
        logger.fatal(error)


def store_library_access(sha256, loaded_libs):
    logger.debug(f'{sha256} loads the following libs:\n{pprint.pformat(loaded_libs)}')
    try:
        db_connection = db.connect(db_string)
    except db.Error:
        logger.error('Could not establish a connection to the database.')
        return
    cursor = db_connection.cursor()
    try:
        cursor.execute("INSERT INTO accessed_classes (sha256, libraries) VALUES (%s, %s) ON CONFLICT DO NOTHING;",
                       (sha256, json.dumps(loaded_libs)))
        db_connection.commit()
    except db.Error:
        db_connection.rollback()
        logger.fatal(f'Could not save accessed libraries for {sha256}')


def store_dex_loader_access(sha256, dex_loaders):
    logger.debug(f'{sha256} loads the following libs:\n{pprint.pformat(dex_loaders)}')
    try:
        db_connection = db.connect(db_string)
    except db.Error:
        logger.error('Could not establish a connection to the database.')
        return
    cursor = db_connection.cursor()
    try:
        cursor.execute("INSERT INTO dex_loaders (sha256, BaseDex, Dex, InMemory, Path, DelegateLast) VALUES"
                       " (%s, %s, %s, %s, %s, %s) ON CONFLICT DO NOTHING;",
                       (sha256,
                        dex_loaders["Ldalvik/system/BaseDexClassLoader;"],
                        dex_loaders["Ldalvik/system/DexClassLoader;"],
                        dex_loaders["Ldalvik/system/InMemoryDexClassLoader;"],
                        dex_loaders["Ldalvik/system/PathClassLoader;"],
                        dex_loaders["Ldalvik/system/DelegateLastClassLoader;"]))
        db_connection.commit()
    except db.Error:
        db_connection.rollback()
        logger.fatal(f'Could not save dex_loaders for {sha256}')


def full_error(sha256, error_str, partial=False):
    try:
        db_connection = db.connect(db_string)
    except db.Error:
        logger.error('Could not establish a connection to the database.')
        return
    cursor = db_connection.cursor()
    try:
        cursor.execute("INSERT INTO errors (sha256, error, partial) VALUES (%s, %s, %s) ON CONFLICT DO NOTHING;",
                       (sha256, error_str, partial))
        db_connection.commit()
    except db.Error:
        db_connection.rollback()
        logger.fatal(f'Could not save errors for {sha256}')


def store_apkid_result(sha256, apkid):
    try:
        db_connection = db.connect(db_string)
    except db.Error:
        logger.error('Could not establish a connection to the database.')
        return
    cursor = db_connection.cursor()
    try:
        cursor.execute("INSERT INTO apkid (sha256, apkid) VALUES (%s, %s) ON CONFLICT DO NOTHING;",
                       (sha256, apkid))
        db_connection.commit()
    except db.Error:
        db_connection.rollback()
        logger.fatal(f'Could not save apkid result for {sha256}')


def apkid_error(sha256, error, error_text):
    try:
        db_connection = db.connect(db_string)
    except db.Error:
        logger.error('Could not establish a connection to the database.')
        return
    cursor = db_connection.cursor()
    try:
        if error_text:
            error_str = error + ':\t' + error_text
        else:
            error_str = error
        cursor.execute("INSERT INTO apkid (sha256, error) VALUES (%s, %s) ON CONFLICT DO NOTHING;",
                       (sha256, error_str))
        db_connection.commit()
    except db.Error:
        db_connection.rollback()
        logger.fatal(f'Could not save apkid errors for {sha256}')


def store_class_loader_access(sha256, loaded_classes):
    logger.debug(f'{sha256} loads the following classes:\n{pprint.pformat(loaded_classes)}')
    try:
        db_connection = db.connect(db_string)
    except db.Error:
        logger.error('Could not establish a connection to the database.')
        return
    cursor = db_connection.cursor()
    try:
        cursor.execute("UPDATE accessed_classes SET loaded_classes = %s WHERE sha256 = %s;",
                       (json.dumps(loaded_classes), sha256))
        db_connection.commit()
    except db.Error:
        db_connection.rollback()
        logger.fatal(f'Could not save accessed classes for {sha256}')


def store_files(application_sha256, files):
    try:
        db_connection = db.connect(db_string)
    except db.Error:
        logger.error('Could not establish a connection to the database.')
        return
    cursor = db_connection.cursor()
    try:
        for sha256, entropy, magic, size in files:
            cursor.execute("INSERT INTO files (sha256, origin, entropy, magic, size) VALUES (%s, %s, %s, %s, %s)"
                           " ON CONFLICT DO NOTHING;",
                           (sha256, application_sha256, entropy, magic, size))
        db_connection.commit()
    except db.Error:
        db_connection.rollback()
        logger.fatal(f'Could not store file information for {application_sha256}')


def record_timeout(sha256, error):
    full_error(sha256, error)


def partial_error(sha256, error):
    full_error(sha256, error, True)


def store_anomalies(sha256, anomalies):
    try:
        db_connection = db.connect(db_string)
    except db.Error:
        logger.error('Could not establish a connection to the database.')
        return
    cursor = db_connection.cursor()
    try:
        cursor.execute("INSERT INTO anomalies (sha256, anomalies) VALUES (%s, %s) ON CONFLICT DO NOTHING;",
                       (sha256, json.dumps(anomalies)))
        db_connection.commit()
    except db.Error:
        db_connection.rollback()
        logger.fatal(f'Could not save anomalies errors for {sha256}')


def store_reflection_information(sha256, reflected_classes, reflected_methods):
    logger.log(utility.convenience.VERBOSE,
               f'{sha256} uses the following classes for reflection\n{pprint.pformat(reflected_classes)}')
    try:
        db_connection = db.connect(db_string)
    except db.Error:
        logger.error('Could not establish a connection to the database.')
        return
    cursor = db_connection.cursor()
    try:
        cursor.execute("INSERT INTO reflection (sha256, reflected_classes, reflected_methods) VALUES (%s, %s, %s)"
                       " ON CONFLICT DO NOTHING;", (sha256, json.dumps(reflected_classes, cls=Encoder),
                                                    json.dumps(reflected_methods, cls=Encoder)))
        db_connection.commit()
    except db.Error:
        db_connection.rollback()
        logger.fatal(f'Could not save reflection information for {sha256}')


def store_anomaly_overview(sha256, anomalies, skipped):
    try:
        db_connection = db.connect(db_string)
    except db.Error:
        logger.error('Could not establish a connection to the database.')
        return
    cursor = db_connection.cursor()
    try:
        cursor.execute("UPDATE results SET (anomalies, skipped) = (%s, %s) WHERE sha256 = %s;", (anomalies, skipped,
                                                                                                 sha256))
        db_connection.commit()
    except db.Error:
        db_connection.rollback()
        logger.fatal(f'Could not update results with anomaly information for {sha256}')