#!/usr/bin/env python3

import numpy as np
from scipy.sparse import csc_matrix, vstack
from sklearn.ensemble import IsolationForest
from androguard.misc import AnalyzeAPK
from compatibility.androguard import method2json_direct
from collections import Counter
import json
import os.path
import glob
from tqdm import tqdm
from multiprocessing import Pool
import gzip
import pickle
import argparse
import time
from cfganomaly import cfganomaly


def analyze_apk(arguments):
    apk, max_n, min_size, min_bbs = arguments

    results = []
    skipped = 0

    vectorizer = cfganomaly.NgramVectorizer(max_n=max_n)
    bin_sizes = Counter()

    a, d, dx = AnalyzeAPK(apk)
    for method in dx.find_methods():
        if method.is_external():
            continue

        if 2 * method.get_method().get_length() < min_size:
            skipped += 1
            continue

        meth_analysis = dx.get_method(method.get_method())
        g = json.loads(method2json_direct(meth_analysis))

        tot_bbs = len(g['reports'])

        # Minimum BB count check
        if tot_bbs < min_bbs:
            skipped += 1
            continue

        ngrams = cfganomaly.extract_ngrams(g['reports'], max_n=max_n)
        vector = vectorizer.vectorize(ngrams, tot_bbs)

        method_name = method.get_method().get_name()
        code_len = 2 * method.get_method().get_length()

        # Bundle all methods that are >= 2^11 bytes into one bin to avoid
        # very small bins, which might lead to overfitting.
        log2_bin = min(11, int(np.log2(code_len)))
        bin_sizes[log2_bin] += 1

        results.append((method_name, log2_bin, tot_bbs, vector))

    filename = os.path.splitext(os.path.basename(apk))[0]
    return (filename, results, bin_sizes, skipped)


parser = argparse.ArgumentParser('Tool for training CFG anomaly detector.')

parser.add_argument('appdir', help='path to directory with apps')
parser.add_argument('output', help='model-file output path')
parser.add_argument('--max_n', type=int, default=5, help='maximum n-gram size')
parser.add_argument('--min_size',
                    type=int,
                    default=300,
                    help='minimum method size (bytes)')
parser.add_argument('--min_bbs',
                    type=int,
                    default=30,
                    help='minimum number of basic blocks')
parser.add_argument('--ensemble_size',
                    type=int,
                    default=300,
                    help='number of trees')
parser.add_argument('--n_threads',
                    type=int,
                    default=-1,
                    help='number of threads to use')

args = parser.parse_args()

matrices = []
weights = []

app_mapping = {}

#idx = 0

tot_skipped = 0
no_methods = 0

start_time = time.time()

print("Extracting training samples...")

entries = [(path, args.max_n, args.min_size, args.min_bbs)
           for path in glob.glob(os.path.join(args.appdir, '*.apk'))]
with Pool(args.n_threads if args.n_threads > 0 else None) as pool:
    for filename, results, bin_sizes, skipped in tqdm(
            pool.imap_unordered(analyze_apk, entries, 1)):
        if len(results) == 0:
            no_methods += 1
            continue

        tot_skipped += skipped

        vectors = [r[3] for r in results]
        weights += [1 / r[1] for r in results]

        # app_mapping[filename] = (idx, idx + len(vectors))
        # idx = len(vectors)

        matrices.append(csc_matrix(vectors, dtype=np.float32))

full_matrix = vstack(matrices, format='csc')
weights_arr = np.array(weights)

print("\nExtraction complete.")
print("   Time: {}.".format(time.time() - start_time))
print("   Apps with no methods: {}.".format(no_methods))
print("   Skipped methods: {}.".format(tot_skipped))

print("\nTraining model...")

model = IsolationForest(n_estimators=args.ensemble_size,
                        n_jobs=args.n_threads,
                        max_samples=1.0)
model.fit(full_matrix, sample_weight=weights_arr)

print(f"\nAll done! Saving model to {args.output}")

with gzip.open(args.output, 'wb') as f:
    pickle.dump(model, f)
