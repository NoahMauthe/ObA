import json
import logging
import operator
from collections import Counter
from itertools import product

import numpy as np

from compatibility.androguard import method2json_direct
from utility.exceptions import CfgAnomalyError


class BasicBlock:
    def __init__(self, bb, mapping):
        self.idx = mapping[bb['BasicBlockId']]
        self.edges = [mapping[bb_id] for bb_id in bb['Edge']]
        # self.edges = list(set([mapping[bb_id] for bb_id in bb['Edge']]))
        self.exit = instruction_shorthand(bb['instructions'][-1]['name']) if bb['instructions'] else None
        if 'Exceptions' in bb:
            self.exceptions = [mapping[e['bb']] for e in bb['Exceptions']['list']]
        else:
            self.exceptions = []

    def __str__(self):
        return "BB #{}: Edges: {}, Exceptions: {}, Exit instruction: {}".format(
            self.idx, self.edges, self.exceptions, self.exit)


class DepthLimitVisitor:
    def __init__(self, cfg, limit):
        self.depth = 0
        self.limit = limit
        self.cfg = cfg

    def enter(self, _):
        self.depth += 1

    def exit(self, idx):
        self.depth -= 1

    def process(self, idx, is_exception):
        pass

    def do_traverse(self, _):
        return self.depth < self.limit


class DFSVisitor:
    def __init__(self, cfg):
        self.visited = [False] * len(cfg)
        self.cfg = cfg

    def enter(self, idx):
        self.visited[idx] = True

    def exit(self, idx):
        pass

    def process(self, idx, is_exception):
        pass

    def do_traverse(self, idx):
        return not self.visited[idx]


class LocalNgramVisitor(DepthLimitVisitor):
    def __init__(self, cfg, n):
        super().__init__(cfg, n)
        self.n = n
        self.ngrams = Counter()
        self.window = []

    def process(self, idx, is_exception):
        instr = self.cfg[idx].exit

        if instr is None:
            return

        # If we got here through an exception edge, we need to remove the
        # entry for the predecessor in the ngram stack, and replace it with
        # an 'E' symbol (for "Exception"). This is OK, since we process
        # exception edges after all regular edges.
        if is_exception:
            self.window.pop()
            self.window.append('E')

        self.window.append(instr)
        assert len(self.window) <= self.limit
        for i in range(len(self.window)):
            ngram = ''.join(list(self.window)[i:])
            self.ngrams[ngram] += 1

    def exit(self, idx):
        super().exit(idx)
        # If exit instruction is None, we haven't pushed anything, skip pop
        if self.cfg[idx].exit is not None:
            self.window.pop()

    def get_ngrams(self):
        return self.ngrams


class GlobalNgramVisitor(DFSVisitor):
    def __init__(self, cfg, n):
        super().__init__(cfg)
        self.n = n
        self.ngrams = Counter()

    def process(self, idx, is_exception):
        visitor = LocalNgramVisitor(self.cfg, self.n)
        traverse_cfg(self.cfg, visitor, idx)
        self.ngrams += visitor.get_ngrams()


class NgramVectorizer:
    def __init__(self, max_n=5):
        exit_types = "CEGIRST"
        exit_combinations = []
        # Generate all valid exit type combinations, taking into account that
        # we cannot have multiple returns along a path in the CFG.
        for i in range(1, max_n + 1):
            exit_combinations += [''.join(n) for n in product(exit_types, repeat=i) if 'R' not in n[:-1]]
        self._vectorizer = {n: 0 for n in exit_combinations}

    def vectorize(self, ngrams, bb_count):
        vector = Counter(self._vectorizer)
        vector.update(ngrams)
        # Sanity check that we didn't get any invalid ngrams added
        assert len(vector) == len(self._vectorizer)
        return np.array([v / bb_count for k, v in sorted(vector.items(), key=operator.itemgetter(0))], dtype=np.float32)


def instruction_shorthand(instr):
    if instr.startswith('return'):
        return 'R'
    elif instr.startswith('throw'):
        return 'T'
    elif instr.startswith('goto'):
        return 'G'
    elif instr.endswith('switch'):
        return 'S'
    elif instr.startswith('if-'):
        return 'I'
    else:
        return 'C'  # "Boring" computation


def build_cfg(basic_blocks):
    # Build [ID: index] mapping
    id_mapping = {}
    idx = 0
    for bb in basic_blocks:
        id_mapping[bb['BasicBlockId']] = idx
        idx += 1

    # Make basic block objects
    result = []
    for bb in basic_blocks:
        result.append(BasicBlock(bb, id_mapping))

    return result


def traverse_cfg(cfg, visitor, start_node=0):
    if len(cfg) == 0:
        return

    class StackEntry:
        def __init__(self, idx, is_exception=False):
            self.bb_idx = idx
            self.edge_idx = 0
            self.exception_idx = 0
            self.is_exception = is_exception

    stack = [StackEntry(start_node)]

    while stack:
        entry = stack[-1]
        bb = cfg[entry.bb_idx]

        if entry.edge_idx == 0 and entry.exception_idx == 0:  # Check if we've been here before
            visitor.enter(entry.bb_idx)
            visitor.process(entry.bb_idx, entry.is_exception)

        next_bb = None
        is_exception_edge = False
        if entry.edge_idx < len(bb.edges):
            next_bb = bb.edges[entry.edge_idx]
            entry.edge_idx += 1
        elif entry.exception_idx < len(bb.exceptions):
            next_bb = bb.exceptions[entry.exception_idx]
            is_exception_edge = True
            entry.exception_idx += 1

        if next_bb and visitor.do_traverse(next_bb):
            stack.append(StackEntry(next_bb, is_exception_edge))
        else:
            visitor.exit(entry.bb_idx)
            stack.pop()


def extract_ngrams(basic_blocks, max_n=5):
    cfg = build_cfg(basic_blocks)
    visitor = GlobalNgramVisitor(cfg, max_n)
    traverse_cfg(cfg, visitor)
    return visitor.ngrams


class CfgAnomaly:
    """
   Wrapper around a scikit-learn IsolationForest anomaly detector.
   Parameters should be set to the same that was used when training the model.
   """

    def __init__(self,
                 model,
                 max_n=5,
                 min_size=300,
                 min_bb_count=30):
        self.model = model
        self.max_n = max_n
        self.vectorizer = NgramVectorizer(max_n)
        self.min_bb_count = min_bb_count
        self.min_size = min_size

    def get_anomaly_scores(self, method_analyses):
        """
      Get anomaly scores for each given method.
      
      Parameters
      ----------
      method_analyses: Iterable of Androguard MethodAnalysis objects.

      Returns
      -------
      A list of anomaly scores. Skipped methods get a score of 1.0.
      Otherwise, scores are between -1 and 0, where lower means more anomalous.
      """
        to_analyze = []
        vectors = []
        idx = 0
        for method in method_analyses:
            dalvik_code = method.method.get_code()
            code_size = dalvik_code.get_bc().get_length() if dalvik_code else 0

            if code_size != 0:
                g = json.loads(method2json_direct(method))
                basic_blocks = g['reports']

                bb_count = len(basic_blocks)

                # Skip methods with very simple control flow.
                # Also skip methods that have very small BBs to avoid too small bins.
                if bb_count >= self.min_bb_count and code_size >= self.min_size:
                    ngrams = extract_ngrams(basic_blocks, self.max_n)
                    vectors.append(self.vectorizer.vectorize(ngrams, bb_count))
                    to_analyze.append(idx)
            idx += 1

        scores = None
        try:
            vectors = np.array(vectors)
            scores = self.model.score_samples(vectors)
        except ValueError as error:
            if len(to_analyze) != 0:
                logging.getLogger('CFGANOMALY').error(repr(error))
                raise CfgAnomalyError(error)

        # Create an array filled with 1.0, and then insert "real" scores for
        # those methods that needed analysis
        results = np.full(idx, 1.0)
        if scores is not None:
            results[to_analyze] = scores

        return results
