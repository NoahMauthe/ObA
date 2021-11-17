from json import JSONEncoder

from androguard.core.mutf8 import MUTF8String


class Encoder(JSONEncoder):

    def default(self, o):
        if type(o) == MUTF8String:
            return str(o)
        # Let the base class default method raise the TypeError
        return JSONEncoder.default(self, o)
