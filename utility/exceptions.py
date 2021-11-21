# This is the Base Exception for all exceptions in the project
class ObfuscationAnalysisException(BaseException):
    pass


class ParserError(ObfuscationAnalysisException):
    pass


class ApkManagerException(ObfuscationAnalysisException):
    pass


class NoMoreApks(ApkManagerException):
    pass


class DownloadFailed(ApkManagerException):
    pass


class DatabaseRetry(ObfuscationAnalysisException):

    def __init__(self, error, func, *args):
        super().__init__()
        self.error = error
        self.func = func
        self.args = args


class CfgAnomalyError(ObfuscationAnalysisException):

    def __init__(self, error):
        super().__init__()
        self.error = error
