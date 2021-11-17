# This is the Base Exception for all exceptions in the project
class MalwareProjectException(BaseException):
    pass


class ApkManagerException(MalwareProjectException):
    pass


class NoMoreApks(ApkManagerException):
    pass


class DownloadFailed(ApkManagerException):
    pass
