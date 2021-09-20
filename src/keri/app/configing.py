# -*- encoding: utf-8 -*-
"""
keri.app.configing module

"""
import os
import stat
import shutil
import tempfile


class Configer():
    """
    Configer instances manage config file directories and files

    Attributes:
        .name (str): unique path component used in directory path
        .temp is Boolean True means use /tmp directory
        .prefix is str used as part of path prefix and formating
        .headDirPath is str used as head of path
        .tailDirpath is str used as tail of path
        .altTailDirPath is str used a alternate tail of path
        .dirPath is full directory path
        .path is full file path
        .opened is Boolean, True means file is opened Otherwise False
    """
    Prefix = "hio"
    HeadDirPath = "/usr/local/var"  # default in /usr/local/var
    TailDirPath = "logs"
    AltHeadDirPath = "~"  #  put in ~ as fallback when desired dir not permitted
    TempHeadDir = "/tmp"
    TempPrefix = "test_"
    TempSuffix = "_temp"

    def __init__(self, name='main', level=logging.ERROR, temp=False,
                 prefix=None, headDirPath=None, reopen=False, clear=False):
        """
        Init instance

        Parameters:
            name is application specific log file name
            level is int logging level from logging. Higher is more restrictive.
                This sets the minimum level of the baseLogger and failLogger
                relative to the global level.
                Logs will output if action level is at or above set level.

                Level    Numeric value
                CRITICAL 50
                ERROR    40
                WARNING  30
                INFO     20
                DEBUG    10
                NOTSET    0

            temp is Boolean True means use /tmp directory If .filed and clear on close
                            False means use  headDirpath If .filed
            prefix is str to include in path and logging template
            headDirPath is str for custom headDirPath for log file
            reopen is Booblean True means reopen path if anything changed
            clear is Boolean True means clear .dirPath when closing in reopen
        """
        self.name = name if name else 'main'  # for file name
        self.temp = True if temp else False
        self.prefix = prefix if prefix is not None else self.Prefix
        self.headDirPath = headDirPath if headDirPath is not None else self.HeadDirPath
        self.dirPath = None
        self.path = None
        self.opened = False

        if reopen:
            self.reopen(headDirPath=self.headDirPath, clear=clear)


    def reopen(self, name=None, temp=None, headDirPath=None, clear=False):
        """
        Use or Create if not preexistent, directory path for file .path
        First closes .path if already opened. If clear is True then also clears
        .path before reopening

        Parameters:
            name is optional name
                if None or unchanged then ignore otherwise recreate path
                    When recreating path, If not provided use .name
            temp is optional boolean:
                If None ignore Otherwise
                    Assign to .temp
                    If True then open temporary directory,
                    If False then open persistent directory
            headDirPath is optional str head directory pathname of main database
                if None or unchanged then ignore otherwise recreate path
                   When recreating path, If not provided use default .HeadDirpath
            clear is Boolean True means clear .path when closing
        """
        if self.opened:
            self.close(clear=clear)

        # check for changes in path parts if need to recreate
        if name is not None and name == self.name:
            name = None  # don't need to recreate path because of name change

        if temp is not None and temp == self.temp:
            temp = None  # don't need to recreate path because of temp change

        if headDirPath is not None and headDirPath == self.headDirPath:
            headDirPath = None  # don't need to recreate path because of headDirPath change

        # always recreates if path is empty or if path part has changed
        if (not self.dirPath or
            temp is not None or
            headDirPath is not None or
            name is not None):  # need to recreate self.dirPath, self.path, self.trPath

            if temp is not None:
                self.temp = True if temp else False
            if headDirPath is not None:
                self.headDirpath = headDirPath
            if name is not None:  # used below for filename
                self.name = name

            if self.temp:
                dirPath = os.path.abspath(
                                        os.path.join(self.TempHeadDir,
                                                    self.prefix,
                                                    self.TailDirPath))
                if not os.path.exists(dirPath):
                    os.makedirs(dirPath)  # mkdtemp only makes last dir
                self.dirPath = tempfile.mkdtemp(prefix=self.TempPrefix,
                                                suffix=self.TempSuffix,
                                                dir=dirPath)

            else:
                self.dirPath = os.path.abspath(
                        os.path.expanduser(
                                            os.path.join(self.headDirPath,
                                                         self.prefix,
                                                         self.TailDirPath)))

                if not os.path.exists(self.dirPath):
                    try:
                        os.makedirs(self.dirPath)
                    except OSError as ex:  # can't make dir
                        # use alt=user's directory instead
                        prefix = ".{}".format(self.prefix)  # hide it
                        self.dirPath = os.path.abspath(
                                                os.path.expanduser(
                                                                os.path.join(self.AltHeadDirPath,
                                                                             prefix,
                                                                            self.TailDirPath)))
                        if not os.path.exists(self.dirPath):
                            os.makedirs(self.dirPath)
                else:  # path exists
                    if not os.access(self.dirPath, os.R_OK | os.W_OK):
                        # but can't access it
                        # use alt=user's directory instead
                        prefix = ".{}".format(self.prefix)  # hide it
                        self.dirPath = os.path.abspath(
                                                os.path.expanduser(
                                                                os.path.join(self.AltHeadDirPath,
                                                                             prefix,
                                                                             self.TailDirPath)))
                        if not os.path.exists(self.dirPath):
                            os.makedirs(self.dirPath)

            fileName = "{}.log".format(self.name)
            self.path = os.path.join(self.dirPath, fileName)

            #create file handlers and assign formatters
            self.baseFileHandler = logging.handlers.TimedRotatingFileHandler(
                self.path, when='H', interval=1, backupCount=48)
            self.baseFileHandler.setFormatter(self.baseFormatter)

        self.opened = True


    def close(self, clear=False):
        """
        Set .opened to False and remove directory at .path
        Parameters:
           clear is boolean, True means clear directory
        """
        self.opened = False
        if clear or self.temp:
            self.clearDirPath()


    def clearDirPath(self):
        """
        Remove logfile directory at .dirPath
        """
        if self.dirPath and os.path.exists(self.dirPath):
            shutil.rmtree(self.dirPath)
