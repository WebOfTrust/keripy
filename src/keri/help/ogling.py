# -*- encoding: utf-8 -*-
"""
keri.help.ogling module

Provides python stdlib logging module support

"""
import os
import logging
import tempfile
import shutil

ogler = None  # module global ogler instance used by all for keri console logging


def initOgler(force=False, level=logging.CRITICAL, **kwa):
    """
    Initialize the ogler global instance once
    Critical is most severe to restrict logging by default

    Parameters:
        force is Boolean True is to force reinit even if global ogler is not None
        level is default logging level

    This should be called in package .__init__ to insure that global ogler is
    defined by default. Users may then reset level and reopen log file if need be
    before calling ogler.getLoggers()
    """
    global ogler
    if ogler is None or force:
        ogler = Ogler(level=level, **kwa)

    return ogler


class Ogler():
    """
    Olgery instances are logger factories that configure and build loggers
    Only need one Ogler per application

    logging.getLogger(name). Multiple calls to getLogger() with the same name
    will always return a reference to the same Logger object.

    Attributes:
        .level is logging severity level
        .logFilePath is path to log file
    """
    HeadDirPath = "/usr/local/var"  # default in /usr/local/var
    TailDirPath = "keri/log"
    AltHeadDirPath = "~"  #  put in ~ as fallback when desired not permitted
    AltTailDirPath = ".keri/log"

    def __init__(self, name='main', level=logging.ERROR, temp=False,
                 headDirPath=None, reopen=False, clear=False):
        """
        Init Loggery factory instance

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

            file is Boolean True means create logfile Otherwise not
            temp is Boolean If file then True means use temp direction
                                         Otherwise use  headDirpath
            headDirPath is str for custom headDirPath for log file
            clear is Boolean True means clear .path when closing in reopen
        """
        self.name = name if name else 'main'
        self.level = level  # basic logger level
        self.temp = True if temp else False
        self.headDirPath = headDirPath if headDirPath is not None else self.HeadDirPath
        self.path = None
        self.opened = False

        #create formatters
        self.baseFormatter = logging.Formatter('%(message)s')  # basic format
        self.failFormatter = logging.Formatter('***Fail: %(message)s')  # failure format

        #create console handlers and assign formatters
        self.baseConsoleHandler = logging.StreamHandler()  # sys.stderr
        self.baseConsoleHandler.setFormatter(self.baseFormatter)
        self.failConsoleHandler = logging.StreamHandler()  # sys.stderr
        self.failConsoleHandler.setFormatter(self.failFormatter)

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
        if (not self.path or
            temp is not None or
            headDirPath is not None or
            name is not None):  # need to recreate self.path


            if temp is not None:
                self.temp = True if temp else False
            if headDirPath is not None:
                self.headDirpath = headDirPath
            if name is not None:  # used below for filename
                self.name = name

            if self.temp:
                headDirPath = tempfile.mkdtemp(prefix="keri_log_", suffix="_test", dir="/tmp")
                self.path = os.path.abspath(
                                    os.path.join(headDirPath,
                                                 self.TailDirPath))
                os.makedirs(self.path)

            else:
                if not headDirPath:
                    headDirPath = self.HeadDirPath

                self.path = os.path.abspath(
                                    os.path.expanduser(
                                        os.path.join(headDirPath,
                                                     self.TailDirPath)))

                if not os.path.exists(self.path):
                    try:
                        os.makedirs(self.path)
                    except OSError as ex:
                        headDirPath = self.AltHeadDirPath
                        self.path = os.path.abspath(
                                            os.path.expanduser(
                                                os.path.join(headDirPath,
                                                             self.AltTailDirPath)))
                        if not os.path.exists(self.path):
                            os.makedirs(self.path)
                else:
                    if not os.access(self.path, os.R_OK | os.W_OK):
                        headDirPath = self.AltHeadDirPath
                        self.path = os.path.abspath(
                                            os.path.expanduser(
                                                os.path.join(headDirPath,
                                                             self.AltTailDirPath)))
                        if not os.path.exists(self.path):
                            os.makedirs(self.path)

            fileName = "{}.log".format(self.name)
            self.path = os.path.join(self.path, fileName)

            #create file handlers and assign formatters
            self.baseFileHandler = logging.FileHandler(self.path)
            self.baseFileHandler.setFormatter(self.baseFormatter)
            self.failFileHandler = logging.FileHandler(self.path)
            self.failFileHandler.setFormatter(self.failFormatter)

        self.opened = True


    def close(self, clear=False):
        """
        Close lmdb at .env and if clear or .temp then remove lmdb directory at .path
        Parameters:
           clear is boolean, True means clear lmdb directory
        """
        self.opened = False
        if clear:
            self.clearDirPath()

    def clearDirPath(self):
        """
        Remove logfile directory at .path
        """
        if os.path.exists(self.path):
            shutil.rmtree(os.path.dirname(self.path))
            self.path = None


    def resetLevels(self, name=__name__, level=None):
        """
        Resets the level of preexisting loggers to level. If level is None then
        use .level
        """
        level = level if level is not None else self.level
        blogger = logging.getLogger(name)
        blogger.setLevel(level)
        flogger = logging.getLogger("%s.%s" % (name, 'fail'))
        flogger.setLevel(max(level, logging.ERROR))


    def getBlogger(self, name=__name__, level=None):
        """
        Returns Basic Logger
        default is to name logger after module
        """
        blogger = logging.getLogger(name)
        blogger.propagate = False  # disable propagation of events
        level = level if level is not None else self.level
        blogger.setLevel(level)
        for handler in list(blogger.handlers):  # remove so no duplicate handlers
            blogger.removeHandler(handler)
        blogger.addHandler(self.baseConsoleHandler)
        if self.opened:
            blogger.addHandler(self.baseFileHandler)
        return blogger


    def getFlogger(self, name=__name__, level=None):
        """
        Returns Failure Logger
        Since loggers are singletons by name we have to use unique name if
            we want to use different log format so we append .fail to base name
        Only logs at level logging.Error or higher
        """
        # Since loggers are singletons by name we have to change name if we
        # want to use different log format
        flogger = logging.getLogger("%s.%s" % (name, 'fail'))
        flogger.propagate = False  # disable propagation of events
        level = level if level is not None else self.level
        flogger.setLevel(max(level, logging.ERROR))
        for handler in list(flogger.handlers):  # remove so no duplicate handlers
            flogger.removeHandler(handler)
        flogger.addHandler(self.failConsoleHandler)  # output to console
        if self.opened:
            flogger.addHandler(self.failFileHandler)  # output to file
        return flogger


    def getLoggers(self, name=__name__):
        """
        Returns duple (blogger, flogger) of basic and failure loggers
        """
        return (self.getBlogger(name), self.getFlogger(name))

