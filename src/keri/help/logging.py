# -*- encoding: utf-8 -*-
"""
keri.help.logging module

"""

from os import path
import logging


class Loggery():
    """
    Loggery instances are logger factories that configure and build loggers
    Only need one loggery per application

    logging.getLogger(name). Multiple calls to getLogger() with the same name
    will always return a reference to the same Logger object.

    Attributes:
        .level is logging severity level
        .logFilePath is path to log file
    """

    def __init__(self, level=logging.ERROR,  logFileDir="", logFileName="",
                 default=False):
        """
        Init Loggery factory instance

        Parameters:
            level is int logging level from logging. Higher is more restrictive.
                This sets the level of the baseLogger relative to the global level
                logs output if severity level is at or above set level.

                Level    Numeric value
                CRITICAL 50
                ERROR    40
                WARNING  30
                INFO     20
                DEBUG    10
                NOTSET    0

            logFileDir is str of directory path
            logFileName is str of name of log file
            default is Boolean False means create default logFileDir if empty
                               Otherwise do not create a logFileDir if empty

        """
        self.level = level  # basic logger level

        if not logFileDir:
            if default:  # use default
                logFileDir = path.join(
                            path.dirname(
                                path.dirname(path.abspath(__file__))), 'logs')
                if not logFileName:
                    logFileName = 'keri.log'

            else:  # do not create logFileDir
                logFileName = ""  # force empty if empty logFiledir

        self.logFilePath = path.join(logFileDir, logFileName)  # empty means none

        #create formatters
        self.baseFormatter = logging.Formatter('%(message)s')  # basic format
        self.failFormatter = logging.Formatter('***Fail: %(message)s')  # failure format

        #create handlers and formatters
        self.baseConsoleHandler = logging.StreamHandler()  # sys.stderr
        self.baseConsoleHandler.setFormatter(self.baseFormatter)
        self.failConsoleHandler = logging.StreamHandler()  # sys.stderr
        self.failConsoleHandler.setFormatter(self.failFormatter)

        if self.logFilePath:  # if empty then no handlers so no logging to file
            self.baseFileHandler = logging.FileHandler(self.logFilePath)
            self.baseFileHandler.setFormatter(self.baseFormatter)
            self.failFileHandler = logging.FileHandler(self.logFilePath)
            self.failFileHandler.setFormatter(self.failFormatter)


    def getBlogger(self, name=__name__, level=None):
        """
        Returns Basic Logger
        default is to name logger after module
        """
        blogger = logging.getLogger(name)
        blogger.propagate = False  # disable propagation of events
        if level is not None:
            self.level = level
        blogger.setLevel(self.level)
        blogger.addHandler(self.baseConsoleHandler)
        if self.logFilePath:
            blogger.addHandler(self.baseFileHandler)
        return blogger

    def getFlogger(self, name=__name__):
        """
        Returns Failure Logger
        Since loggers are singletons by name we have to use unique name if
            we want to use different log format so we append .fail to base name
        """
        # Since loggers are singletons by name we have to change name if we
        # want to use different log format
        flogger = logging.getLogger("%s.%s" % (name, 'fail'))
        flogger.propagate = False  # disable propagation of events
        flogger.setLevel(logging.ERROR)
        flogger.addHandler(self.failConsoleHandler)  # output to console
        if self.logFilePath:
            flogger.addHandler(self.failFileHandler)  # output to file
        return flogger

    def getLoggers(self, name=__name__):
        """
        Returns duple (blogger, flogger) of basic and failure loggers
        """
        return (self.getBlogger(name), self.getFlogger(name))

