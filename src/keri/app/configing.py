# -*- encoding: utf-8 -*-
"""
keri.app.configing module

"""
import os
import stat
import shutil
import tempfile
from contextlib import contextmanager

@contextmanager
def openFiler(cls=None, name="test", temp=True, **kwa):
    """
    Context manager wrapper Filer instances for managing a filesystem directory
    and or files in a directory.

    Defaults to using temporary directory path.
    Context 'with' statements call .close on exit of 'with' block

    Parameters:
        cls is Class instance of subclass instance
        name is str name of ogler instance for filename so can have multiple oglers
             at different paths thar each use different log file directories
        temp is Boolean, True means open in temporary directory, clear on close
                Otherwise open in persistent directory, do not clear on close

    Usage:

    with openPather(name="bob") as configer:

    with openConfiger(name="eve", cls=SubclassConfiger)

    """
    if cls is None:
        cls = Configer
    try:
        configer = cls(name=name, temp=temp, reopen=True, **kwa)
        yield configer

    finally:
        if configer:
            configer.close()  # if .temp also clears



class Filer():
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

    Fire/Directory Creation Mode Notes:
        DirMode is for Restricted Access Permissions to directory of db

        stat.S_ISVTX  is Sticky bit. When this bit is set on a directory it means
            that a file in that directory can be renamed or deleted only by the
            owner of the file, by the owner of the directory, or by a privileged process.
        stat.S_IRUSR Owner has read permission.
        stat.S_IWUSR Owner has write permission.
        stat.S_IXUSR Owner has execute permission.

        # stat.S_ISVTX | stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR  # 0o1700==960

    """
    HeadDirPath = "/usr/local/var"  # default in /usr/local/var
    TailDirPath = "keri/db"
    CleanTailDirPath = "keri/clean/db"
    AltHeadDirPath = "~"  # put in ~ as fallback when desired not permitted
    AltTailDirPath = ".keri/db"
    AltCleanTailDirPath = ".keri/clean/db"
    TempHeadDir = "/tmp"
    TempPrefix = "keri_lmdb_"
    TempSuffix = "_test"
    MaxNamedDBs = 64
    DirMode = stat.S_ISVTX | stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR  # 0o1700==960

    def __init__(self, name='main', temp=False, headDirPath=None, dirMode=None,
                 reopen=True, clear=False, reuse=False, clean=False, readonly=False):
        """
        Setup main database directory at .dirpath.
        Create main database environment at .env using .dirpath.

        Parameters:
            name (str): directory path name differentiator for main database
                When system employs more than one keri database, name allows
                differentiating each instance by name
            temp (bool): assign to .temp
                True then open in temporary directory, clear on close
                Otherwise then open persistent directory, do not clear on close
            headDirPath (str): optional head directory pathname for main database
                Default .HeadDirPath
            dirMode (int): optional numeric os dir permissions for database
                directory and database files. Default .DirMode
            reopen (bool): True means database will be reopened by this init
                              False means databse not opened by this init
            clear (bool): True means remove directory upon close if reopon
                             False means do not remove directory upon close if reopen
            reuse (bool): True means reuse self.path if already exists
                             False means do not reuse but remake self.path
            clean (bool): True means path uses clean tail variant
                             False means path uses normal tail variant
            readonly (bool): True means open database in readonly mode
                                False means open database in read/write mode

        """
        self.name = name
        self.temp = True if temp else False
        self.headDirPath = headDirPath if headDirPath is not None else self.HeadDirPath
        self.dirMode = dirMode if dirMode is not None else self.DirMode
        self.path = None
        self.env = None
        self.opened = False

        if reopen:
            self.reopen(headDirPath=self.headDirPath, dirMode=dirMode,
                        clear=clear, reuse=reuse, clean=clean, readonly=readonly)



    def reopen(self, temp=None, headDirPath=None, dirMode=None, clear=False,
               reuse=False, clean=False, readonly=False):
        """
        Open if closed or close and reopen if opened or create and open if not
        if not preexistent, directory path for lmdb at .path and then
        Open lmdb and assign to .env

        Parameters:
            temp (bool): assign to .temp
                True then open in temporary directory, clear on close
                Othewise then open persistent directory, do not clear on close
            headDirPath (str): optional head directory pathname for main database
                Default .HeadDirpath
            dirMode (int): optional numeric os dir permissions for database
                directory and database files. Default .DirMode
            clear (bool): True means remove directory upon close
                             False means do not remove directory upon close
            reuse (bool): True means reuse self.path if already exists
                             False means do not reuse but remake self.path
            clean (bool): True means path uses clean tail variant
                             False means path uses normal tail variant
            readonly (bool): True means open database in readonly mode
                                False means open database in read/write mode
        """
        self.close(clear=clear)

        if temp is not None:
            self.temp = temp
        if headDirPath is not None:
            self.headDirPath = headDirPath
        if dirMode is not None:
            self.dirMode = dirMode

        if not reuse or not self.path:
            self.path = self.makePath(name=self.name,
                                      temp=self.temp,
                                      headDirPath=self.headDirPath,
                                      dirMode=self.dirMode,
                                      clean=clean)

        # open lmdb major database instance
        # creates files data.mdb and lock.mdb in .dbDirPath
        self.env = lmdb.open(self.path, max_dbs=self.MaxNamedDBs,
                             perm=self.dirMode, readonly=readonly)
        self.opened = True
        return self.env


    def makePath(self, name, temp=None, headDirPath=None, dirMode=None, clean=False):
        """
        Make .path by opening or creating and opening if not preexistent, directory
        path for lmdb and assigning to .path

        Parameters:
            name (str): unique name alias portion of path
            temp (bool): optional
                None means ignore,
                True means open temporary directory, may clear on close
                False menans open persistent directory, may not clear on close

            headDirPath (str): optional head directory pathname of main database

            dirMode (int): directory permissions such as
                stat.S_IRUSR Owner has read permission.
                stat.S_IWUSR Owner has write permission.
                stat.S_IXUSR Owner has execute permission.

            clean (bool): True means make path for cleaned version of db and
                               remove old directory at clean path if exists
                             False means make path for regular version of db
        """
        temp = True if temp else False

        if headDirPath is None:
            headDirPath = self.HeadDirPath
        if dirMode is None:
            dirMode = self.DirMode

        tailDirPath = self.CleanTailDirPath if clean else self.TailDirPath
        altTailDirPath = self.AltCleanTailDirPath if clean else self.AltTailDirPath

        if temp:
            headDirPath = tempfile.mkdtemp(prefix=self.TempPrefix,
                                           suffix=self.TempSuffix,
                                           dir=self.TempHeadDir)
            path = os.path.abspath(
                                os.path.join(headDirPath,
                                             tailDirPath,
                                             name))

            if clean and os.path.exists(path):
                shutil.rmtree(path)

            os.makedirs(path)

        else:
            path = os.path.abspath(
                                os.path.expanduser(
                                    os.path.join(headDirPath,
                                                 tailDirPath,
                                                 name)))

            if clean and os.path.exists(path):
                shutil.rmtree(path)

            if not os.path.exists(path):
                try:
                    os.makedirs(path)
                except OSError as ex:
                    headDirPath = self.AltHeadDirPath
                    path = os.path.abspath(
                                        os.path.expanduser(
                                            os.path.join(headDirPath,
                                                         altTailDirPath,
                                                         name)))
                    if not os.path.exists(path):
                        os.makedirs(path)
            else:
                if not os.access(path, os.R_OK | os.W_OK):
                    headDirPath = self.AltHeadDirPath
                    path = os.path.abspath(
                                        os.path.expanduser(
                                            os.path.join(headDirPath,
                                                         altTailDirPath,
                                                         name)))
                    if not os.path.exists(path):
                        os.makedirs(path)

            os.chmod(path, dirMode)  # set dir creation mode

        return path


    def close(self, clear=False):
        """
        Close lmdb at .env and if clear or .temp then remove lmdb directory at .path
        Parameters:
           clear is boolean, True means clear lmdb directory
        """
        if self.env:
            try:
                self.env.close()
            except:
                pass

        self.env = None
        self.opened = False

        if clear:
            self.clearDirPath()


    def clearDirPath(self):
        """
        Remove lmdb directory at end of .path
        """
        if self.path and os.path.exists(self.path):
            shutil.rmtree(self.path)


@contextmanager
def openConfiger(cls=None, name="test", temp=True, **kwa):
    """
    Context manager wrapper Configer instances.
    Defaults to temporary file logs.
    Context 'with' statements call .close on exit of 'with' block

    Parameters:
        cls is Class instance of subclass instance
        name is str name of ogler instance for filename so can have multiple oglers
             at different paths thar each use different log file directories
        temp is Boolean, True means open in temporary directory, clear on close
                Otherwise open in persistent directory, do not clear on close

    Usage:

    with openConfigerr(name="bob") as configer:

    with openConfiger(name="eve", cls=SubclassConfiger)

    """
    if cls is None:
        cls = Configer
    try:
        configer = cls(name=name, temp=temp, reopen=True, **kwa)
        yield configer

    finally:
        if configer:
            configer.close()  # if .temp also clears



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

    Fire/Directory Creation Mode Notes:
        DirMode is for Restricted Access Permissions to directory of db

        stat.S_ISVTX  is Sticky bit. When this bit is set on a directory it means
            that a file in that directory can be renamed or deleted only by the
            owner of the file, by the owner of the directory, or by a privileged process.
        stat.S_IRUSR Owner has read permission.
        stat.S_IWUSR Owner has write permission.
        stat.S_IXUSR Owner has execute permission.

        # stat.S_ISVTX | stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR  # 0o1700==960

    """
    HeadDirPath = "/usr/local/var"  # default in /usr/local/var
    TailDirPath = "keri/db"
    CleanTailDirPath = "keri/clean/db"
    AltHeadDirPath = "~"  # put in ~ as fallback when desired not permitted
    AltTailDirPath = ".keri/db"
    AltCleanTailDirPath = ".keri/clean/db"
    TempHeadDir = "/tmp"
    TempPrefix = "keri_lmdb_"
    TempSuffix = "_test"
    MaxNamedDBs = 64
    DirMode = stat.S_ISVTX | stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR  # 0o1700==960

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
