# -*- encoding: utf-8 -*-
"""
keri.kli.commands.import module

Because multicommand names commands from filesystem/module names, and the desired KLI command is
- `kli import`
then this _index.py file is necessary so that multicommand version exposes it as `kli import`

yet "import" is a keyword
The _index.py wrapper creates a package whose directory name is the public command name:
- src/keri/app/cli/commands/import/_index.py

causing multicommand to see the package name import and exposes `kli import`

The split avoids having an implementation module literally named import.py,
which is awkward because import is a Python keyword.
"""

from keri.app.cli.commands import import_

parser = import_.importParser
