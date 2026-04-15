# Configuration file for the Sphinx documentation builder.
#
# This file only contains a selection of the most common options. For a full
# list see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Path setup --------------------------------------------------------------

# If extensions (or modules to document with autodoc) are in another directory,
# add these directories to sys.path here. If the directory is relative to the
# documentation root, use os.path.abspath to make it absolute, like shown here.
#
# import os
# import sys
# sys.path.insert(0, os.path.abspath('.'))


# -- Project information -----------------------------------------------------
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join("..", "src")))
import keri  # noqa: E402

try:
    import sphinx_rtd_theme
except ImportError:
    sphinx_rtd_theme = None

project = "keri"
copyright = "2022 - 2026, Dr. Samuel Smith and contributors"
author = "Dr. Samuel Smith"

version = release = keri.__version__

# -- General configuration ---------------------------------------------------

# Add any Sphinx extension module names here, as strings. They can be
# extensions coming with Sphinx (named 'sphinx.ext.*') or your custom
# ones.
extensions = [
    "myst_parser",
    "sphinx.ext.viewcode",
    "sphinx.ext.autosummary",
    "sphinx.ext.autodoc",
    "sphinx.ext.napoleon",
    "sphinx.ext.intersphinx",
]
# Add any paths that contain templates here, relative to this directory.
templates_path = ["_templates"]

# List of patterns, relative to source directory, that match files and
# directories to ignore when looking for source files.
# This pattern also affects html_static_path and html_extra_path.
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]

napoleon_include_init_with_doc = True

# Preserve KERI domain language in docstrings by mapping frequently used
# domain terms to canonical symbols. This avoids forcing prose rewrites.
napoleon_type_aliases = {
    "Serder": "keri.core.serdering.Serder",
    "SerderKERI": "keri.core.serdering.SerderKERI",
    "SerderACDC": "keri.core.serdering.SerderACDC",
    "Diger": "keri.core.coring.Diger",
    "Saider": "keri.core.coring.Saider",
    "Siger": "keri.core.coring.Siger",
    "Cigar": "keri.core.coring.Cigar",
    "Prefixer": "keri.core.coring.Prefixer",
    "Verfer": "keri.core.coring.Verfer",
    "Seqner": "keri.core.coring.Seqner",
    "Number": "keri.core.coring.Number",
    "Tholder": "keri.core.coring.Tholder",
    "Kever": "keri.core.eventing.Kever",
    "Kevery": "keri.core.eventing.Kevery",
    "Parser": "keri.core.parsing.Parser",
    "Router": "keri.core.routing.Router",
    "Revery": "keri.core.routing.Revery",
    "Hab": "keri.app.habbing.Hab",
    "GroupHab": "keri.app.habbing.GroupHab",
    "Habery": "keri.app.habbing.Habery",
    "KeyStateRecord": "keri.recording.KeyStateRecord",
    "EndpointRecord": "keri.recording.EndpointRecord",
    "LocationRecord": "keri.recording.LocationRecord",
    "Deck": "hio.help.decking.Deck",
    "Versionage": "keri.kering.Versionage",
}

# Resolve common external symbols from their upstream docs inventories.
intersphinx_mapping = {
    "python": ("https://docs.python.org/3", None),
    "falcon": ("https://falcon.readthedocs.io/en/stable/", None),
}

# Preserve legacy/domain-rich terminology in docstrings without forcing
# destructive content rewrites to satisfy unresolved Python cross-references.
# Keep structural/docutils warnings visible in separate cleanup lanes.
suppress_warnings = ["ref.class", "ref.exc", "ref.obj"]

# Keep domain-specific docstring type names intact while suppressing unresolved
# cross-reference warnings for symbols that are not import-resolvable by Sphinx.
nitpick_ignore = [
    ("py:class", "SerderKERI"),
    ("py:class", "serdering.SerderKERI"),
    ("py:class", "SerderKeri"),
    ("py:class", "serving.Client"),
    ("py:class", "TCP Client"),
    ("py:class", "TCP Remoter"),
    ("py:class", "Habitat"),
    ("py:class", "Client"),
    ("py:class", "Request"),
    ("py:class", "Response"),
    ("py:class", "Serder"),
    ("py:class", "serdering.Serder"),
    ("py:class", "hicting.Mict"),
    ("py:class", "OrderedSet"),
    ("py:class", "oset.OrderedSet"),
    ("py:class", "decking.Deck"),
    ("py:class", "collections.abc.Iterable"),
    ("py:class", "falcon.App"),
    ("py:class", "serder is SerderKERI instance of"),
    ("py:class", "serder is SerderKERI instance"),
    ("py:exc", "ValidationError"),
    ("py:exc", "ConfigurationError"),
    ("py:exc", "MissingEntryError"),
    ("py:exc", "ClosedError"),
    ("py:exc", "AuthError"),
    ("py:exc", "KeriError"),
    ("py:obj", "datetime"),
]

# Many unresolved references are phrase-like parser artifacts from legacy
# docstrings/autosummary output (for example targets containing spaces). Keep
# this conservative to avoid muting real symbol regressions.
nitpick_ignore_regex = [
    ("py:class", r".*\s+.*"),
    ("py:obj", r".*\s+.*"),
]

# -- Options for HTML output -------------------------------------------------

# The theme to use for HTML and HTML Help pages.  See the documentation for
# a list of builtin themes.
#
if sphinx_rtd_theme:
    html_theme = "sphinx_rtd_theme"
else:
    html_theme = "default"

# Add any paths that contain custom static files (such as style sheets) here,
# relative to this directory. They are copied after the builtin static files,
# so a file named "default.css" will overwrite the builtin "default.css".
html_static_path = ["_static"]
