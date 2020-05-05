#!/usr/bin/env python
# -*- encoding: utf-8 -*-
"""
$ python setup.py register sdist upload

More secure to use twine to upload
$ pip3 install twine
$ python3 setup.py sdist
$ twine upload dist/leopy-0.1.2.tar.gz

"""



from __future__ import absolute_import
from __future__ import print_function

import io
import re
from glob import glob
from os.path import basename
from os.path import dirname
from os.path import join
from os.path import splitext

from setuptools import find_packages
from setuptools import setup


def read(*names, **kwargs):
    with io.open(
        join(dirname(__file__), *names),
        encoding=kwargs.get('encoding', 'utf8')
    ) as fh:
        return fh.read()


setup(
    name='leopy',
    version='0.1.6',
    license='Apache Software License 2.0',
    description='Hyperledger Aries Cloud Agent Controller Demo',
    long_description="Hyperledger Aries Cloud Agent Controller Demo",
    author='Samuel M. Smith',
    author_email='smith.samuel.m@gmail.com',
    url='https://github.com/SmithSamuelM/leopy',
    packages=find_packages('src'),
    package_dir={'': 'src'},
    py_modules=[splitext(basename(path))[0] for path in glob('src/*.py')],
    include_package_data=True,
    zip_safe=False,
    classifiers=[
        # complete classifier list: http://pypi.python.org/pypi?%3Aaction=list_classifiers
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: Unix',
        'Operating System :: POSIX',
        'Operating System :: Microsoft :: Windows',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: Implementation :: CPython',
        # uncomment if you test on these interpreters:
        #'Programming Language :: Python :: Implementation :: PyPy',
        # 'Programming Language :: Python :: Implementation :: IronPython',
        # 'Programming Language :: Python :: Implementation :: Jython',
        # 'Programming Language :: Python :: Implementation :: Stackless',
        'Topic :: Utilities',
    ],
    project_urls={
        'Documentation': 'https://leopy.readthedocs.io/',
        'Changelog': 'https://leopy.readthedocs.io/en/latest/changelog.html',
        'Issue Tracker': 'https://github.com/SmithSamuelM/leopy/issues',
    },
    keywords=[
        # eg: 'keyword1', 'keyword2', 'keyword3',
    ],
    python_requires='>=3.7',
    install_requires=[
        'ioflo>=1.7.6',
        'falcon>=2.0.0',
    ],
    extras_require={
        # eg:
        #   'rst': ['docutils>=0.11'],
        #   ':python_version=="2.6"': ['argparse'],
    },
    setup_requires=[
    ],
    entry_points={
        'console_scripts': [
            'leopy = leopy.cli:main',
            'leopyd = leopy.daemon:main'
        ]
    },
)
