#!/usr/bin/env python
# -*- encoding: utf-8 -*-
"""
$ python setup.py register sdist upload

First Time register project on pypi
https://pypi.org/manage/projects/


More secure to use twine to upload
$ pip3 install twine
$ python3 setup.py sdist
$ twine upload dist/keri-0.0.1.tar.gz


Best practices for setup.py and requirements.txt
https://caremad.io/posts/2013/07/setup-vs-requirement/


"""


from glob import glob
from os.path import basename
from os.path import splitext

from setuptools import find_packages
from setuptools import setup



setup(
    name='keri',
    version='0.3.2',  #  also change in src/keri/__init__.py
    license='Apache Software License 2.0',
    description='Key Event Receipt Infrastructure',
    long_description="KERI Decentralized Key Management Infrastructure",
    author='Samuel M. Smith',
    author_email='smith.samuel.m@gmail.com',
    url='https://github.com/decentralized-identity/keripy',
    packages=find_packages('src'),
    package_dir={'': 'src'},
    py_modules=[splitext(basename(path))[0] for path in glob('src/*.py')],
    include_package_data=True,
    zip_safe=False,
    classifiers=[
        # complete classifier list: http://pypi.python.org/pypi?%3Aaction=list_classifiers
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: Unix',
        'Operating System :: POSIX',
        'Operating System :: Microsoft :: Windows',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: Implementation :: CPython',
        # uncomment if you test on these interpreters:
        #'Programming Language :: Python :: Implementation :: PyPy',
        # 'Programming Language :: Python :: Implementation :: IronPython',
        # 'Programming Language :: Python :: Implementation :: Jython',
        # 'Programming Language :: Python :: Implementation :: Stackless',
        'Topic :: Utilities',
    ],
    project_urls={
        'Documentation': 'https://keri.readthedocs.io/',
        'Changelog': 'https://keri.readthedocs.io/en/latest/changelog.html',
        'Issue Tracker': 'https://github.com/decentralized-identity/keripy/issues',
    },
    keywords=[
        # eg: 'keyword1', 'keyword2', 'keyword3',
    ],
    python_requires='>=3.9.2',
    install_requires=[
        'lmdb>=1.1.1',
        'pysodium>=0.7.7',
        'blake3>=0.1.8',
        'msgpack>=1.0.2',
        'cbor2>=5.2.0',
        'multidict>=5.1.0',
        'orderedset>=2.0.3',
        'hio>=0.2.4',

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
            'keri = keri.cli:main',
            'kerid = keri.daemon:main',
            'keri_bob = keri.demo.demo_bob:main',
            'keri_eve = keri.demo.demo_eve:main',
            'keri_sam = keri.demo.demo_sam:main',
        ]
    },
)
