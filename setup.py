#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys
from setuptools import setup

with open('README.rst') as readme_file:
    readme = readme_file.read()


requirements = [
    'pysodium',
]

test_requirements = [
    'pytest'
]

setup(
    name='sqrl',
    version='0.1.0',
    description="Secure Quick Reliable Login",
    long_description=readme,
    author="Terrel Shumway",
    author_email='moan-o-storm-beware-spoke@shumway.us',
    url='https://github.com/bbiw/sqrl',
    packages=[
        'sqrl',
    ],
    package_dir={'sqrl':
                 'sqrl'},
    entry_points={
        'console_scripts': [
            'sqrl=sqrl.cli:main'
        ]
    },
    include_package_data=True,
    install_requires=requirements,
    license="Apache Software License 2.0",
    zip_safe=False,
    keywords='SQRL',
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache Software License',
        'Natural Language :: English',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
    ],
    test_suite='tests',
    tests_require=test_requirements
)
