#!/usr/bin/python
# Copyright (c) 2010-2011 OpenStack, LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from setuptools import setup, find_packages

from sos import __version__ as version


name = 'sos'


setup(
    name=name,
    version=version,
    description='Swift Origin Server',
    license='Apache License (2.0)',
    author='OpenStack, LLC.',
    author_email='david.goetz@rackspace.com',
    url='https://github.com/dpgoetz/sos',
    packages=find_packages(exclude=['test_sos', 'bin']),
    test_suite='nose.collector',
    classifiers=[
        'Development Status :: 4 - Beta',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python :: 2.6',
        'Environment :: No Input/Output (Daemon)',
        ],
    install_requires=[],  # removed for better compat
    scripts=[
        'bin/swift-origin-prep',
        'bin/origin-ref-migration',
        ],
    entry_points={
        'paste.filter_factory': [
            'sos=sos.origin:filter_factory',
            ],
        },
    )
