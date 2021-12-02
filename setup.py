# Copyright 2021 Y7n05h
# This file is part of PowerfulLeaker.
# PowerfulLeaker is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

from setuptools import find_packages, setup
from os import path as os_path

this_directory = os_path.abspath(os_path.dirname(__file__))


def read_file(filename):
    with open(os_path.join(this_directory, filename), encoding='utf-8') as f:
        long_description = f.read()
    return long_description


setup(
    name="PowerfulLeaker",
    version="0.0.1a",
    description="Powerful Tools for libc leak",
    author="Y7n05h",
    author_email="Y7n05h@protonmail.com",
    platforms=["any"],
    license="GPL-3.0-or-later",
    url="https://github.com/Y7n05h/PowerfulLeaker",
    long_description=read_file('README.md'),
    long_description_content_type="text/markdown",
    install_requires=[
        'requests',
        'pwntools'
    ],
    packages=find_packages())
