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

from pwnlib.elf.elf import ELF
import subprocess
from .Searcher import NewSearcher
from pathlib import PosixPath
from pwnlib.log import getLogger
log = getLogger(__name__)


class Rebase:
    def __init__(self, base: int = None):
        self.__base: int = base

    def __int__(self) -> int:
        if self.__base == None:
            raise RuntimeError("rebase failed")
        return self.__base

    def set_base(self, base: int):
        if (base & 0xfff) != 0:
            raise RuntimeError("addr Error")
        self.__base = base

    def status(self):
        return self.__base != None


class Search:

    def __init__(self):
        self.collect = {}
        self.search: NewSearcher = NewSearcher()
        self.base: Rebase = Rebase()

    def set_base(self):
        if self.collect == {}:
            raise RuntimeError("Empty Input")
        (name, addr) = self.collect.popitem()
        offset = self.search.dump(name)
        self.base.set_base(addr-offset)

    def __setitem__(self, name: str, addr: int):
        self.collect[name] = addr
        self.search[name] = addr

    def __getitem__(self, name: str) -> int:
        if self.base.status() == False:
            self.set_base()
        addr = self.search[name]
        return addr+int(self.base)


def SearchLibc(path: PosixPath) -> str:
    libcList = path.glob("libc*.so")
    try:
        return str(next(libcList))
    except StopIteration:
        return None


class Libc:
    def __init__(self, path: str, base: int = None):
        self.libc = None
        self.debug = None
        path = PosixPath(path)
        if path.exists() == False:
            raise FileNotFoundError("path not exist")
        if path.is_file():
            self.libc = ELF(path, checksec=False)
        elif path.is_dir():
            libcpath: str = SearchLibc(path)
            if libcpath == None:
                raise FileNotFoundError("no libc*.so")
            self.libc = ELF(libcpath, checksec=False)
            debugPath = SearchLibc(path/".debug")
            if path.exists() and path.is_dir() and debugPath != None:
                self.debug = ELF(debugPath, checksec=False)
        else:
            raise FileNotFoundError("Invalid path")
        self.symbols = self.libc.symbols
        if self.debug != None:
            self.symbols |= self.debug.symbols

        self.base: Rebase = Rebase(base)

    def __setitem__(self, name: str, addr: int):
        offset = self.libc.symbols[name]
        log.debug("addr & 0xfff "+bin(addr & 0xfff))
        log.debug("offset & 0xfff "+bin(offset & 0xfff))
        if(addr & 0xfff) != (offset & 0xfff):
            raise RuntimeError("addr Error")

        log.success("Leak "+name + " "+hex(addr))
        self.base.set_base(addr-offset)

    def __getitem__(self, key: str) -> int:
        return self.symbols[key]+int(self.base)

    def search(self, content: bytes, rebase: bool = True) -> int:
        result = self.base.rebase(next(self.libc.search(content)), rebase)
        log.success("search addr "+hex(result))
        return result

    def one_gadget(self, rebase: bool = True):
        array = [self.base.rebase(int(i), rebase) for i in subprocess.check_output(
            ['one_gadget', '--raw', self.path]).decode().split(' ')]
        log.info("one_gadget array len {}".format(len(array)))
        return array
