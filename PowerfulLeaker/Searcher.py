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

import requests
import json


API_FIND = 'https://libc.rip/api/find'
API_LIBC = 'https://libc.rip/api/libc/'
HEADERS = {'Content-Type': 'application/json'}


def RedColor(message: str):
    return "\x1b[33m"+message+"\x1b[0m"


class NewSearcher:
    def __init__(self, name: str = None, addr: int = None, algo: str = None, value: str = None):
        self.constraint = {}
        self.libc_info = None
        self.libc_list = None
        self.vaild: bool = False
        self.symbols = {}
        if algo != None and value != None:
            self.__Search_by_Hash(algo, value)
        if name != None and addr != None:
            self.__setitem__(name, addr)

    def __Search_by_Hash(self, name: str, value: str):
        payload = {name: value}
        result = requests.post(
            API_FIND, data=json.dumps(payload), headers=HEADERS)
        self.libc_list = json.loads(result.text)
        self.__Check_Result()

    def __len__(self):
        if self.vaild == False:
            self.__Search_by_Symbol()
        if self.libc_info is None:
            return len(self.libc_list)
        return 1

    def __iter__(self):
        if self.vaild == False:
            self.__Search_by_Symbol()
        if self.libc_info is None:
            return iter([libc['id'] for libc in self.libc_list])
        else:
            return iter([self.libc_info['id']])

    def __bool__(self):
        if self.vaild == False:
            self.__Search_by_Symbol()
        return self.libc_info != None

    def __repr__(self):
        if self.vaild == False:
            self.__Search_by_Symbol()
        if self.libc_info == None:
            return RedColor("[+] Current constraints are not enough to determine a libc.")

        return "[ libc_id ] : " + self.libc_info['id'] + "\n" \
            "[ buildid ] : " + self.libc_info['buildid'] + "\n" \
            "[ dowload ] : " + self.libc_info['download_url'] + "\n" \
            "[ symbols ] : " + self.libc_info['symbols_url']

    def __setitem__(self, symbol_name: str, address: int):
        self.constraint[symbol_name] = address
        self.vaild = False

    def select_libc(self):
        for index, libc in enumerate(self.libc_list):
            print(str(index) + " - " + libc['id'])
        chosen_index = input(RedColor("[+] Choose one : "))
        try:
            self.libc_info = self.libc_list[int(chosen_index)]
            self.symbols = self.libc_info['symbols']
        except IndexError:
            print("\x1b[1;31m" +
                  "[+] Index out of bound!" +
                  "\x1b[0;m")
            self.select_libc()

    def __determine_libc_info(self):
        if self.vaild == False:
            self.__Search_by_Symbol()
            if self.libc_info != None:
                return
        assert(len(self.libc_list) > 1)
        print(
            RedColor("[+] There are multiple libc that meet current constraints :"))
        self.select_libc()

    def __Check_Result(self):
        if self.libc_list == []:
            print(RedColor("[+] No libc satisfies constraints."))
            raise RuntimeError("Search Failed")
        elif len(self.libc_list) == 1:
            self.libc_info = self.libc_list[0]
            self.symbols = self.libc_info['symbols']
        self.vaild: bool = True

    def __Search_by_Symbol(self):
        payload = {
            "symbols":
            {s_name: hex(s_addr) for s_name, s_addr in self.constraint.items()}
        }
        result = requests.post(
            API_FIND, data=json.dumps(payload), headers=HEADERS)
        self.libc_list = json.loads(result.text)
        self.__Check_Result()

    def __Query_Symbol(self,  name: str):
        libc_id = self.libc_info['id']
        payload = {
            "symbols":
            [name]
        }
        result = requests.post(
            API_LIBC+libc_id, data=json.dumps(payload), headers=HEADERS)
        self.symbols[name] = json.loads(result.text)['symbols'][name]

    def __getitem__(self, name: str) -> int:
        if self.libc_info == None:
            self.__determine_libc_info()
        if name not in self.symbols:
            self.__Query_Symbol(name)
        return int(self.symbols[name], 16)
