#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2017 Pierre Paleo <pierre.paleo@gringalet.fr>
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# * Redistributions of source code must retain the above copyright notice, this
#   list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
#
# * Neither the name of SPIRE nor the names of its
#   contributors may be used to endorse or promote products derived from
#   this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

import hashlib
import re
import argparse
import logging
logging.basicConfig(filename='passwordcheck_debug.log', filemode='w',
                    format='%(asctime)s %(levelname)s %(message)s',
                    datefmt='%m/%d/%Y %I:%M:%S', level=logging.DEBUG)


# TODO: user-defined maximum cache size.
# Once rstripped: Size = (lines * 40)/1e6   MBytes
#   lines = S_max * 1e6/40.     [where S_max is in MBytes], up to round to block_size


# TODO: cache bisection, build an index
#    00 -> 0
#    01 -> ...
#    A0 ->  ...


class PasswordChecker(object):
    """
    Check if a password is in a database of "leaked" passwords.
    """

    sha1_re = re.compile('^[0-9a-f]{40}$', flags=re.IGNORECASE)

    def __init__(self, db_fname):
        self.db_fname = db_fname
        self.fid = open(db_fname, "r")
        self.get_buffer_size()
        self.nlines = 1000 # TODO: user-defined (eg. from max bytes)


    def get_buffer_size(self):
        lines = self.fid.readlines(1)
        self.buffsize = len(lines)
        self.itemsize = len(lines[0])
        self.fid.seek(0)


    def detect_sha1(self, passwd):
        """
        Detects if a password is a SHA1 digest.
        """
        match_result = self.sha1_re.findall(passwd)
        return (match_result != [])


    def hash_password_if_necessary(self, passwd):
        if not(self.detect_sha1(passwd)):
            logging.debug("hashing")
            res = hashlib.sha1(passwd).hexdigest()
        else:
            logging.debug("not hashing")
            res = passwd
        res = res.upper()
        logging.debug("Password: %s" % res)
        return res


    def bisection_search(self, passwd):
        first_letters_val = int(passwd[:10], 16)

        begin_pos = 0
        first_line = self.fid.readline()
        begin_val = int(first_line[:10], 16) # TODO try :4, ..., :10  for best performances

        # TODO check if this mechanism is actually working on the current platform
        self.fid.seek(-self.itemsize, 2)
        end_pos = self.fid.tell()
        last_line = self.fid.readline()
        end_val = int(last_line[:10], 16) # TODO

        while end_pos - begin_pos > self.buffsize*self.itemsize*self.nlines/10: # TODO: custom bound
            mid_pos = (end_pos + begin_pos)//2
            if (mid_pos % self.itemsize):
                mid_pos -= (mid_pos % self.itemsize)
            self.fid.seek(mid_pos)
            mid_line = self.fid.readline()
            mid_val = int(mid_line[:10], 16)
            logging.debug("v: %s \t c: %s" % (passwd[:10], mid_line.rstrip()))
            logging.debug("v=%d (?)> c=%d" % (first_letters_val, mid_val))
            if first_letters_val > mid_val:
                prev_begin_pos = begin_pos
                begin_pos = mid_pos
            else:
                end_pos = mid_pos
            logging.debug("Search between %d and %d" % (begin_pos, end_pos))

        if (prev_begin_pos % self.itemsize):
            prev_begin_pos -= (prev_begin_pos % self.itemsize)
        return prev_begin_pos


    def linear_search(self, passwd, search_pos):
        self.fid.seek(search_pos)
        first_two_letters_val = int(passwd[:2], 16)
        pass_found = 0
        nbytes = self.buffsize * self.itemsize * self.nlines
        while not(pass_found):
            lines = self.fid.readlines(nbytes)
            if lines == []:
                break
            logging.debug("Read %d lines" % len(lines))
            logging.debug("Start: %s" % lines[0][:2])
            if first_two_letters_val < int(lines[0][:2], 16):
                break # cf previous Bisection
            # Build sub-hashtable from read lines
            lines = map(lambda x : x.rstrip(), lines)
            hashtable = dict.fromkeys(lines)
            if hashtable.has_key(passwd):
                pass_found = 1 # TODO location (lines interval) in file ?
        return pass_found


    def check_password(self, passwd):
        passwd = self.hash_password_if_necessary(passwd)
        search_pos = self.bisection_search(passwd)
        res = self.linear_search(passwd, search_pos)
        return res


    def __del__(self):
        self.fid.close()

    __call__ = check_password



if __name__ == "__main__":

    arg_parser = argparse.ArgumentParser(description='Find whether a password (or hash) has been pwned')
    arg_parser.add_argument('-f', '--filename', metavar='filename',
                            help='File containing one SHA1 per line, sorted in ascending order (text format)')
    arg_parser.add_argument('password', nargs='+', help='password or SHA1 to check')
    args = arg_parser.parse_args()

    if args.filename:
        db_fname = args.filename
    else:
        db_fname = "pwned-passwords-1.0.txt"
    passwd = " ".join(args.password)


    C = PasswordChecker(db_fname)
    pass_found = C(passwd)

    if pass_found:
        print("Password found !")
    else:
        print("Password not found")

