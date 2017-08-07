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

import sys
import hashlib
import re
sha1 = hashlib.sha1()
sha1_re = re.compile('^[0-9a-f]{40}$', flags=re.IGNORECASE)
# TODO: automatically compute this
block_size = 196*40 # minimum number of lines read (platform-dependent)

# TODO: user-defined maximum cache size.
# Once rstripped: Size = (lines * 40)/1e6   MBytes
#   lines = S_max * 1e6/40.     [where S_max is in MBytes], up to round to block_size




def detect_sha1(passwd):
    """
    Detects if a password is a SHA1 digest.
    """
    match_result = sha1_re.findall(passwd)
    return (match_result != [])





if __name__ == "__main__":

    # TODO parse arguments: -f <database.txt>

    args = sys.argv[1:]
    if args == []:
        print("Usage: %s <password>" % sys.argv[0])
        sys.exit(1)
    passwd = args[0]
    if not(detect_sha1(passwd)):
        print("hashing")
        sha1.update(passwd)
        passwd = sha1.hexdigest().upper()
    else:
        passwd = passwd.upper()

    print(passwd)
    first_two_letters = passwd[:2]
    first_letters_val = int(passwd[:10], 16)

    fid = open("pwned-passwords-1.0.txt", "r") # TODO custom file name



    first_line = fid.readline()
    begin_pos = 0
    fid.seek(-42, 2) # TODO check if this mechanism works at class instanciation
    end_pos = fid.tell()
    last_line = fid.readline()

    begin_val = int(first_line[:10], 16) # TODO try :4, ..., :10  for best performances
    end_val = int(last_line[:10], 16)


    # Bisection search (sorted database)
    while end_pos - begin_pos > 196*42*1000:
        mid_pos = (end_pos + begin_pos)//2
        if (mid_pos % 42):
            mid_pos -= (mid_pos % 42)
        assert((mid_pos % 42) == 0)
        fid.seek(mid_pos)
        mid_line = fid.readline()
        mid_val = int(mid_line[:10], 16)

        print("v: %s \t c: %s" % (passwd[:10], mid_line.rstrip()))
        print("v=%d (?)> c=%d" % (first_letters_val, mid_val))
        if first_letters_val > mid_val:
            prev_begin_pos = begin_pos
            begin_pos = mid_pos
        else:
            end_pos = mid_pos

        print("Search between %d and %d" % (begin_pos, end_pos))

    #~ begin_pos -= 42*1600000
    # TODO: seek "early enough", difficult to guess when "many" iterations of bisection
    assert((prev_begin_pos % 42) == 0)
    fid.seek(prev_begin_pos)


    pass_found = 0
    while not(pass_found): # TODO user "max-time"
        lines = fid.readlines(196*40*1000) # TODO: block size
        if lines == []:
            break
        print("Read %d lines" % len(lines))

        print("Start: %s" % lines[0][:2])
        if int(first_two_letters, 16) < int(lines[0][:2], 16):
            break # cf previous Bisection

        lines = map(lambda x : x.rstrip(), lines)
        hashtable = dict.fromkeys(lines)
        if hashtable.has_key(passwd):
            pass_found = 1 # TODO line number ?
    fid.close()

    if pass_found:
        print("Password found !")
    else:
        print("Password not found")


















