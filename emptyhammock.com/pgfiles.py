#!/usr/bin/env python

# Copyright 2012 Jeff Trawick, http://emptyhammock.com/
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import os
import re
import subprocess
import sys

ver = '1.02'

class Processes:
    def __init__(self):
        self.processes = []

    def add_process(self, process):
        self.processes.append(process)

class Files:
    def __init__(self):
        self.files = []

    def add_file(self, file, process):
        for f in self.files:
            if f.same_file(file):
                f.add_process(process)
                return
        self.files.append(file)

class File:
    def __init__(self, fd, process):
        self.fd = fd
        self.name = None
        self.type = None
        self.device = None
        self.processes = []
        self.processes.append(process)

    def set_type(self, type):
        self.type = type

    def set_device(self, device):
        self.device = device

    def set_name(self, name):
        self.name = name

    def set_tcpinfo(self, tcpinfo):
        pass

    def same_file(self, other_file):
        if self.type != other_file.type:
            return False

        if self.device != other_file.device:
            return False

        if self.name != other_file.name:
            return False

        if self.fd != other_file.fd:
            return False

        return True

    def add_process(self, process):
        # This should be simple, but FreeBSD 9 ports lsof 
        # duplicates output when selecting by process group.
        for p in self.processes:
            if p.same_process(process):
                return
        self.processes.append(process)

    def __str__(self):
        s = "fd " + self.fd
        if self.type:
            s += " type " + self.type
        if self.device:
            s += " dev " + self.device
        if self.name:
            s += " name " + self.name
        return s

class Process:
    def __init__(self, pid):
        self.files = []
        self.pid = pid

    def same_process(self, other_process):
        return self.pid == other_process.pid

    def add_file(self, file):
        self.files.append(file)

    def __str__(self):
        return self.pid

# keys are passed to lsof to indicate which columns are desired
# and are also used as labels in the lsof output
#
# values are names of setters on the File object which should
# be called (as 'set_FOO'); no setter is configured for info
# that requires special handling

lsof_fields = {'f': None,      # file descriptor
               'p': None,      # pid
               't': 'type',    # type
               'T': 'tcpinfo', # TCP info
               'd': 'device',  # major/minor devno
               'n': 'name',    # name
               }

# tell lsof not to report these fd-less objects
lsof_ignored_types = ('txt',
                      'rtd',
                      'cwd',
                      'mem',
                      'DEL')

def assert_in_path(exe):
    """ Die if the specified executable is not found in PATH. """
    for bin in os.environ.get('PATH', '').split(os.pathsep):
        if os.access(os.path.join(bin, exe), os.X_OK):
            return
    print >> sys.stderr, 'couldn\'t locate %s in PATH...' % exe
    sys.exit(1)

def list_pgid(pgid):
    """ Use ps to get a list of processes in the specified group. """
    assert_in_path('ps')
    cmd = ['ps', '-A', '-o', 'pid,pgid']
    p = subprocess.Popen(cmd,
                         shell=False,
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    pids = []
    prog = re.compile('^[ \t]*(\d+)[ \t]+%s$' % pgid)
    while True:
        l = p.stdout.readline()
        if not l:
            break
        m = prog.match(l.rstrip())
        if m:
            pids.append(m.group(1))

    st = p.wait()
    if st:
        print >> sys.stderr, 'ps exit status: %d' % st
        print >> sys.stderr, 'invocation: >%s<' % ' '.join(cmd)

    return pids

# -g nnn    select this process group
# FreeBSD:  lsof -P -a -p 1516,1517,1641,1642,1643 -d ^txt,^rtd,^cwd 
# Linux:    lsof -P -a -p nnn,nnn                  -d ^txt,^rtd,^cwd,^mem,^DEL

def lsof_gather(pgid):
    """ Use lsof to gather file information """
    #
    # Selecting the pids in the process group is a mess.
    #
    # lsof 4.86 on FreeBSD 9 (from ports) won't handle -p pid1,pid2,pid3
    # (it only returns files for the last pid in the list) but over-reports
    # each pid with -g.  So use -g and rely on more code in the objects above
    # to filter out the over-reporting.
    #
    # Mac OS X 10.6.8-provided lsof 4.81 won't handle -g pgid at all (nor will
    # Mac OS X 10.7.5-provided lsof 4.84).
    #
    # Ubuntu 11.10-provided lsof 4.81 works fine either way, as does lsof
    # 4.86 built from source on Solaris 10 U5.
    #
    if 'freebsd' in sys.platform:
        selection = ['-g', pgid]
    else:
        selection = ['-p', ','.join(list_pgid(pgid))]
    assert_in_path('lsof')
    cmd = ['lsof'] \
        + selection \
        + ['-w',       # we can't predict the "harmless" warnings
                       # in order to filter them out, so disable
                       # warnings altogether
           '-P', '-a',
           '-d',
           '^' + ',^'.join(lsof_ignored_types),
           '-F' + ''.join(lsof_fields)]
    p = subprocess.Popen(cmd,
                         shell=False,
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    curfile = None
    curprocess = None
    processes = Processes()
    files = Files()

    while True:
        l = p.stdout.readline()
        if not l:
            break
        l = l.rstrip()

        field = l[0]
        data = l[1:]

        if field in lsof_fields:
            setter_name = lsof_fields[field]
            if setter_name:
                getattr(curfile, 'set_' + setter_name)(data)
                continue

            if l[0] == 'p':
                if curfile and curprocess:
                    curprocess.add_file(curfile)
                    files.add_file(curfile, curprocess)

                curfile = None
                curprocess = Process(data)
                processes.add_process(curprocess)
                continue

            if l[0] == 'f':
                if curfile:
                    curprocess.add_file(curfile)
                    files.add_file(curfile, curprocess)

                curfile = File(data, curprocess)
                continue

        print >> sys.stderr, 'Unrecognized data: %s' % l

    if curfile and curprocess:
        curprocess.add_file(curfile)
        files.add_file(curfile, curprocess)

    st = p.wait()
    if st:
        print >> sys.stderr, 'lsof exit status: %d' % st
        print >> sys.stderr, 'invocation: >%s<' % ' '.join(cmd)

    return (processes, files)

def main(argv):
    if len(argv) != 2:
        print >> sys.stderr, 'Usage: %s process-group-id' % argv[0]
        sys.exit(1)

    (processes, files) = lsof_gather(argv[1])

    for f in files.files:
        print f
        print ' ',
        for p in f.processes:
            print p,
        print

if __name__ == "__main__":
    sys.exit(main(sys.argv))
