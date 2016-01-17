#!/usr/bin/env python

# Copyright 2013 Jeff Trawick, http://emptyhammock.com/
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

VERSION = '0.01'

import httplib
import sys

from urlparse import urlparse

def changed_to_lower(uri, url):
    purl = urlparse(url)
    if purl.path == uri.lower():
        return True
    return False

def get_redirect(host, port, uri):
    print 'Testing ' + uri + '...'
    conn = httplib.HTTPConnection(host, port)
    conn.request("HEAD", uri)
    res = conn.getresponse()
    if res.status == 301:
        loc = res.getheader('Location')
        print "-> " + loc
        if changed_to_lower(uri, loc):
            print 'rerunning after map to lower case...'
            purl = urlparse(loc)
            return get_redirect(host, port, purl.path)
        return loc
    print 'ERROR: non-301 status', res.status, res.reason
    return 'NOT-REDIRECTED'

def main():
    if len(sys.argv) != 4:
        print >> sys.stderr, "Usage: %s host port uri" % (sys.argv[0])
        sys.exit(1)

    host = sys.argv[1]
    port = sys.argv[2]
    uri  = sys.argv[3]

    get_redirect(host, port, uri)

if __name__ == "__main__":
    main()
