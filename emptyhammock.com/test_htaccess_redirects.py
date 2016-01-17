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
import os
import sys
import shlex

from optparse import OptionParser
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

def validate_redirect_targets(redirect_lines, valid_urls):
    print 'Verifying that targets of redirects are in the sitemap...'
    for l in redirect_lines:
        fields = shlex.split(l)
        redirected = fields[3]

        if '$1' not in redirected:
            if redirected not in valid_urls and url_encoded(redirected) not in valid_urls:
                print 'ERROR: %s is not in the sitemap' % redirected
                print '   Directive: [%s]' % l
                print '   Maybe %s will itself get redirected to a different value?' % redirected

def url_encoded(url):
    # lame lame lame
    # use something like this in "real life": urllib2.quote(url)
    return url.replace(' ', '%20')

def test_redirects(host, port, redirect_lines):
    for l in redirect_lines:
        anchored_at_start = False
        fields = shlex.split(l)
        directive = fields[0].lower()
        assert directive == 'redirectmatch' or directive == 'redirect'
        assert fields[1] == '301'
        uri = fields[2]
        expectedloc = fields[3]

        if directive == 'redirectmatch':
            uri = uri.replace('(.*)', '___')
            if uri.endswith('$'):
                uri = uri[:-1]
            while True:
                orig_uri = uri
                if uri.startswith('^'):
                    uri = uri[1:]
                    anchored_at_start = True
                if uri.startswith('(?i)'):
                    uri = uri[4:]
                if orig_uri == uri:
                    break
        else:
            anchored_at_start = True

        if not anchored_at_start:
            # any old junk can appear at the start of the URL since the 
            # match isn't anchored at the beginning; put some junk in place
            if uri[0] == '/':
                uri = '/START-OF-URI' + uri
            else:
                uri = '/START-OF-URI/' + uri

        newloc = get_redirect(host, port, uri)
        if '$1' not in expectedloc:
            if newloc != url_encoded(fields[3]):
                print 'ERROR: expected to be redirected to [%s] instead of to [%s] from [%s]' %  (url_encoded(fields[3]), newloc, fields[2])
                print '   Directive: [%s] (%s/%s/%s/%s)' % (l, fields[0], fields[1], fields[2], fields[3])

def read_redirects(fname):
    lines = None
    with open(fname) as f:
        lines = f.read().splitlines()
    redirect_lines = [l for l in lines if l.startswith('RedirectMatch') or l.startswith('Redirect')]
    return redirect_lines

def read_valid_urls(fname):
    valid_urls = None
    with open(fname) as f:
        valid_urls = f.read().splitlines()
    return valid_urls

def main():
    htaccess_fname = '.htaccess'
    urllist_fname  = 'valid_urls.txt'
    host           = '127.0.0.1'
    port           = 80

    parser = OptionParser()
    parser.add_option("-a", "--htaccess", dest="htaccess", type="string",
                      action="store",
                      help="override default .htaccess filename (%s)" % htaccess_fname)
    parser.add_option("-v", "--valid-urls", dest="validurls", type="string",
                      action="store",
                      help="override default list of valid urls (%s)" % urllist_fname)
    parser.add_option("-p", "--port", dest="port", type="int",
                      action="store",
                      help="override default port (%d)" % port)
    parser.add_option("-o", "--host", dest="host", type="string",
                      action="store",
                      help="override default host (%s)" % host)
    (options, args) = parser.parse_args()

    if options.htaccess:
        htaccess_fname = options.htaccess

    if options.validurls:
        urllist_fname = options.validurls

    if options.host:
        host = options.host

    if options.port:
        port = options.port

    if not os.path.isfile(htaccess_fname):
        print >> sys.stderr, 'File %s does not exist, cannot perform any meaningful tests' % htaccess_fname
        sys.exit(1)

    if not os.path.isfile(urllist_fname):
        print >> sys.stderr, 'File %s does not exist, skipping any validity checking on redirect targets' % urllist_fname

    redirect_lines = read_redirects(htaccess_fname)

    if os.path.isfile(urllist_fname):
        valid_urls = read_valid_urls(urllist_fname)
        validate_redirect_targets(redirect_lines, valid_urls)

    test_redirects(host, port, redirect_lines)

if __name__ == "__main__":
    main()
