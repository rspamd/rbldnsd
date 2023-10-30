import os
import stat
import tempfile

import DNS


def get_test_directory():
    return os.path.abspath(os.path.dirname(os.path.realpath(__file__)) + "../../")


def get_top_dir():
    if os.environ.get('RBLDNSD_TOPDIR'):
        return os.environ['RBLDNSD_TOPDIR']

    return get_test_directory() + "/../../"


def make_temporary_directory():
    """Creates and returns a unique temporary directory

    Example:
    | ${RBLDNSD_TMPDIR} = | Make Temporary Directory |
    """
    dirname = tempfile.mkdtemp()
    os.chmod(dirname, stat.S_IRUSR |
             stat.S_IXUSR |
             stat.S_IWUSR |
             stat.S_IRGRP |
             stat.S_IXGRP |
             stat.S_IROTH |
             stat.S_IXOTH)
    return dirname


def query_dns(server, port, name, qtype='TXT'):
    req = DNS.Request(name=name, qtype=qtype, rd=0)
    resp = req.req(server=server, port=port)
    if resp.header['status'] == 'NOERROR':
        assert len(resp.answers) == 1
        assert len(resp.answers[0]['data']) == 1
        return 'NOERROR', resp.answers[0]['data'][0]
    return resp.header['status'], None


def reversed_ip4(ip4addr, domain='example.com'):
    revip = '.'.join(reversed(ip4addr.split('.')))
    return "%s.%s" % (revip, domain)


def reversed_ip6(ip6addr, domain='example.com'):
    return "%s.%s" % ('.'.join(reversed(_to_nibbles(ip6addr))), domain)


def _to_nibbles(ip6addr):
    """ Convert ip6 address (in rfc4291 notation) to a sequence of nibbles

    NB: We avoid the use of socket.inet_pton(AF_INET6, ip6addr) here
    because it fails (with 'error: can't use AF_INET6, IPv6 is
    disabled') when python has been compiled without IPv6 support. See
    http://www.corpit.ru/pipermail/rbldnsd/2013q3/001181.html

    """
    def _split_words(addr):
        return [ int(w, 16) for w in addr.split(':') ] if addr else []

    if '::' in ip6addr:
        head, tail = [ _split_words(s) for s in ip6addr.split('::', 1) ]
        nzeros = 8 - len(head) - len(tail)
        assert nzeros >= 0
        words = head + [ 0 ] * nzeros + tail
    else:
        words = _split_words(ip6addr)

    assert len(words) == 8
    for word in words:
        assert 0 <= word <= 0xffff

    return ''.join("%04x" % word for word in words)
