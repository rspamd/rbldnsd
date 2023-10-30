DUMMY_ZONE_HEADER = """
$SOA 0 example.org. hostmaster.example.com. 0 1h 1h 2d 1h
$NS 1d ns0.example.org
"""

RBLDNSD_BIN = '${TOPDIR}/rbldnsd' # this variable is expanded
RBLDNSD_PORT= 53000
RBLDNSD_SCOPE = 'Test'

SOA = 'example.com'
