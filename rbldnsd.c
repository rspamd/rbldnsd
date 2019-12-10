/* rbldnsd: main program
 */

#define _LARGEFILE64_SOURCE /* to define O_LARGEFILE if supported */

#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h> /* for bool */
#include <errno.h>
#include <pwd.h>
#include <grp.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <syslog.h>
#include <time.h>
#include <sys/time.h>	/* some systems can't include time.h and sys/time.h */
#include <fcntl.h>
#include <sys/wait.h>
#include "ev.h"
#include "rbldnsd.h"
#include "sds/sds.h"


#ifndef NO_SELECT_H
# include <sys/select.h>
#endif
#ifndef NO_POLL
# include <poll.h>
#endif

#ifdef WITH_JEMALLOC
#include <jemalloc/jemalloc.h>
#else
#ifndef NO_MEMINFO
#if defined(__APPLE__)
#include <malloc/malloc.h>
#endif

#if defined(__linux__)
#include <malloc.h>
#endif


#if defined(__FreeBSD__)
#include <malloc_np.h>
#endif
#endif

#endif
#ifndef NO_TIMES
# include <sys/times.h>
#endif
#ifndef NO_STDINT_H
/* if system have stdint.h, assume it have inttypes.h too */
# include <inttypes.h>
#endif
#ifndef NO_STATS
# ifndef NO_IOVEC
#  include <sys/uio.h>
#  define STATS_IPC_IOVEC 1
# endif
#endif
#ifndef NO_DSO
# include <dlfcn.h>
#endif

#ifndef NI_MAXHOST
# define NI_MAXHOST 1025
#endif
#ifndef NI_MAXSERV
# define NI_MAXSERV 32
#endif

#ifndef O_LARGEFILE
# define O_LARGEFILE 0
#endif

const char *version = VERSION;
const char *show_version = "rbldnsd " VERSION;
/* version to show in version.bind CH TXT reply */
char *progname; /* limited to 32 chars */
int logto;

void error(int errnum, const char *fmt, ...) {
  char buf[256];
  int l, pl;
  va_list ap;
  l = pl = ssprintf(buf, sizeof(buf), "%.30s: ", progname);
  va_start(ap, fmt);
  l += vssprintf(buf + l, sizeof(buf) - l, fmt, ap);
  if (errnum)
    l += ssprintf(buf + l, sizeof(buf) - l, ": %.50s", strerror(errnum));
  if (logto & LOGTO_SYSLOG) {
    fmt = buf + pl;
    syslog(LOG_ERR, strchr(fmt, '%') ? "%s" : fmt, fmt);
  }
  buf[l++] = '\n';
  write(2, buf, l);
  _exit(1);
}

static unsigned recheck = 60;	/* interval between checks for reload */
static int initialized;		/* 1 when initialized */
static char *logfile;		/* log file name */
#ifndef NO_STATS
static char *statsfile;		/* statistics file */
static int stats_relative;	/* dump relative, not absolute, stats */
#endif
int accept_in_cidr;		/* accept 127.0.0.1/8-"style" CIDRs */
int nouncompress;		/* disable on-the-fly decompression */
unsigned def_ttl = 35*60;	/* default record TTL 35m */
unsigned min_ttl, max_ttl;	/* TTL constraints */
const char def_rr[5] = "\177\0\0\2\0";		/* default A RR */

#define MAXSOCK	20	/* maximum # of supported sockets */
static int sock[MAXSOCK];	/* array of active sockets */
static int update_sock = -1; /* used for dynamic updates */
static int numsock;		/* number of active sockets in sock[] */
static FILE *flog;		/* log file */
static int flushlog;		/* flush log after each line */
static struct zone *zonelist;	/* list of zones we're authoritative for */
static int numzones;		/* number of zones in zonelist */
int lazy;			/* don't return AUTH section by default */
static int fork_on_reload; /* >0 - perform fork on reloads, <0 - this is a child of reloading parent */
static int can_reload; /* block reload when another reload is there */
static int pending_reload = 0;
static ev_signal ev_hup, ev_usr1, ev_usr2, ev_term, ev_int;
#if STATS_IPC_IOVEC
static struct iovec *stats_iov;
#endif
#ifndef NO_DSO
hook_reload_check_t hook_reload_check;
hook_reload_t hook_reload;
hook_query_access_t hook_query_access;
hook_query_result_t hook_query_result;
#endif

/* a list of zonetypes. */
const struct dstype *ds_types[] = {
  dstype(ip4set),
  dstype(ip4tset),
  dstype(ip4trie),
  dstype(ip6tset),
  dstype(ip6trie),
  dstype(dnset),
  dstype(dnhash),
  dstype(dnhash_fixed),
  dstype(combined),
  dstype(generic),
  dstype(acl),
  dstype(aclkey),
  NULL
};

static int do_reload(int do_fork, struct ev_loop *loop);

static int satoi(const char *s) {
  int n = 0;
  if (*s < '0' || *s > '9') return -1;
  do n = n * 10 + (*s++ - '0');
  while (*s >= '0' && *s <= '9');
  return *s ? -1 : n;
}

static void NORETURN usage(int exitcode) {
   const struct dstype **dstp;
   printf(
"%s: rbl dns daemon version %s\n"
"Usage is: %s options zonespec...\n"
"where options are:\n"
" -u user[:group] - run as this user:group (rbldns)\n"
" -r rootdir - chroot to this directory\n"
" -w workdir - working directory with zone files\n"
" -b address[/port] - bind to (listen on) this address (required)\n"
#ifndef NO_IPv6
" -4 - use IPv4 socket type\n"
" -6 - use IPv6 socket type\n"
#endif
" -t ttl - default TTL value to set in answers (35m)\n"
" -v - hide version information in replies to version.bind CH TXT\n"
"  (second -v makes rbldnsd to refuse such requests completely)\n"
" -e - enable CIDR ranges where prefix is not on the range boundary\n"
"  (by default ranges such 127.0.0.1/8 will be rejected)\n"
" -c check - time interval to check for data file updates (1m)\n"
" -p pidfile - write pid to specified file\n"
" -n - do not become a daemon\n"
" -f - fork a child process while reloading zones, to process requests\n"
"  during reload (may double memory requiriments)\n"
" -q - quickstart, load zones after backgrounding\n"
" -l [+]logfile - log queries and answers to this file (+ for unbuffered)\n"
" -U address/port or unix socket - socket credentials for updates\n"
#ifndef NO_STATS
" -s [+]statsfile - write a line with short statistics summary into this\n"
"  file every `check' (-c) secounds, for rrdtool-like applications\n"
"  (+ to log relative, not absolute, statistics counters)\n"
#endif
" -a - omit AUTH section from regular replies, do not return list of\n"
"  nameservers, but only return NS info when explicitly asked.\n"
"  This is an equivalent of bind9 \"minimal-answers\" setting.\n"
"  In future versions this mode will be the default.\n"
" -A - put AUTH section in every reply.\n"
" -F facility - Log facility for syslog. Default is 'daemon'.\n"
#ifndef NO_ZLIB
" -C - disable on-the-fly decompression of dataset files\n"
#endif
#ifndef NO_DZO
" -x extension - load given extension module (.so file)\n"
" -X extarg - pass extarg to extension init routine\n"
#endif
" -d - dump all zones in BIND format to standard output and exit\n"
"each zone specified using `name:type:file,file...'\n"
"syntax, repeated names constitute the same zone.\n"
"Available dataset types:\n"
, progname, version, progname);
  for(dstp = ds_types; *dstp; ++dstp)
    printf(" %s - %s\n", (*dstp)->dst_name, (*dstp)->dst_descr);
  exit(exitcode);
}

static inline int sockaddr_in_equal(const struct sockaddr_in *addr1,
                                    const struct sockaddr_in *addr2)
{
  return (addr1->sin_port == addr2->sin_port
          && addr1->sin_addr.s_addr == addr2->sin_addr.s_addr);
}

#ifndef NO_IPv6
static inline int sockaddr_in6_equal(const struct sockaddr_in6 *addr1,
                                     const struct sockaddr_in6 *addr2)
{
  if (memcmp(addr1->sin6_addr.s6_addr, addr2->sin6_addr.s6_addr, 16) != 0)
    return 0;
  return (addr1->sin6_port == addr2->sin6_port
          && addr1->sin6_flowinfo == addr2->sin6_flowinfo
          && addr1->sin6_scope_id == addr2->sin6_scope_id);
}
#endif

static inline int sockaddr_equal(const struct sockaddr *addr1,
                                 const struct sockaddr *addr2)
{
  if (addr1->sa_family != addr2->sa_family)
    return 0;
  switch (addr1->sa_family) {
  case AF_INET:
    return sockaddr_in_equal((const struct sockaddr_in *)addr1,
                             (const struct sockaddr_in *)addr2);
#ifndef NO_IPv6
  case AF_INET6:
    return sockaddr_in6_equal((const struct sockaddr_in6 *)addr1,
                              (const struct sockaddr_in6 *)addr2);
#endif
    default:
      error(0, "unknown address family (%d)", addr1->sa_family);
  }
}

/* already_bound(addr, addrlen)
 *
 * Determine whether we've already bound to a particular address.
 * This is here mostly to deal with the fact that on certain systems,
 * gethostbyname()/getaddrinfo() can return a duplicate 127.0.0.1
 * for 'localhost'.  See
 *   - http://sourceware.org/bugzilla/show_bug.cgi?id=4980
 *   - https://bugzilla.redhat.com/show_bug.cgi?id=496300
 */
static int already_bound(const struct sockaddr *addr, socklen_t addrlen) {
#ifdef NO_IPv6
  struct sockaddr_in addr_buf;
#else
  struct sockaddr_in6 addr_buf;
#endif
  struct sockaddr *boundaddr = (struct sockaddr *)&addr_buf;
  socklen_t buflen;
  int i;

  for (i = 0; i < numsock; i++) {
    buflen = sizeof(addr_buf);
    if (getsockname(sock[i], boundaddr, &buflen) < 0)
      error(errno, "getsockname failed");
    if (buflen == addrlen && sockaddr_equal(boundaddr, addr))
      return 1;
  }
  return 0;
}

#ifdef NO_IPv6
static void newsocket(struct sockaddr_in *sin) {
  int fd;
  const char *host = ip4atos(ntohl(sin->sin_addr.s_addr));

  if (already_bound((struct sockaddr *)sin, sizeof(*sin)))
    return;
  if (numsock >= MAXSOCK)
    error(0, "too many listening sockets (%d max)", MAXSOCK);
  fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (fd < 0)
    error(errno, "unable to create socket");
  if (bind(fd, (struct sockaddr *)sin, sizeof(*sin)) < 0)
    error(errno, "unable to bind to %s/%d", host, ntohs(sin->sin_port));

  dslog(LOG_INFO, 0, "listening on %s/%d", host, ntohs(sin->sin_port));
  sock[numsock++] = fd;
}
#else
static int newsocket(struct addrinfo *ai) {
  int fd;
  char host[NI_MAXHOST], serv[NI_MAXSERV];

  if (already_bound(ai->ai_addr, ai->ai_addrlen))
    return -1;
  if (numsock >= MAXSOCK)
    error(0, "too many listening sockets (%d max)", MAXSOCK);
  fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
  if (fd < 0) {
    if (errno == EAFNOSUPPORT) return 0;
    error(errno, "unable to create socket");
  }
  getnameinfo(ai->ai_addr, ai->ai_addrlen,
              host, sizeof(host), serv, sizeof(serv),
              NI_NUMERICHOST|NI_NUMERICSERV);
  if (bind(fd, ai->ai_addr, ai->ai_addrlen) < 0)
        error(errno, "unable to bind to %s/%s", host, serv);

  dslog(LOG_INFO, 0, "listening on %s/%s", host, serv);

  return fd;
}
#endif

static int newsocket_unix(const char *path)
{
  int nelts, i, fd;
  sds *elts = sdssplitlen(path, strlen(path), ":", 1, &nelts);
  struct sockaddr_un un;
  unsigned mode = 00644;
  size_t pwlen;
  char *pwbuf, *p;
  struct passwd pw, *ppw;
  struct group gr, *pgr;
  uid_t owner = (uid_t)-1;
  gid_t group = (gid_t)-1;
  int has_group = false;

  if (nelts < 1) {
    error(0, "invalid path: %s", path);
  }

  estrlcpy(un.sun_path, elts[0], sizeof (un.sun_path));
#if defined(FREEBSD) || defined(__APPLE__)
  un.sun_len = SUN_LEN (&un);
#endif

#ifdef _SC_GETPW_R_SIZE_MAX
  pwlen = sysconf (_SC_GETPW_R_SIZE_MAX);
  if (pwlen <= 0) {
    pwlen = 8192;
  }
#else
  pwlen = 8192;
#endif

  pwbuf = emalloc(pwlen);

  for (i = 1; i < nelts; i ++) {
    if (strncmp(elts[i], "mode=", sizeof ("mode=") - 1) == 0) {
      p = strchr(elts[i], '=');
      /* XXX: add error check */
      mode = strtoul (p + 1, NULL, 8);

      if (mode == 0) {
        error(0, "bad mode: %s", p + 1);
      }
    }
    else if (strncmp(elts[i], "owner=", sizeof ("owner=") - 1) == 0) {
      p = strchr(elts[i], '=');

      if (getpwnam_r(p + 1, &pw, pwbuf, pwlen, &ppw) != 0 || ppw == NULL) {
        error(errno, "bad user: %s", p + 1);
      }

      owner = pw.pw_uid;

      if (!has_group) {
        group = pw.pw_gid;
      }
    }
    else if (strncmp(elts[i], "group=", sizeof ("group=") - 1) == 0) {
      p = strchr(elts[i], '=');

      if (getgrnam_r(p + 1, &gr, pwbuf, pwlen, &pgr) != 0 || pgr == NULL) {
        error(errno, "bad group: %s", p + 1);
      }

      has_group = true;
      group = gr.gr_gid;
    }
  }

  sdsfreesplitres(elts, nelts);
  free(pwbuf);

  fd = socket(AF_UNIX, SOCK_DGRAM, 0);

  if (fd == -1) {
    error(errno, "unable to create socket");
  }

  if (bind(fd, (struct sockaddr *)&un, sizeof(un)) < 0) {
    error(errno, "unable to bind to unix socket: %s", path);
  }

  if (owner != (uid_t)-1 || group != (gid_t)-1) {
    if (chown(un.sun_path, owner, group) == -1) {
      error(errno, "cannot change owner for %s to %d:%d: %s",
            un.sun_path, (int)owner, (int)group,
            strerror(errno));
    }
  }

  if (chmod(un.sun_path, mode) == -1) {
    error(errno, "cannot change mode for %s to %od %s",
          un.sun_path, mode, strerror(errno));
  }

  dslog(LOG_INFO, 0, "listening on %s", un.sun_path);
  return fd;
}

static int
initsockets(const char *bindaddr[MAXSOCK], int *dest, int nba, int UNUSED family) {

  int i, x, cur_sock = 0;
  char *host, *serv;
  const char *ba;

  struct addrinfo hints, *aires, *ai;

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = family;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_flags = AI_PASSIVE;

  for (i = 0; i < nba; ++i) {
    ba = bindaddr[i];

    if (ba[0] == '/' || ba[0] == '.') {
      int nfd = newsocket_unix(ba);

      if (nfd != -1) {
        dest[cur_sock++] = nfd;
      }
    }
    else {
      host = estrdup(ba);

      serv = strchr(host, '/');
      if (serv) {
        *serv++ = '\0';
        if (!*host)
          error(0, "missing host part in bind address `%.60s'", ba);
      }

      if (!serv || !*serv)
        serv = "domain";

      x = getaddrinfo(host, serv, &hints, &aires);
      if (x != 0)
        error(0, "%.60s: %s", ba, gai_strerror(x));
      for (ai = aires, x = 0; ai; ai = ai->ai_next) {
        int nfd = newsocket(ai);
        if (nfd != -1) {
          ++x;
          dest[cur_sock++] = nfd;
        }
      }
      if (!x)
        error(0, "%.60s: no available protocols", ba);
      freeaddrinfo(aires);
      free(host);
    }
  }
  endservent();
  endhostent();

  for (i = 0; i < cur_sock; ++i) {
    x = 65536;
    do {
      if (setsockopt(dest[i], SOL_SOCKET, SO_RCVBUF, (void *) &x, sizeof x) == 0) {
        break;
      }
    } while ((x -= (x >> 5)) >= 1024);
  }

  return cur_sock;
}

static struct {
    int facility;
    const char *name;
} facility_names[] = {
    { LOG_AUTH,         "auth" },
    { LOG_AUTHPRIV,     "authpriv" },
    { LOG_CRON,         "cron" },
    { LOG_DAEMON,       "daemon" },
    { LOG_FTP,          "ftp" },
    { LOG_KERN,         "kern" },
    { LOG_LOCAL0,       "local0" },
    { LOG_LOCAL1,       "local1" },
    { LOG_LOCAL2,       "local2" },
    { LOG_LOCAL3,       "local3" },
    { LOG_LOCAL4,       "local4" },
    { LOG_LOCAL5,       "local5" },
    { LOG_LOCAL6,       "local6" },
    { LOG_LOCAL7,       "local7" },
    { LOG_LPR,          "lpr" },
    { LOG_MAIL,         "mail" },
    { LOG_NEWS,         "news" },
    { LOG_SYSLOG,       "syslog" },
    { LOG_USER,         "user" },
    { LOG_UUCP,         "uucp" },
};

static int logfacility_lookup(const char *facility, int *logfacility) {
    unsigned int t;

    if ( logfacility == NULL ) {
        return 0;
    }

    for ( t=0; t < sizeof(facility_names) / sizeof(facility_names[0]); t++ ) {
        if ( !strncmp(facility_names[t].name, facility, strlen(facility_names[t].name)+1) ) {
            *logfacility = facility_names[t].facility;
            return 1;
        }
    }

    *logfacility = LOG_DAEMON;

    return 0;
}

static void init(int argc, char **argv, struct ev_loop *loop) {
  int c;
  char *p;
  const char *user = NULL;
  const char *rootdir = NULL, *workdir = NULL, *pidfile = NULL, *facility = NULL;
  const char *bindaddr[MAXSOCK];
  const char *update_addr = NULL;
  int logfacility;
  int nba = 0;
  uid_t uid = 0;
  gid_t gid = 0;
  int nodaemon = 0, quickstart = 0, dump = 0, nover = 0, forkon = 0, dry_run = 0;
  int family = AF_UNSPEC;
  int cfd = -1;
  const struct zone *z;
#ifndef NO_DSO
  char *ext = NULL, *extarg = NULL;
  int (*extinit)(const char *arg, struct zone *zonelist) = NULL;
#endif

  if ((progname = strrchr(argv[0], '/')) != NULL)
    argv[0] = ++progname;
  else
    progname = argv[0];

  if (argc <= 1) usage(1);

  while((c = getopt(argc, argv, "u:r:b:w:t:c:p:nel:qs:h46dvaAfF:Cx:X:DU:")) != EOF)
    switch(c) {
    case 'u': user = optarg; break;
    case 'r': rootdir = optarg; break;
    case 'b':
      if (nba >= MAXSOCK)
        error(0, "too many addresses to listen on (%d max)", MAXSOCK);
      bindaddr[nba++] = optarg;
      break;
    case 'U':
      update_addr = optarg;
      break;
#ifndef NO_IPv6
    case '4': family = AF_INET; break;
    case '6': family = AF_INET6; break;
#else
    case '4': break;
    case '6': error(0, "IPv6 support isn't compiled in");
#endif
    case 'w': workdir = optarg; break;
    case 'p': pidfile = optarg; break;
    case 't':
      p = optarg;
      if (*p == ':') ++p;
      else {
        if (!(p = parse_time(p, &def_ttl)) || !def_ttl ||
            (*p && *p++ != ':'))
          error(0, "invalid ttl (-t) value `%.50s'", optarg);
      }
      if (*p == ':') ++p;
      else if (*p) {
        if (!(p = parse_time(p, &min_ttl)) || (*p && *p++ != ':'))
          error(0, "invalid minttl (-t) value `%.50s'", optarg);
      }
      if (*p == ':') ++p;
      else if (*p) {
        if (!(p = parse_time(p, &max_ttl)) || (*p && *p++ != ':'))
          error(0, "invalid maxttl (-t) value `%.50s'", optarg);
      }
      if (*p)
        error(0, "invalid value for -t (ttl) option: `%.50s'", optarg);
      if ((min_ttl && max_ttl && min_ttl > max_ttl) ||
          (min_ttl && def_ttl < min_ttl) ||
          (max_ttl && def_ttl > max_ttl))
        error(0, "inconsistent def:min:max ttl: %u:%u:%u",
              def_ttl, min_ttl, max_ttl);
      break;
    case 'c':
      if (!(p = parse_time(optarg, &recheck)) || *p)
        error(0, "invalid check interval (-c) value `%.50s'", optarg);
      break;
    case 'n': nodaemon = 1; break;
    case 'e': accept_in_cidr = 1; break;
    case 'l':
      logfile = optarg;

      if (*logfile != '+') {
        flushlog = 0;
      }
      else {
        ++logfile;
        flushlog = 1;
      }

      if (!*logfile) {
        logfile = NULL;
        flushlog = 0;
      }
      else if (logfile[0] == '-' && logfile[1] == '\0') {
        /* No need to reopen stdout */
        logfile = NULL;
        flog = stdout;
      }
      break;
break;
    case 's':
#ifdef NO_STATS
      fprintf(stderr,
        "%s: warning: no statistics counters support is compiled in\n",
        progname);
#else
      statsfile = optarg;
      if (*statsfile != '+') stats_relative = 0;
      else ++statsfile, stats_relative = 1;
      if (!*statsfile) statsfile = NULL;
#endif
      break;
    case 'q': quickstart = 1; break;
    case 'd':
      dump = 1;
      break;
    case 'D': dry_run = 1; break;
    case 'v': show_version = nover++ ? NULL : "rbldnsd"; break;
    case 'a': lazy = 1; break;
    case 'A': lazy = 0; break;
    case 'f': forkon = 1; break;
    case 'F': facility = optarg; break;
    case 'C': nouncompress = 1; break;
#ifndef NO_DSO
    case 'x': ext = optarg; break;
    case 'X': extarg = optarg; break;
#else
    case 'x':
    case 'X':
      error(0, "extension support is not compiled in");
#endif
    case 'h': usage(0);
    default: error(0, "type `%.50s -h' for help", progname);
    }
    /* options switch end */

  if (!(argc -= optind))
    error(0, "no zone(s) to service specified (-h for help)");
  argv += optind;

  if (dump || dry_run) {
    time_t now;
    logto = LOGTO_STDERR;
    for(c = 0; c < argc; ++c)
      zonelist = addzone(zonelist, argv[c]);
    init_zones_caches(zonelist);
    if (rootdir && (chdir(rootdir) < 0 || chroot(rootdir) < 0))
      error(errno, "unable to chroot to %.50s", rootdir);
    if (workdir && chdir(workdir) < 0)
      error(errno, "unable to chdir to %.50s", workdir);
    if (!do_reload(0, loop))
      error(0, "zone loading errors, aborting");

    if (dump) {
      now = time(NULL);
      printf("; zone dump made %s", ctime(&now));
      printf("; rbldnsd version %s\n", version);
      for (z = zonelist; z; z = z->z_next)
        dumpzone(z, stdout);
      fflush(stdout);
      exit(ferror(stdout) ? 1 : 0);
    }
    else {
      /* Dry run */
      printf("zones loaded successfully\n");
      fflush(stdout);
      exit(ferror(stdout) ? 1 : 0);
    }
  }

  if (!nba)
    error(0, "no address to listen on (-b option) specified");

  if ( facility == NULL ) {
    logfacility = LOG_DAEMON;
  }
  else {
    if ( logfacility_lookup(facility, &logfacility) == 0 ) {
      error(0, "log facility %s is not valid", facility);
    }
  }

  tzset();
  if (nodaemon)
    logto = LOGTO_STDOUT|LOGTO_STDERR;
  else
  {
    /* fork early so that logging will be from right pid */
    int pfd[2];
    if (pipe(pfd) < 0) error(errno, "pipe() failed");
    c = fork();
    if (c < 0) error(errno, "fork() failed");
    if (c > 0) {
      close(pfd[1]);
      if (read(pfd[0], &c, 1) < 1) exit(1);
      else exit(0);
    }

    /* Forked process */
    ev_loop_fork(loop);
    cfd = pfd[1];
    close(pfd[0]);


    openlog(progname, LOG_PID|LOG_NDELAY, logfacility);
    logto = LOGTO_STDERR|LOGTO_SYSLOG;
    if (!quickstart && !flog) logto |= LOGTO_STDOUT;
  }

  numsock = initsockets(bindaddr, sock, nba, family);

  if (update_addr) {
    if (initsockets(&update_addr, &update_sock, 1, family) != 1) {
      error(0, "unable to listen for updates on `%s'", update_addr);
    }
  }

#ifndef NO_DSO
  if (ext) {
    void *handle = dlopen(ext, RTLD_NOW);
    if (!handle)
      error(0, "unable to load extension `%s': %s", ext, dlerror());
    extinit = dlsym(handle, "rbldnsd_extension_init");
    if (!extinit)
      error(0, "unable to find extension init routine in `%s'", ext);
  }
#endif

  if (!user && !(uid = getuid()))
    user = "rbldns";

  if (!user)
    p = NULL;
  else {
    if ((p = strchr(user, ':')) != NULL)
      *p++ = '\0';
    if ((c = satoi(user)) >= 0)
      uid = c, gid = c;
    else {
      struct passwd *pw = getpwnam(user);
      if (!pw)
        error(0, "unknown user `%s'", user);
      uid = pw->pw_uid;
      gid = pw->pw_gid;
      endpwent();
    }
  }
  if (!uid)
    error(0, "daemon should not run as root, specify -u option");
  if (p) {
    if ((c = satoi(p)) >= 0)
      gid = c;
    else {
      struct group *gr = getgrnam(p);
      if (!gr)
        error(0, "unknown group `%s'", p);
      gid = gr->gr_gid;
      endgrent();
    }
    p[-1] = ':';
  }

  if (pidfile) {
    int fdpid;
    char buf[40];
    c = sprintf(buf, "%ld\n", (long)getpid());
    fdpid = open(pidfile, O_CREAT|O_WRONLY|O_TRUNC, 0644);
    if (fdpid < 0 || write(fdpid, buf, c) < c)
      error(errno, "unable to write pidfile");
    close(fdpid);
  }

  if (rootdir && (chdir(rootdir) < 0 || chroot(rootdir) < 0))
    error(errno, "unable to chroot to %.50s", rootdir);
  if (workdir && chdir(workdir) < 0)
    error(errno, "unable to chdir to %.50s", workdir);

  if (user)
    if (setgroups(1, &gid) < 0 || setgid(gid) < 0 || setuid(uid) < 0)
      error(errno, "unable to setuid(%d:%d)", (int)uid, (int)gid);

  for(c = 0; c < argc; ++c)
    zonelist = addzone(zonelist, argv[c]);
  init_zones_caches(zonelist);

#ifndef NO_DSO
  if (extinit && extinit(extarg, zonelist) != 0)
    error(0, "unable to iniitialize extension `%s'", ext);
#endif

  if (!quickstart && !do_reload(0, loop))
    error(0, "zone loading errors, aborting");

  /* count number of zones */
  for(c = 0, z = zonelist; z; z = z->z_next)
    ++c;
  numzones = c;

#if STATS_IPC_IOVEC
  stats_iov = (struct iovec *)emalloc(numzones * sizeof(struct iovec));
  for(c = 0, z = zonelist; z; z = z->z_next, ++c) {
    stats_iov[c].iov_base = (char*)&z->z_stats;
    stats_iov[c].iov_len = sizeof(z->z_stats);
  }
#endif
  dslog(LOG_INFO, 0, "rbldnsd version %s started (%d socket(s), %d zone(s))",
        version, numsock, numzones);
  initialized = 1;

  if (cfd >= 0) {
    write(cfd, "", 1);
    close(cfd);
    close(0); close(2);
    if (!flog) close(1);
    setsid();
    logto = LOGTO_SYSLOG;
  }

  if (quickstart)
    do_reload(0, loop);

  /* only set "main" fork_on_reload after first reload */
  fork_on_reload = forkon;
}

#ifndef NO_STATS

struct dnsstats gstats;
static struct dnsstats gptot;
static time_t stats_time;

static void dumpstats(void) {
  struct dnsstats tot;
  char name[DNS_MAXDOMAIN+1];
  FILE *f;
  struct zone *z;

  f = fopen(statsfile, "a");

  if (f)
    fprintf(f, "%ld", (long)time(NULL));

#define C ":%" PRI_DNSCNT
  tot = gstats;
  for(z = zonelist; z; z = z->z_next) {
#define add(x) tot.x += z->z_stats.x
    add(b_in); add(b_out);
    add(q_ok); add(q_nxd); add(q_err);
#undef add
    if (f) {
      dns_dntop(z->z_dn, name, sizeof(name));
#define delta(x) z->z_stats.x - z->z_pstats.x
      fprintf(f, " %s" C C C C C,
        name,
        delta(q_ok) + delta(q_nxd) + delta(q_err),
        delta(q_ok), delta(q_nxd),
        delta(b_in), delta(b_out));
#undef delta
    }
    if (stats_relative)
      z->z_pstats = z->z_stats;
  }
  if (f) {
#define delta(x) tot.x - gptot.x
    fprintf(f, " *" C C C C C "\n",
      delta(q_ok) + delta(q_nxd) + delta(q_err),
      delta(q_ok), delta(q_nxd),
      delta(b_in), delta(b_out));
#undef delta
    fclose(f);
  }
  if (stats_relative)
    gptot = tot;
#undef C
}

static void dumpstats_z(void) {
  FILE *f = fopen(statsfile, "a");
  if (f) {
    fprintf(f, "%ld\n", (long)time(NULL));
    fclose(f);
  }
}

static void logstats(int reset) {
  time_t t = time(NULL);
  time_t d = t - stats_time;
  struct dnsstats tot = gstats;
  char name[DNS_MAXDOMAIN+1];
  struct zone *z;

#define C(x) " " #x "=%" PRI_DNSCNT
  for(z = zonelist; z; z = z->z_next) {
#define add(x) tot.x += z->z_stats.x
    add(b_in); add(b_out);
    add(q_ok); add(q_nxd); add(q_err);
#undef add
    dns_dntop(z->z_dn, name, sizeof(name));
    dslog(LOG_INFO, 0,
      "stats for %ldsecs zone %.60s:" C(tot) C(ok) C(nxd) C(err) C(in) C(out),
      (long)d, name,
      z->z_stats.q_ok + z->z_stats.q_nxd + z->z_stats.q_err,
      z->z_stats.q_ok, z->z_stats.q_nxd, z->z_stats.q_err,
      z->z_stats.b_in, z->z_stats.b_out);
  }
  dslog(LOG_INFO, 0,
    "stats for %ldsec:" C(tot) C(ok) C(nxd) C(err) C(in) C(out),
    (long)d,
    tot.q_ok + tot.q_nxd + tot.q_err,
    tot.q_ok, tot.q_nxd, tot.q_err,
    tot.b_in, tot.b_out);
#undef C
  if (reset) {
    for(z = zonelist; z; z = z->z_next) {
      memset(&z->z_stats, 0, sizeof(z->z_stats));
      memset(&z->z_pstats, 0, sizeof(z->z_pstats));
    }
    memset(&gstats, 0, sizeof(gstats));
    memset(&gptot, 0, sizeof(gptot));
    stats_time = t;
  }
}

#if STATS_IPC_IOVEC
# define ipc_read_stats(fd)  readv(fd, stats_iov, numzones)
# define ipc_write_stats(fd) writev(fd, stats_iov, numzones)
#else
static void ipc_read_stats(int fd) {
  struct zone *z;
  for(z = zonelist; z; z = z->z_next)
    if (read(fd, &z->z_stats, sizeof(z->z_stats)) <= 0)
      break;
}
static void ipc_write_stats(int fd) {
  const struct zone *z;
  for(z = zonelist; z; z = z->z_next)
    if (write(fd, &z->z_stats, sizeof(z->z_stats)) <= 0)
      break;
}
#endif

#else
# define ipc_read_stats(fd)
# define ipc_write_stats(fd)
#endif

static void reopenlog(void) {
  if (logfile) {
    int fd;
    if (flog) fclose(flog);
    fd = open(logfile, O_WRONLY|O_APPEND|O_CREAT|O_NONBLOCK|O_LARGEFILE, 0644);
    if (fd < 0 || (flog = fdopen(fd, "a")) == NULL) {
      dslog(LOG_WARNING, 0, "error (re)opening logfile `%.50s': %s",
            logfile, strerror(errno));
      if (fd >= 0) close(fd);
      flog = NULL;
    }
  }
  else if (flog && !flushlog) { /* log to stdout */
    clearerr(flog);
    fflush(flog);
  }
}

static void check_expires(void) {
  struct zone *zone;
  time_t now = time(NULL);
  for (zone = zonelist; zone; zone = zone->z_next) {
    if (!zone->z_stamp)
      continue;
    if (zone->z_expires && zone->z_expires < now) {
      zlog(LOG_WARNING, zone, "zone data expired, zone will not be serviced");
      zone->z_stamp = 0;
    }
  }
}

#ifdef WITH_JEMALLOC
struct jemalloc_write_cbdata {
  char *buf;
  size_t len;
};

static void
jemalloc_write_cb(void *ud, const char *msg)
{
  struct jemalloc_write_cbdata *cbd = (struct jemalloc_write_cbdata *)ud;
  int r;

  r = ssprintf(cbd->buf, cbd->len, "%s", msg);

  if (r < cbd->len) {
    cbd->buf += r;
    cbd->len -= r;
  }
}
#endif

static void
reload_cld_cb (EV_P_ ev_child *w, int revents)
{
  int cfd = (int)(uintptr_t)w->data;

  ev_child_stop(EV_A_ w);
  ipc_read_stats(cfd);
  close(cfd);

  dslog(LOG_INFO, 0, "process %d exited with status %x\n", w->rpid, w->rstatus);

  can_reload = 1;

  if (pending_reload) {
    dslog(LOG_INFO, 0, "perform delayed reload");
    do_reload(fork_on_reload, loop);
  }
}

static int do_reload(int do_fork, struct ev_loop *loop) {
  int r;
  static ev_child ev_cld;
#ifdef WITH_JEMALLOC
  char ibuf[8192];
#else
  char ibuf[512];
#endif
  int ip;
  struct dataset *ds;
  struct zone *zone;
  pid_t cpid = 0;	/* child pid; =0 to make gcc happy */
  int cfd = 0;		/* child stats fd; =0 to make gcc happy */
#ifndef NO_TIMES
  struct tms tms;
  clock_t utm, etm;
#ifndef HZ
  static clock_t HZ;
#endif
#endif /* NO_TIMES */

  pending_reload = 0;
  ds = nextdataset2reload(NULL);
  if (!ds && call_hook(reload_check, (zonelist)) == 0) {
    check_expires();
    return 1;	/* nothing to reload */
  }

  if (do_fork) {
    int pfd[2];
    if (flog && !flushlog)
      fflush(flog);
    /* forking reload. if anything fails, just do a non-forking one */
    if (pipe(pfd) < 0) {
      do_fork = 0;
    }
    else if ((cpid = fork()) < 0) {	/* fork failed, close the pipe */
      close(pfd[0]);
      close(pfd[1]);
      do_fork = 0;
    }

    if (do_fork) {
      if (!cpid) {  /* child, continue answering queries */
        fork_on_reload = -1;
        can_reload = 0; /* Deny reload for child process */
        ev_loop_fork(loop);

        close(pfd[0]);
        /* Store our pipe end in fork_on_reload poor var */
        if (pfd[1] != 1) {
          fork_on_reload = -(pfd[1]);
        }
        return 1;
      } else {
        close(pfd[1]);
        cfd = pfd[0];
        ev_child_init(&ev_cld, reload_cld_cb, cpid, 0);
        ev_cld.data = (void *)(uintptr_t)(cfd);
        ev_child_start(loop, &ev_cld);
        can_reload = 0; /* Prevent reloading */
      }
    }
  }

#ifndef NO_TIMES
#ifndef HZ
  if (!HZ)
    HZ = sysconf(_SC_CLK_TCK);
#endif
  etm = times(&tms);
  utm = tms.tms_utime;
#endif /* NO_TIMES */

  r = 1;
  while(ds) {
    if (!loaddataset(ds, loop))
      r = 0;
    ds = nextdataset2reload(ds);
  }

  for (zone = zonelist; zone; zone = zone->z_next) {
    time_t stamp = 0;
    time_t expires = 0;
    const struct dssoa *dssoa = NULL;
    const struct dsns *dsns = NULL;
    unsigned nsttl = 0;
    struct dslist *dsl;

    for(dsl = zone->z_dsl; dsl; dsl = dsl->dsl_next) {
      const struct dataset *ds = dsl->dsl_ds;
      if (!ds->ds_stamp) {
        stamp = 0;
        break;
      }
      if (stamp < ds->ds_stamp)
        stamp = ds->ds_stamp;
      if (ds->ds_expires && (!expires || expires > ds->ds_expires))
        expires = ds->ds_expires;
      if (!dssoa)
        dssoa = ds->ds_dssoa;
      if (!dsns)
        dsns = ds->ds_dsns, nsttl = ds->ds_nsttl;
    }

    zone->z_expires = expires;
    zone->z_stamp = stamp;
    if (!stamp) {
      zlog(LOG_WARNING, zone,
           "not all datasets are loaded, zone will not be serviced");
      r = 0;
    }
    else if (!update_zone_soa(zone, dssoa) ||
             !update_zone_ns(zone, dsns, nsttl, zonelist))
      zlog(LOG_WARNING, zone,
           "NS or SOA RRs are too long, will be ignored");
  }

  if (call_hook(reload, (zonelist)) != 0)
    r = 0;

  ip = ssprintf(ibuf, sizeof(ibuf), "zones reloaded");
#ifndef NO_TIMES
  etm = times(&tms) - etm;
  utm = tms.tms_utime - utm;
# define sec(tm) (unsigned long)(tm/HZ), (unsigned long)((tm*100/HZ)%100)
  ip += ssprintf(ibuf + ip, sizeof(ibuf) - ip,
        ", time %lu.%lue/%lu.%luu sec", sec(etm), sec(utm));
# undef sec
#endif /* NO_TIMES */
#ifdef WITH_JEMALLOC
  struct jemalloc_write_cbdata cbd;
  ibuf[ip++] = '\n';
  cbd.buf = ibuf + ip;
  cbd.len = sizeof(ibuf) - ip;
  malloc_stats_print(jemalloc_write_cb, (void *)&cbd, NULL);
  ip = cbd.buf - ibuf;
#else
#if !defined(NO_MEMINFO) && defined(__GLIBC__)
  {
    struct mallinfo mi = mallinfo();
# define kb(x) ((mi.x + 512)>>10)
    ip += ssprintf(ibuf + ip, sizeof(ibuf) - ip,
          ", mem arena=%d free=%d mmap=%d Kb",
          kb(arena), kb(fordblks), kb(hblkhd));
# undef kb
  }
#endif /* NO_MEMINFO */
#endif
  dslog(LOG_INFO, 0, "%s", ibuf);

  check_expires();

  /* ok, (something) loaded. */

  if (do_fork) {
    if (kill(cpid, SIGTERM) != 0) {
      dslog(LOG_WARNING, 0, "kill(qchild): %s", strerror(errno));
    }
  }

  return r;
}

#ifdef WITH_RECVMMSG
#define MSGVEC_LEN 64
#else
#define MSGVEC_LEN 1
#endif

static int request(int fd) {
  int q;
#ifndef NO_IPv6
  struct sockaddr_storage peer_sa[MSGVEC_LEN];
#else
  struct sockaddr_in peer_sa[MSGVEC_LEN];
#endif
  socklen_t salen = sizeof(peer_sa);
  struct dnsqinfo qi;
  struct dnspacket pkt[MSGVEC_LEN];
  struct iovec iovs[MSGVEC_LEN];
  int lim, replies_lengths[MSGVEC_LEN];
#ifdef WITH_RECVMMSG
#define MSG_FIELD(msg, field) msg.msg_hdr.field
  struct mmsghdr msg[MSGVEC_LEN];
#else
#define MSG_FIELD(msg, field) msg.field
  struct msghdr msg[MSGVEC_LEN];
#endif

  memset(msg, 0, sizeof(*msg) * MSGVEC_LEN);

  for (int i = 0; i < MSGVEC_LEN; i ++) {
    /* Prepare msghdr structs */
    iovs[i].iov_base = pkt[i].p_buf;
    iovs[i].iov_len = sizeof(pkt[i].p_buf);
    MSG_FIELD(msg[i], msg_name) = (void *)&peer_sa[i];
    MSG_FIELD(msg[i], msg_namelen) = salen;
    MSG_FIELD(msg[i], msg_iov) = &iovs[i];
    MSG_FIELD(msg[i], msg_iovlen) = 1;
  }
#ifdef WITH_RECVMMSG
  q = recvmmsg(fd, msg, MSGVEC_LEN, 0, NULL);
  lim = q;
#else
  q = recvmsg(fd, msg, 0);
  lim = 1;
#endif
  if (q <= 0) {
    return -1;
  }

  for (int i = 0; i < lim; i ++) {
#ifdef WITH_RECVMMSG
    q = msg[i].msg_len;
#endif
    pkt[i].p_peerlen = MSG_FIELD(msg[i], msg_namelen);
    pkt[i].p_peer = MSG_FIELD(msg[i], msg_name);
    replies_lengths[i] = replypacket(&pkt[i], q, zonelist, &qi);

    if (flog) {
      logreply(&pkt[i], flog, flushlog, &qi, replies_lengths[i]);
    }
  }

  int cur_rep = 0;
  for (int i = 0; i < lim; i ++) {
    if (replies_lengths[i] > 0) {
      iovs[cur_rep].iov_base = pkt[i].p_buf;
      iovs[cur_rep].iov_len = replies_lengths[i];
      MSG_FIELD(msg[cur_rep], msg_name) = (void *)&peer_sa[i];
      MSG_FIELD(msg[cur_rep], msg_namelen) = MSG_FIELD(msg[i], msg_namelen);
      MSG_FIELD(msg[cur_rep], msg_iov) = &iovs[cur_rep];
      MSG_FIELD(msg[cur_rep], msg_iovlen) = 1;
      cur_rep ++;
    }
  }

#ifdef WITH_RECVMMSG
  while (sendmmsg(fd, msg, cur_rep, 0) < 0) {
    if (errno != EINTR && errno != EAGAIN) {
      break;
    }
  }
#else
  while (sendmsg(fd, msg, 0) < 0) {
    if (errno != EINTR && errno != EAGAIN) {
      break;
    }
  }
#endif

  return 1;
}

static int
make_socket_nonblocking(int fd)
{
  int ofl;

  ofl = fcntl (fd, F_GETFL, 0);

  if (fcntl (fd, F_SETFL, ofl | O_NONBLOCK) == -1) {
    syslog(LOG_WARNING, "fcntl failed: %d, '%s'", errno, strerror (errno));
    return -1;
  }
  return 0;
}

static void
ev_stat_handler(struct ev_loop *loop, ev_stat *w, int revents)
{
  if (can_reload) {
    if (statsfile) {
      dumpstats();
    }

    dslog(LOG_INFO, 0, "reload zones as file %s has been changed", w->path);
    do_reload(fork_on_reload, loop);
  }
  else {
    pending_reload = 1;
    dslog(LOG_INFO, 0, "already reloading, ignore stat update for %s",
        w->path);
  }
}

static void
ev_request_handler(struct ev_loop *loop, ev_io *w, int revents)
{
  request(w->fd);
}

static void
ev_update_handler(struct ev_loop *loop, ev_io *w, int revents)
{
  unsigned char pbuf[4096];
  const unsigned char *zero_pos;
  ssize_t r;
  struct zone *found = NULL, *cur;

  r = read(w->fd, pbuf, sizeof (pbuf) - 1);

  if (r == -1) {
    if (errno == EINTR || errno == EAGAIN) {
      return;
    }
    else {
      dslog(LOG_ERR, 0, "failed to read update: %s", strerror (errno));
      return;
    }
  }
  else if (r == 0) {
    dslog(LOG_ERR, 0, "failed to read update: zero size input");

    return;
  }

  zero_pos = memchr(pbuf, 0, r);

  if (zero_pos == NULL) {
    dslog(LOG_ERR, 0, "failed to read update: no \\0 character found");

    return;
  }

  for (cur = zonelist; cur != NULL; cur = cur->z_next) {
    if (cur->z_name && strcmp (pbuf, cur->z_name) == 0) {
      found = cur;
      break;
    }
  }

  if (found) {
    dslog(LOG_INFO, 0, "got update event for zone %s", found->z_name);

    /* Zero terminate update string */
    pbuf[r] = '\0';
    struct dsctx dsc;

    for(struct dslist *dsl = found->z_dsl; dsl; dsl = dsl->dsl_next) {
      if (dsl->dsl_ds->ds_type->dst_updatefn) {
        dsl->dsl_ds->ds_type->dst_updatefn(dsl->dsl_ds, (char *)(zero_pos + 1), &dsc);
        dslog(LOG_INFO, 0, "send update event for zone %s: %s",
            found->z_name, zero_pos + 1);
      }
    }
  }
  else {
    dslog(LOG_ERR, 0, "cannot find zone for update %s", pbuf);

    return;
  }
}

/*
 * Signal handlers
 */
static void
ev_usr1_handler (struct ev_loop *loop, ev_signal *w, int revents)
{
  if (statsfile) {
    dumpstats();
  }

    logstats(0);
}

static void
ev_usr2_handler(struct ev_loop *loop, ev_signal *w, int revents)
{
  if (statsfile) {
    dumpstats();
  }

  logstats(1);

  if (statsfile) {
    dumpstats_z();
  }

  if (can_reload) {
    do_reload(fork_on_reload, loop);
  }
  else {
    pending_reload = 1;
    dslog(LOG_INFO, 0, "already reloading, ignore reload on SIGUSR2");
  }
}

static void
ev_hup_handler(struct ev_loop *loop, ev_signal *w, int revents)
{
  if (can_reload) {
    reopenlog();

    if (statsfile) {
      dumpstats();
    }

    do_reload(fork_on_reload, loop);
  }
  else {
    pending_reload = 1;
    dslog(LOG_INFO, 0, "already reloading, ignore SIGHUP");
  }
}

static void
ev_term_handler (struct ev_loop *loop, ev_signal *w, int revents)
{
  if (fork_on_reload < 0) { /* this is a temp child; dump stats and exit */
    dslog(LOG_INFO, 0, "temp worker received terminating signal %s",
        strsignal(w->signum));
    /* pipe end is stored in fork_on_reload for a child */
    ipc_write_stats(-(fork_on_reload));
    if (flog && !flushlog) {
      fflush(flog);
    }
    ev_break(loop, EVBREAK_ALL);
    exit(0);
  }

  dslog(LOG_INFO, 0, "terminating after %s", strsignal(w->signum));
#ifndef NO_STATS
  if (statsfile) {
    dumpstats();
  }
  logstats(0);
  if (statsfile) {
    dumpstats_z();
  }
#endif
  ev_break (loop, EVBREAK_ALL);
}

static void setup_signals(struct ev_loop *loop) {
  ev_signal_init(&ev_hup, ev_hup_handler, SIGHUP);
  ev_signal_init(&ev_usr1, ev_usr1_handler, SIGUSR1);
  ev_signal_init(&ev_usr2, ev_usr2_handler, SIGUSR2);
  ev_signal_init(&ev_term, ev_term_handler, SIGTERM);
  ev_signal_init(&ev_int, ev_term_handler, SIGINT);

  ev_signal_start(loop, &ev_hup);
  ev_signal_start(loop, &ev_usr1);
  ev_signal_start(loop, &ev_usr2);
  ev_signal_start(loop, &ev_term);
  ev_signal_start(loop, &ev_int);

  signal(SIGPIPE, SIG_IGN);	/* in case logfile is FIFO */
}

/*
 * End of signal handlers
 */

int main(int argc, char **argv) {
  struct ev_loop *loop;
  ev_io *io_evs = NULL; /* Events for sockets */
  ev_stat *stat_evs = NULL; /* Events for zone files */

#ifdef EVFLAG_SIGNALFD
  loop = ev_default_loop(EVFLAG_SIGNALFD);
#else
  loop = ev_default_loop(0);
#endif

  if (loop == NULL) {
    syslog(LOG_CRIT, "cannot initialize event loop! bad $LIBEV_FLAGS in environment?");
    abort ();
  }

  init(argc, argv, loop);
  setup_signals(loop);
  reopenlog();
  can_reload = 1;

#ifndef NO_STATS
  stats_time = time(NULL);
  if (statsfile)
    dumpstats_z();
#endif

  io_evs = calloc(numsock, sizeof (ev_io));

  if (io_evs == NULL) {
    oom();
  }

  for(int i = 0; i < numsock; ++i) {
    make_socket_nonblocking(sock[i]);
    ev_io_init(&io_evs[i], ev_request_handler, sock[i], EV_READ);
    ev_io_start(loop, &io_evs[i]);
  }

  static ev_io update_ev;

  if (update_sock != -1) {
    make_socket_nonblocking(update_sock);
    ev_io_init(&update_ev, ev_update_handler, update_sock, EV_READ);
    ev_io_start(loop, &update_ev);
  }

  /* Also monitor zones for changes */
  if (recheck) {
    unsigned nds = 0;
    struct dataset *ds = NULL;
    struct dsfile *dsf = NULL;

    while((ds = nextdataset(ds)) != NULL) {
      for(dsf = ds->ds_dsf; dsf; dsf = dsf->dsf_next) {
        nds++;
      }
    }

    stat_evs = calloc(nds, sizeof(ev_stat));

    if (stat_evs == NULL) {
      oom();
    }

    nds = 0;
    ds = NULL;

    while((ds = nextdataset(ds)) != NULL) {
      for(dsf = ds->ds_dsf; dsf; dsf = dsf->dsf_next) {
        ev_stat_init(&stat_evs[nds], ev_stat_handler, dsf->dsf_name, recheck);
        stat_evs[nds].data = dsf;
        ev_stat_start(loop, &stat_evs[nds]);
        dsf->stat_ev = &stat_evs[nds];
        nds ++;
      }
    }
  }

  ev_loop(loop, 0);

  for(int i = 0; i < numsock; ++i) {
    close(sock[i]);
  }

  if (update_sock != -1) {
    close (update_sock);
  }

  free(io_evs);
  free(stat_evs);

  return 0;
}

void oom(void) {
#ifdef WITH_JEMALLOC
  malloc_stats_print(NULL, NULL, NULL);
#endif
  if (initialized)
    dslog(LOG_ERR, 0, "out of memory loading dataset");
  else
    error(0, "out of memory");
}
