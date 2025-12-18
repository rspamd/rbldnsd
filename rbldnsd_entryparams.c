/*
 * Entry params parsing + plugin callbacks.
 */

#include <string.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include "rbldnsd.h"

#define MAX_ENTRY_PARAM_HANDLERS 32

static entry_params_handler_t handlers[MAX_ENTRY_PARAM_HANDLERS];
static unsigned nhandlers;

int rbldnsd_register_entry_params_handler(entry_params_handler_t cb) {
  if (!cb) {
    return -1;
  }
  if (nhandlers >= MAX_ENTRY_PARAM_HANDLERS) {
    return -1;
  }
  handlers[nhandlers++] = cb;
  return 0;
}

int rbldnsd_apply_entry_params(const struct sockaddr *requestor,
                               const struct dataset *ds,
                               const struct dnsqinfo *qinfo,
                               const struct kv_params *params,
                               struct entry_action *action) {
  if (!action) {
    return -1;
  }

  if (!params || params->n == 0 || nhandlers == 0) {
    return 0;
  }

  for (unsigned i = 0; i < nhandlers; i++) {
    if (!handlers[i]) {
      continue;
    }
    (void)handlers[i](requestor, ds, qinfo, params, action);
    if (!action->allow) {
      break;
    }
    if (action->flags & ENTRY_ACTION_STOP) {
      break;
    }
  }

  return 0;
}

static inline int
parse_time_seconds(const char *s, unsigned *out)
{
  if (!s || !*s || !out) {
    return 0;
  }

  char buf[64];
  size_t n = strlen(s);
  if (n >= sizeof(buf) - 2) {
    return 0;
  }
  memcpy(buf, s, n);
  buf[n] = ' ';
  buf[n + 1] = '\0';

  unsigned sec = 0;
  char *p = buf;
  char *end = parse_time(p, &sec);
  if (!end) {
    return 0;
  }
  while (*end && ISSPACE(*end)) {
    end++;
  }
  if (*end != '\0') {
    return 0;
  }

  *out = sec;
  return 1;
}

static inline int
parse_u64(const char *s, unsigned long long *out)
{
  if (!s || !*s || !out) {
    return 0;
  }
  errno = 0;
  char *end = NULL;
  unsigned long long v = strtoull(s, &end, 10);
  if (errno != 0 || end == s) {
    return 0;
  }
  while (*end && ISSPACE(*end)) {
    end++;
  }
  if (*end != '\0') {
    return 0;
  }
  *out = v;
  return 1;
}

static int
rbldnsd_builtin_entry_params_handler(const struct sockaddr *UNUSED requestor,
                                     const struct dataset *UNUSED ds,
                                     const struct dnsqinfo *qinfo,
                                     const struct kv_params *params,
                                     struct entry_action *action)
{
  int is_keyed = qinfo && (qinfo->qi_tflag & NSQUERY_KEY);

  int require_key = 0;
  int nodelay = 0;
  unsigned delay_sec = 0;
  int have_delay = 0;
  unsigned long long ts = 0;
  int have_ts = 0;

  for (unsigned i = 0; params && i < params->n; i++) {
    const char *k = params->kv[i].k;
    const char *v = params->kv[i].v;
    if (!k) {
      continue;
    }

    if (strcmp(k, "key") == 0 && v) {
      if (strcmp(v, "require") == 0) {
        require_key = 1;
      }
      else if (strcmp(v, "nodelay") == 0) {
        nodelay = 1;
      }
    }
    else if (strcmp(k, "delay") == 0 && v) {
      if (parse_time_seconds(v, &delay_sec)) {
        have_delay = 1;
      }
    }
    else if (strcmp(k, "ts") == 0 && v) {
      if (parse_u64(v, &ts)) {
        have_ts = 1;
      }
    }
  }

  if (require_key && !is_keyed) {
    action->allow = 0;
    action->flags |= ENTRY_ACTION_STOP;
    return 0;
  }

  if (nodelay && is_keyed) {
    action->delay_ms = 0;
    action->flags |= ENTRY_ACTION_NODELAY;
    action->flags |= ENTRY_ACTION_STOP;
    return 0;
  }

  if (have_ts && have_delay) {
    unsigned long long ready = ts + (unsigned long long)delay_sec;
    unsigned long long now = (unsigned long long)rbldnsd_cached_time();
    if (now < ready) {
      action->allow = 0;
      action->flags |= ENTRY_ACTION_STOP;
    }
    return 0;
  }

  if (have_delay && !have_ts) {
    unsigned long long ms = (unsigned long long)delay_sec * 1000ULL;
    if (ms > UINT_MAX) {
      ms = UINT_MAX;
    }
    if ((unsigned)ms > action->delay_ms) {
      action->delay_ms = (unsigned)ms;
    }
  }

  return 0;
}

void __attribute__((constructor))
rbldnsd_builtin_entry_params_init(void)
{
  (void)rbldnsd_register_entry_params_handler(rbldnsd_builtin_entry_params_handler);
}

static inline int is_namech(char c) {
  return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
         (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.';
}

char *rbldnsd_split_entry_params(char *s, char **params_out) {
  if (params_out) {
    *params_out = NULL;
  }
  if (!s) {
    return NULL;
  }

  char *p = s;
  char prev = '\0';
  while (*p) {
    if (*p == '@' && (p == s || ISSPACE(prev))) {
      char *at = p;
      /* trim whitespace before @ */
      while (at > s && ISSPACE(at[-1])) {
        at[-1] = '\0';
        at--;
      }
      *p++ = '\0';
      SKIPSPACE(p);
      if (params_out) {
        *params_out = p;
      }
      return s;
    }
    prev = *p;
    p++;
  }

  return s;
}

const struct kv_params *rbldnsd_parse_kv_params(struct mempool *mp,
                                                struct dsctx *dsc,
                                                const char *s) {
  if (!s) {
    return NULL;
  }
  while (ISSPACE(*s)) {
    s++;
  }
  if (!*s || ISCOMMENT(*s)) {
    return NULL;
  }

  char *buf = mp_strdup(mp, s);
  if (!buf) {
    return NULL;
  }

  /* Strip trailing comment if present */
  for (char *c = buf; *c; c++) {
    if (ISCOMMENT(*c) && (c == buf || ISSPACE(c[-1]))) {
      *c = '\0';
      break;
    }
  }

  /* First pass: count pairs */
  unsigned npairs = 0;
  {
    char *p = buf;
    while (*p) {
      while (*p == ':' || *p == ';' || ISSPACE(*p)) {
        p++;
      }
      if (!*p) {
        break;
      }
      npairs++;
      while (*p && *p != ':' && *p != ';') {
        p++;
      }
    }
  }

  if (npairs == 0) {
    return NULL;
  }

  struct kv_params *params =
      mp_alloc(mp, sizeof(*params) + sizeof(params->kv[0]) * npairs, 1);
  if (!params) {
    return NULL;
  }
  params->n = 0;
  params->storage = buf;

  /* Second pass: split into key/value */
  char *p = buf;
  while (*p) {
    while (*p == ':' || *p == ';' || ISSPACE(*p)) {
      p++;
    }
    if (!*p) {
      break;
    }

    char *tok = p;
    while (*p && *p != ':' && *p != ';') {
      p++;
    }
    if (*p == ':' || *p == ';') {
      *p++ = '\0';
    }

    /* trim token */
    while (ISSPACE(*tok)) {
      tok++;
    }
    char *end = tok + strlen(tok);
    while (end > tok && ISSPACE(end[-1])) {
      end[-1] = '\0';
      end--;
    }
    if (!*tok) {
      continue;
    }

    char *eq = strchr(tok, '=');
    if (eq) {
      *eq++ = '\0';
      while (ISSPACE(*eq)) {
        eq++;
      }
    }

    for (char *k = tok; *k; k++) {
      if (!is_namech(*k)) {
        dswarn(dsc, "invalid entry params key");
        tok = NULL;
        break;
      }
    }
    if (!tok) {
      continue;
    }

    params->kv[params->n].k = tok;
    params->kv[params->n].v = eq && *eq ? eq : NULL;
    params->n++;
  }

  if (params->n == 0) {
    return NULL;
  }
  return params;
}
