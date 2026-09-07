/* Link the production quota module to deterministic entropy syscall doubles. */
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

static int random_mode;
static int entropy_mode;
static int device_mode;
static int calls[4];
static int closes;

static ssize_t quota_getrandom(void *buffer, size_t size, unsigned flags) {
  ++calls[0];
  if (flags != 0) {
    errno = EINVAL;
    return -1;
  }
  if (random_mode == 1 && calls[0] == 1) {
    errno = EINTR;
    return -1;
  }
  if (random_mode == 2 || (random_mode == 7 && calls[0] > 1)) {
    errno = ENOSYS;
    return -1;
  }
  if (random_mode == 3 || (random_mode == 5 && calls[0] > 1)) {
    errno = EIO;
    return -1;
  }
  if (random_mode == 4) {
    return 0;
  }
  if (random_mode == 6) {
    errno = EPERM;
    return -1;
  }
  if ((random_mode == 1 || random_mode == 5 || random_mode == 7) && size > 3) {
    size = 3;
  }
  memset(buffer, 0xa5, size);
  return (ssize_t)size;
}

static int quota_getentropy(void *buffer, size_t size) {
  ++calls[1];
  if (entropy_mode == 1 && calls[1] == 1) {
    errno = EINTR;
    return -1;
  }
  if (entropy_mode == 2) {
    errno = ENOSYS;
    return -1;
  }
  if (entropy_mode == 3) {
    errno = EIO;
    return -1;
  }
  memset(buffer, 0xa5, size);
  return 0;
}

static int quota_open(const char *path, int flags, ...) {
  ++calls[2];
  if (strcmp(path, "/dev/urandom") || flags != O_RDONLY) {
    errno = EINVAL;
    return -1;
  }
  if (device_mode == 1) {
    errno = EACCES;
    return -1;
  }
  if (calls[2] == 1) {
    errno = EINTR;
    return -1;
  }
  return 91;
}

static ssize_t quota_read(int fd, void *buffer, size_t size) {
  ++calls[3];
  if (fd != 91) {
    errno = EBADF;
    return -1;
  }
  if (device_mode == 2) {
    return 0;
  }
  if (device_mode == 3 || (device_mode == 4 && calls[3] > 1)) {
    errno = EIO;
    return -1;
  }
  if (device_mode == 0 && calls[3] == 1) {
    errno = EINTR;
    return -1;
  }
  if (size > 3) {
    size = 3;
  }
  memset(buffer, 0xa5, size);
  return (ssize_t)size;
}

static int quota_close(int fd) {
  if (fd != 91) {
    errno = EBADF;
    return -1;
  }
  ++closes;
  return 0;
}

#define getrandom quota_getrandom
#define getentropy quota_getentropy
#define open quota_open
#define read quota_read
#define close quota_close
#include "rbldnsd_ratelimit.c"

void quota_entropy_modes(int random, int entropy, int device) {
  random_mode = random;
  entropy_mode = entropy;
  device_mode = device;
  memset(calls, 0, sizeof(calls));
  closes = 0;
}

int quota_entropy_calls(unsigned backend) {
  return calls[backend];
}

int quota_entropy_closes(void) {
  return closes;
}

void quota_entropy_secret(unsigned char *output) {
  memcpy(output, secret, sizeof(secret));
}

int quota_entropy_has_accounting(void) {
  return accounting != NULL;
}
