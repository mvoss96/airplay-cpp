// LD_PRELOAD shim that impairs the UDP packets a program receives: drops, reorders and duplicates them.
// Works without root or kernel support (unlike tc netem), so the receiver's retransmission handling can be
// tested against real senders anywhere.
//
//   gcc -shared -fPIC -O2 impair.c -o impair.so -ldl
//   IMPAIR_LOSS=0.05 IMPAIR_REORDER=0.02 IMPAIR_DUPLICATE=0.01 LD_PRELOAD=./impair.so program
//
// IMPAIR_SEED sets the random sequence, IMPAIR_VERBOSE=1 logs every dropped packet.
// Rates are probabilities per packet. TCP is not touched. Statistics are printed to stderr at exit.
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#define MAX_FDS 1024
#define MAX_PACKET 2048

typedef ssize_t (*recvfrom_fn)(int, void *, size_t, int, struct sockaddr *, socklen_t *);

struct Held {
  int valid;
  int due;  // Deliver on the next call
  size_t length;
  struct sockaddr_storage from;
  socklen_t from_length;
  unsigned char data[MAX_PACKET];
};

static struct Held held[MAX_FDS];  // A packet held back to be delivered after the next one, or again
static double loss, reorder, duplicate;
static int verbose;
static unsigned long received, dropped, reordered, duplicated;
static unsigned int seed = 12345;
static int initialized;

static double random01(void) { return (double) rand_r(&seed) / RAND_MAX; }

static void report(void) {
  fprintf(stderr, "impair: %lu UDP packets, %lu dropped, %lu reordered, %lu duplicated\n", received, dropped,
          reordered, duplicated);
}

static void init(void) {
  const char *value;
  if ((value = getenv("IMPAIR_LOSS")) != NULL)
    loss = atof(value);
  if ((value = getenv("IMPAIR_REORDER")) != NULL)
    reorder = atof(value);
  if ((value = getenv("IMPAIR_DUPLICATE")) != NULL)
    duplicate = atof(value);
  verbose = getenv("IMPAIR_VERBOSE") != NULL;
  if ((value = getenv("IMPAIR_SEED")) != NULL)
    seed = (unsigned int) atoi(value);
  atexit(report);
  initialized = 1;
}

static int is_udp(int fd) {
  int type = 0;
  socklen_t length = sizeof(type);
  return getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &length) == 0 && type == SOCK_DGRAM;
}

static ssize_t deliver(struct Held *packet, void *buffer, size_t size, struct sockaddr *from, socklen_t *from_length) {
  const size_t n = packet->length < size ? packet->length : size;
  memcpy(buffer, packet->data, n);
  if (from != NULL && from_length != NULL) {
    const socklen_t m = packet->from_length < *from_length ? packet->from_length : *from_length;
    memcpy(from, &packet->from, m);
    *from_length = packet->from_length;
  }
  return (ssize_t) n;
}

ssize_t recvfrom(int fd, void *buffer, size_t size, int flags, struct sockaddr *from, socklen_t *from_length) {
  static recvfrom_fn real_recvfrom;
  if (real_recvfrom == NULL)
    real_recvfrom = (recvfrom_fn) dlsym(RTLD_NEXT, "recvfrom");
  if (!initialized)
    init();
  if (fd < 0 || fd >= MAX_FDS || !is_udp(fd))
    return real_recvfrom(fd, buffer, size, flags, from, from_length);

  if (held[fd].valid && held[fd].due) {
    held[fd].valid = 0;
    return deliver(&held[fd], buffer, size, from, from_length);
  }
  while (1) {
    struct Held incoming;
    incoming.from_length = sizeof(incoming.from);
    const ssize_t n = real_recvfrom(fd, incoming.data, sizeof(incoming.data), flags,
                                    (struct sockaddr *) &incoming.from, &incoming.from_length);
    if (n < 0) {
      // Nothing new: hand out a packet held back for reordering rather than keeping it
      if (held[fd].valid && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        held[fd].valid = 0;
        return deliver(&held[fd], buffer, size, from, from_length);
      }
      return n;
    }
    incoming.length = (size_t) n;
    received++;
    if (random01() < loss) {
      dropped++;
      if (verbose && incoming.length >= 4)
        fprintf(stderr, "impair: dropped packet type 0x%02x seq %u\n", incoming.data[1] & 0x7f,
                (incoming.data[2] << 8) | incoming.data[3]);
      continue;
    }
    if (held[fd].valid) {
      held[fd].due = 1;  // This newer packet overtakes the held one
    } else if (random01() < reorder) {
      held[fd] = incoming;
      held[fd].valid = 1;
      held[fd].due = 0;
      reordered++;
      continue;
    } else if (random01() < duplicate) {
      held[fd] = incoming;
      held[fd].valid = 1;
      held[fd].due = 1;
      duplicated++;
    }
    return deliver(&incoming, buffer, size, from, from_length);
  }
}
