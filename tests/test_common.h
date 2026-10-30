#pragma once

#include <cstdio>

static int g_failures = 0;

#define CHECK(condition) \
  do { \
    if (!(condition)) { \
      std::printf("%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #condition); \
      g_failures++; \
    } \
  } while (0)

static int finish(const char *name) {
  std::printf("%s: %s\n", name, g_failures == 0 ? "OK" : "FAILED");
  return g_failures == 0 ? 0 : 1;
}
