// Decodes ALAC streams encoded by ffmpeg and compares the output with ffmpeg's own decoder (as a hash of the
// PCM data). Usage: test_alac <directory of tests/vectors>
#include "airplay_alac.h"
#include "test_common.h"

#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

using namespace airplay;

struct Vector {
  const char *name;
  uint8_t channels;
  size_t samples;
  uint64_t hash;  // FNV-1a of the little endian 16-bit PCM
};

// ffmpeg -f lavfi -i <source> -c:a alac (frame length 4096); references decoded with ffmpeg
static const Vector VECTORS[] = {
    {"sine", 2, 202860, 0x18b89aa2dfdae251ULL},     // Sine sweep
    {"noise", 2, 185220, 0x1188d6f936092989ULL},    // White noise: large residuals and escapes
    {"mono", 1, 52920, 0x156d50464559f0ecULL},      // Single channel element
    {"silence", 2, 132300, 0x360b175d57b06105ULL},  // Zero runs
    {"lvl0", 2, 105840, 0x83d3f1f63e355981ULL},     // Compression level 0: uncompressed escape frames
};

static uint64_t fnv1a(uint64_t hash, const uint8_t *data, size_t length) {
  for (size_t i = 0; i < length; i++) {
    hash ^= data[i];
    hash *= 0x100000001b3ULL;
  }
  return hash;
}

static std::vector<uint8_t> read_file(const std::string &path) {
  std::vector<uint8_t> data;
  FILE *file = std::fopen(path.c_str(), "rb");
  if (file == nullptr)
    return data;
  uint8_t buffer[4096];
  size_t n;
  while ((n = std::fread(buffer, 1, sizeof(buffer), file)) > 0)
    data.insert(data.end(), buffer, buffer + n);
  std::fclose(file);
  return data;
}

static void test_vector(const std::string &directory, const Vector &vector) {
  static constexpr uint32_t FRAME_LENGTH = 4096;
  const std::vector<uint8_t> data = read_file(directory + "/" + vector.name + ".bin");
  const std::vector<uint8_t> sizes_text = read_file(directory + "/" + vector.name + ".sizes");
  CHECK(!data.empty() && !sizes_text.empty());
  if (data.empty() || sizes_text.empty())
    return;
  const std::string sizes(sizes_text.begin(), sizes_text.end());

  ALACDecoder decoder;
  CHECK(decoder.init(FRAME_LENGTH));
  ALACConfig config;
  config.frame_length = FRAME_LENGTH;
  config.num_channels = vector.channels;
  CHECK(decoder.configure(config));

  std::vector<int16_t> output(FRAME_LENGTH * vector.channels);
  uint64_t hash = 0xcbf29ce484222325ULL;
  size_t samples = 0;
  size_t offset = 0;
  const char *p = sizes.c_str();
  char *end = nullptr;
  for (unsigned long size = std::strtoul(p, &end, 10); end != p; size = std::strtoul(p, &end, 10)) {
    p = end;
    if (offset + size > data.size()) {
      CHECK(false);
      return;
    }
    const int32_t frames = decoder.decode(&data[offset], size, output.data());
    CHECK(frames > 0);
    if (frames <= 0)
      return;
    // The vectors were made on a little endian host
    const size_t count = static_cast<size_t>(frames) * vector.channels;
    for (size_t i = 0; i < count; i++) {
      const uint8_t bytes[2] = {static_cast<uint8_t>(output[i]), static_cast<uint8_t>(output[i] >> 8)};
      hash = fnv1a(hash, bytes, 2);
    }
    samples += count;
    offset += size;
  }
  if (samples != vector.samples || hash != vector.hash)
    std::printf("%s: %zu samples, hash %016llx\n", vector.name, samples, static_cast<unsigned long long>(hash));
  CHECK(samples == vector.samples);
  CHECK(hash == vector.hash);
}

static void test_invalid_input() {
  ALACDecoder decoder;
  CHECK(decoder.init(352));
  ALACConfig config;
  CHECK(decoder.configure(config));
  int16_t output[352 * 2];
  uint8_t garbage[64];
  for (size_t i = 0; i < sizeof(garbage); i++)
    garbage[i] = static_cast<uint8_t>(i * 37 + 11);
  // Must not crash or write out of bounds; the result may be an error
  decoder.decode(garbage, sizeof(garbage), output);
  CHECK(decoder.decode(garbage, 0, output) <= 0);

  config.frame_length = 4096;
  CHECK(!decoder.configure(config));  // Larger than init()
  config.frame_length = 352;
  config.bit_depth = 24;
  CHECK(!decoder.configure(config));
}

int main(int argc, char **argv) {
  const std::string directory = argc > 1 ? argv[1] : "tests/vectors";
  for (const Vector &vector : VECTORS)
    test_vector(directory, vector);
  test_invalid_input();
  return finish("test_alac");
}
