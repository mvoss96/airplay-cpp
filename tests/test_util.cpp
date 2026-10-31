// base64, DMAP metadata and DACP helpers
#include "airplay_dacp.h"
#include "airplay_util.h"
#include "test_common.h"

#include <cstring>
#include <string>

using namespace airplay;

static std::string item(const char *tag, const std::string &value) {
  std::string result(tag, 4);
  const auto n = static_cast<uint32_t>(value.size());
  result += static_cast<char>(n >> 24);
  result += static_cast<char>(n >> 16);
  result += static_cast<char>(n >> 8);
  result += static_cast<char>(n);
  return result + value;
}

static void test_base64() {
  const char *unpadded = "zcZmAZtqh7uGcEwPXk0QeA";  // 16 bytes, as in an Apple-Challenge
  uint8_t data[32];
  const size_t n = base64_decode(unpadded, std::strlen(unpadded), data, sizeof(data));
  CHECK(n == 16);
  char text[64];
  CHECK(base64_encode_unpadded(data, n, text, sizeof(text)) == 22);
  CHECK(std::strcmp(text, unpadded) == 0);

  const char *padded = "aGVsbG8=";
  CHECK(base64_decode(padded, std::strlen(padded), data, sizeof(data)) == 5);
  CHECK(std::memcmp(data, "hello", 5) == 0);
  CHECK(base64_encode_unpadded(reinterpret_cast<const uint8_t *>("hello"), 5, text, sizeof(text)) == 7);
  CHECK(std::strcmp(text, "aGVsbG8") == 0);
  CHECK(base64_decode(padded, std::strlen(padded), data, 4) == 0);  // Too small
  CHECK(base64_encode_unpadded(reinterpret_cast<const uint8_t *>("hello"), 5, text, 7) == 0);
}

static void test_dmap() {
  const std::string inner = item("mper", std::string(8, '\x01')) + item("asal", "Abbey Road") +
                            item("asar", "The Beatles") + item("minm", "Here Comes the Sun") + item("caps", "\x01") +
                            item("asaa", "Various") + item("asyr", std::string("\x07\xb1", 2)) +
                            item("astn", std::string("\x00\x07", 2));
  const std::string body = item("mlit", inner);
  Metadata metadata{};
  parse_dmap_metadata(reinterpret_cast<const uint8_t *>(body.data()), body.size(), metadata);
  CHECK(std::strcmp(metadata.title, "Here Comes the Sun") == 0);
  CHECK(std::strcmp(metadata.artist, "The Beatles") == 0);
  CHECK(std::strcmp(metadata.album, "Abbey Road") == 0);
  CHECK(std::strcmp(metadata.album_artist, "Various") == 0);
  CHECK(metadata.year == 1969 && metadata.track == 7);

  // Shortening must not split a multi-byte character: 10 x "ä" (2 bytes each) into 8 bytes
  std::string umlauts;
  for (int i = 0; i < 10; i++)
    umlauts += "\xc3\xa4";
  char small[8];
  copy_utf8(small, sizeof(small), reinterpret_cast<const uint8_t *>(umlauts.data()), umlauts.size());
  CHECK(std::strlen(small) == 6);

  // A corrupt length must not read past the end
  const std::string bad = std::string("mlit\x7f\xff\xff\xff", 8) + "minm";
  Metadata untouched{};
  parse_dmap_metadata(reinterpret_cast<const uint8_t *>(bad.data()), bad.size(), untouched);
  CHECK(untouched.title[0] == '\0');
}

static void test_dacp() {
  CHECK(dacp_instance_matches("iTunes_Ctrl_A1B2C3D4E5F60718", "a1b2c3d4e5f60718"));
  CHECK(dacp_instance_matches("A1B2C3D4E5F60718", "A1B2C3D4E5F60718"));
  CHECK(!dacp_instance_matches("iTunes_Ctrl_0000000000000000", "A1B2C3D4E5F60718"));
  CHECK(!dacp_instance_matches("iTunes_Ctrl_A1B2", "A1B2C3D4E5F60718"));
  CHECK(!dacp_instance_matches("anything", ""));

  char command[64];
  CHECK(dacp_volume_steps(0.5f, 0.5f) == 0);
  CHECK(dacp_volume_steps(0.5f, 0.53f) == 0);
  CHECK(dacp_volume_steps(0.5f, 0.6f) == 2);
  CHECK(dacp_volume_steps(0.6f, 0.5f) == -2);
  CHECK(dacp_volume_steps(1.0f, 0.0f) == -16);
  CHECK(dacp_volume_command(1.0f, command, sizeof(command)) > 0);
  CHECK(std::strcmp(command, "setproperty?dmcp.device-volume=0.000000") == 0);
  CHECK(dacp_volume_command(0.5f, command, sizeof(command)) > 0);
  CHECK(std::strcmp(command, "setproperty?dmcp.device-volume=-15.000000") == 0);
  CHECK(dacp_volume_command(0.0f, command, sizeof(command)) > 0);
  CHECK(std::strcmp(command, "setproperty?dmcp.device-volume=-144.000000") == 0);
  CHECK(dacp_volume_command(0.5f, command, 10) == 0);

  RemoteTarget target{};
  std::strcpy(target.dacp_id, "A1B2C3D4E5F60718");
  std::strcpy(target.active_remote, "1986535575");
  const uint8_t ip[4] = {192, 168, 1, 20};
  std::memcpy(&target.address, ip, 4);
  char request[256];
  CHECK(dacp_format_request(target, 3689, DACP_PAUSE, request, sizeof(request)) > 0);
  CHECK(std::strcmp(request,
                    "GET /ctrl-int/1/pause HTTP/1.1\r\nHost: 192.168.1.20:3689\r\nActive-Remote: 1986535575\r\n"
                    "Connection: close\r\n\r\n") == 0);
  CHECK(dacp_format_request(target, 3689, DACP_PAUSE, request, 20) == 0);

  const char *ok = "HTTP/1.1 204 No Content\r\n";
  CHECK(dacp_parse_status(ok, std::strlen(ok)) == 204);
  CHECK(dacp_parse_status("RTSP/1.0 200 OK", 15) == 0);
  CHECK(dacp_parse_status("HTTP/1.1 2", 10) == 0);
}

static void test_md5() {
  struct Vector {
    const char *text;
    const char *digest;
  };
  static const Vector VECTORS[] = {
      {"", "d41d8cd98f00b204e9800998ecf8427e"},
      {"abc", "900150983cd24fb0d6963f7d28e17f72"},
      {"The quick brown fox jumps over the lazy dog", "9e107d9d372bb6826bd81d3542a419d6"},
      // 56 to 64 bytes need a second padding block, 80 bytes a whole block first
      {"12345678901234567890123456789012345678901234567890123456", "49f193adce178490e34d1b3a4ec0064c"},
      {"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
       "57edf4a22be3c955ac49da2e2107b67a"},
  };
  for (const Vector &vector : VECTORS) {
    char hex[MD5_SIZE * 2 + 1];
    md5_hex(vector.text, std::strlen(vector.text), hex);
    CHECK(std::strcmp(hex, vector.digest) == 0);
  }
}

int main() {
  test_base64();
  test_md5();
  test_dmap();
  test_dacp();
  return finish("test_util");
}
