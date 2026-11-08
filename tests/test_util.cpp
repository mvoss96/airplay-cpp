// base64, DMAP metadata and DACP helpers
#include "airplay_dacp.h"
#include "airplay_mrp.h"
#include "airplay_ptp.h"
#include "airplay_util.h"
#include "test_common.h"

#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

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

/// A PTP message: header with type, clock, sequence and flags, then a timestamp
static std::vector<uint8_t> ptp_message(uint8_t type, uint64_t clock, uint16_t sequence, bool two_step,
                                        int64_t timestamp_ns, size_t length = 44) {
  std::vector<uint8_t> m(length, 0);
  m[0] = type;
  m[1] = 2;
  m[2] = static_cast<uint8_t>(length >> 8);
  m[3] = static_cast<uint8_t>(length);
  m[6] = two_step ? 0x02 : 0x00;
  for (int i = 0; i < 8; i++)
    m[20 + i] = static_cast<uint8_t>(clock >> (56 - 8 * i));
  m[30] = static_cast<uint8_t>(sequence >> 8);
  m[31] = static_cast<uint8_t>(sequence);
  const auto seconds = static_cast<uint64_t>(timestamp_ns / 1000000000);
  const auto nanoseconds = static_cast<uint32_t>(timestamp_ns % 1000000000);
  for (int i = 0; i < 6; i++)
    m[34 + i] = static_cast<uint8_t>(seconds >> (40 - 8 * i));
  for (int i = 0; i < 4; i++)
    m[40 + i] = static_cast<uint8_t>(nanoseconds >> (24 - 8 * i));
  return m;
}

// The iPad's pause from the Home app's tile, as an iPhone received it
static const uint8_t MRP_PAUSE[] = {
    0xec, 0x02, 0x08, 0x01, 0x12, 0x24, 0x44, 0x44, 0x30, 0x36, 0x35, 0x32, 0x41, 0x36, 0x2d, 0x43, 0x32, 0x33, 0x33,
    0x2d, 0x34, 0x32, 0x41, 0x39, 0x2d, 0x39, 0x35, 0x38, 0x43, 0x2d, 0x37, 0x42, 0x34, 0x34, 0x44, 0x45, 0x32, 0x39,
    0x32, 0x31, 0x35, 0x46, 0x32, 0x9a, 0x02, 0x08, 0x02, 0x12, 0x94, 0x01, 0x88, 0x01, 0x00, 0x82, 0x02, 0x24, 0x34,
    0x38, 0x37, 0x44, 0x43, 0x31, 0x30, 0x39, 0x2d, 0x35, 0x31, 0x33, 0x36, 0x2d, 0x34, 0x46, 0x37, 0x46, 0x2d, 0x41,
    0x38, 0x46, 0x38, 0x2d, 0x31, 0x31, 0x32, 0x45, 0x43, 0x36, 0x41, 0x46, 0x37, 0x44, 0x32, 0x44, 0x8a, 0x02, 0x53,
    0x53, 0x65, 0x6e, 0x64, 0x65, 0x72, 0x44, 0x65, 0x76, 0x69, 0x63, 0x65, 0x20, 0x3d, 0x20, 0x3c, 0x69, 0x50, 0x61,
    0x64, 0x3e, 0x2c, 0x20, 0x53, 0x65, 0x6e, 0x64, 0x65, 0x72, 0x42, 0x75, 0x6e, 0x64, 0x6c, 0x65, 0x49, 0x64, 0x65,
    0x6e, 0x74, 0x69, 0x66, 0x69, 0x65, 0x72, 0x20, 0x3d, 0x20, 0x3c, 0x63, 0x6f, 0x6d, 0x2e, 0x61, 0x70, 0x70, 0x6c,
    0x65, 0x2e, 0x48, 0x6f, 0x6d, 0x65, 0x3e, 0x2c, 0x20, 0x53, 0x65, 0x6e, 0x64, 0x65, 0x72, 0x50, 0x49, 0x44, 0x20,
    0x3d, 0x20, 0x3c, 0x37, 0x34, 0x34, 0x3e, 0x81, 0x04, 0xb9, 0xfa, 0xe7, 0x54, 0xb0, 0x4f, 0xc8, 0x41, 0xf2, 0x05,
    0x07, 0x38, 0x36, 0x33, 0x62, 0x34, 0x64, 0x37, 0x1a, 0x7f, 0x0a, 0x1a, 0x08, 0x02, 0x12, 0x10, 0x4d, 0x61, 0x72,
    0x63, 0x75, 0x73, 0x20, 0x69, 0x50, 0x68, 0x6f, 0x6e, 0x65, 0x20, 0x31, 0x36, 0x18, 0xc6, 0xd8, 0xd9, 0xa3, 0x04,
    0x12, 0x32, 0x08, 0x9a, 0x44, 0x12, 0x1b, 0x63, 0x6f, 0x6d, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x69,
    0x6f, 0x73, 0x2e, 0x79, 0x6f, 0x75, 0x74, 0x75, 0x62, 0x65, 0x6d, 0x75, 0x73, 0x69, 0x63, 0x20, 0xf5, 0x03, 0x3a,
    0x0d, 0x59, 0x6f, 0x75, 0x54, 0x75, 0x62, 0x65, 0x20, 0x4d, 0x75, 0x73, 0x69, 0x63, 0x1a, 0x2d, 0x0a, 0x19, 0x4d,
    0x65, 0x64, 0x69, 0x61, 0x52, 0x65, 0x6d, 0x6f, 0x74, 0x65, 0x2d, 0x44, 0x65, 0x66, 0x61, 0x75, 0x6c, 0x74, 0x50,
    0x6c, 0x61, 0x79, 0x65, 0x72, 0x12, 0x0e, 0x44, 0x65, 0x66, 0x61, 0x75, 0x6c, 0x74, 0x20, 0x50, 0x6c, 0x61, 0x79,
    0x65, 0x72, 0x30, 0x00, 0xaa, 0x05, 0x24, 0x39, 0x41, 0x38, 0x34, 0x35, 0x46, 0x41, 0x30, 0x2d, 0x33, 0x42, 0x46,
    0x33, 0x2d, 0x34, 0x33, 0x34, 0x45, 0x2d, 0x38, 0x33, 0x34, 0x41, 0x2d, 0x30, 0x41, 0x41, 0x33, 0x33, 0x34, 0x39,
    0x38, 0x35, 0x41, 0x44, 0x43,
};

static void test_mrp() {
  using namespace airplay;
  mrp::Request requests[2];
  CHECK(mrp::parse(MRP_PAUSE, sizeof(MRP_PAUSE), requests, 2) == 1);
  CHECK(requests[0].type == mrp::MESSAGE_TYPE_SEND_COMMAND && requests[0].command == mrp::COMMAND_PAUSE);
  CHECK(std::strcmp(requests[0].identifier, "DD0652A6-C233-42A9-958C-7B44DE29215F") == 0);
  CHECK(std::strcmp(requests[0].command_id, "487DC109-5136-4F7F-A8F8-112EC6AF7D2D") == 0);
  CHECK(mrp::parse(MRP_PAUSE, 10, requests, 2) == 0);  // Cut off
  // A nested message longer than 127 bytes gets a two-byte length
  uint8_t buffer[512];
  ProtoWriter w(buffer, sizeof(buffer));
  w.varint(1, 300);
  w.begin(2);
  for (int i = 0; i < 20; i++)
    w.string(3, "0123456789");
  w.end();
  w.real(4, 1.5);
  CHECK(w.length() == 3 + 3 + 20 * 12 + 9);
  ProtoReader r(buffer, w.length());
  CHECK(r.next() && r.field() == 1 && r.value() == 300);
  CHECK(r.next() && r.field() == 2 && r.is_bytes() && r.size() == 240);
  ProtoReader inner(r.data(), r.size());
  int strings = 0;
  while (inner.next())
    strings += inner.field() == 3 && inner.size() == 10 ? 1 : 0;
  CHECK(strings == 20);
  double value = 0;
  CHECK(r.next() && r.field() == 4);
  const uint64_t bits = r.value();
  std::memcpy(&value, &bits, sizeof(value));
  CHECK(value == 1.5 && !r.next());
  ProtoWriter small(buffer, 8);
  small.string(1, "far too long for it");
  CHECK(small.length() == 0);
  // What the receiver answers with goes through the parser too
  const mrp::NowPlaying now{"Title", "Artist", "Album", "Mac", 200.0, 10.0, true};
  const size_t length = mrp::write_command_result(buffer, sizeof(buffer), "id-1", "id-2", "cmd-1", now);
  CHECK(length > 0 && mrp::parse(buffer, length, requests, 2) == 1);
  CHECK(requests[0].type == mrp::MESSAGE_TYPE_SEND_COMMAND_RESULT && std::strcmp(requests[0].identifier, "id-1") == 0);
  CHECK(mrp::write_state(buffer, 40, nullptr, "id", now) == 0);  // Does not fit
  // A state with the cover: its bytes follow what is written, and the length in front counts them
  const mrp::Cover cover{"image/jpeg", "c0ffee", 600, 400, 3000, true};
  const size_t start = mrp::write_state(buffer, sizeof(buffer), "id-3", "id-4", now, &cover);
  CHECK(start > 0 && start + cover.size > sizeof(buffer));
  uint64_t message_length = 0;
  for (size_t i = 0, shift = 0; i < 3; i++, shift += 7) {
    message_length |= static_cast<uint64_t>(buffer[i] & 0x7f) << shift;
    if ((buffer[i] & 0x80) == 0) {
      CHECK(i + 1 + message_length == start + cover.size);
      break;
    }
  }
  CHECK(message_length > cover.size);
}

static void test_image_size() {
  using namespace airplay;
  uint16_t width = 0;
  uint16_t height = 0;
  // PNG: signature and IHDR
  const uint8_t png[24] = {0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0,    13,
                           'I',  'H', 'D', 'R', 0,    0,    0x02, 0x58, 0, 0, 0x01, 0x90};
  CHECK(image_size(png, sizeof(png), &width, &height) && width == 600 && height == 400);
  // JPEG: an APP0 segment, then the start of frame
  const uint8_t jpeg[] = {0xff, 0xd8, 0xff, 0xe0, 0x00, 0x04, 'J', 'F', 0xff, 0xc0, 0x00, 0x11, 0x08, 0x01,
                          0x2c, 0x02, 0x80, 0x03, 0,    0,    0,   0,   0,    0,    0,    0,    0,    0};
  CHECK(image_size(jpeg, sizeof(jpeg), &width, &height) && width == 640 && height == 300);
  CHECK(!image_size(jpeg, 10, &width, &height));  // Cut off before the frame
  const uint8_t other[] = {'G', 'I', 'F', '8', '9', 'a', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  CHECK(!image_size(other, sizeof(other), &width, &height));
}

/// Messages of two clocks read late together (the receiver was busy) move neither; one clock set back moves only it
static void test_ptp_busy_receiver() {
  using airplay::PtpClocks;
  PtpClocks clocks;
  const uint64_t a = 0x1111111111111111ULL;
  const uint64_t b = 0x2222222222222222ULL;
  const int64_t offset_a = 7000LL * 1000000000LL;
  const int64_t offset_b = 9000LL * 1000000000LL;
  int64_t now_us = 1000000;
  uint16_t seq = 0;
  auto sync = [&](uint64_t clock, int64_t offset, int64_t late_us, int64_t set_back_ns) {
    const int64_t sent_ns = now_us * 1000 + offset - set_back_ns;
    clocks.handle(false, ptp_message(0x0, clock, seq, true, 0).data(), 44, 0x0100000a, now_us + 1000 + late_us);
    clocks.handle(true, ptp_message(0x8, clock, seq, false, sent_ns).data(), 44, 0x0100000a, now_us + 1100 + late_us);
  };
  auto run = [&](int64_t seconds, int64_t late_us, int64_t set_back_a_ns) {
    for (int64_t i = 0; i < seconds * 8; i++, seq++, now_us += 125000) {
      sync(a, offset_a, late_us, set_back_a_ns);
      sync(b, offset_b, late_us, 0);
    }
  };
  int64_t found_a = 0;
  int64_t found_b = 0;
  run(3, 0, 0);
  CHECK(clocks.offset_ns(a, now_us, &found_a) && clocks.offset_ns(b, now_us, &found_b));
  const int64_t before_a = found_a;
  const int64_t before_b = found_b;
  // 12 s in which the receiver reads everything 900 ms late
  run(12, 900000, 0);
  CHECK(clocks.offset_ns(a, now_us, &found_a) && clocks.offset_ns(b, now_us, &found_b));
  CHECK(found_a > before_a - 5000000 && found_b > before_b - 5000000);
  run(2, 0, 0);
  // Clock a alone is set back by 500 ms: it follows after a while
  run(12, 0, 500000000);
  CHECK(clocks.offset_ns(a, now_us, &found_a) && clocks.offset_ns(b, now_us, &found_b));
  CHECK(found_a < before_a - 450000000 && found_a > before_a - 550000000);
  CHECK(found_b > before_b - 5000000);
}

static void test_ptp() {
  using airplay::PtpClocks;
  PtpClocks clocks;
  const uint64_t clock = 0x1122334455667788ULL;
  const int64_t offset = 5000LL * 1000000000LL + 123456789;  // The master's time minus local time
  int64_t found = 0;
  CHECK(!clocks.offset_ns(clock, 1000000, &found));
  // Two-step Sync messages every 125 ms; the delay varies from 1 to 4 ms, the least is 1 ms
  int64_t now_us = 1000000;
  for (uint16_t seq = 0; seq < 20; seq++) {
    const int64_t sent_ns = now_us * 1000 + offset;
    const int64_t delay_us = 1000 + (seq % 4) * 1000;
    const int64_t arrival_us = now_us + delay_us;
    clocks.handle(false, ptp_message(0x0, clock, seq, true, 0).data(), 44, 0x0100000a, arrival_us);
    clocks.handle(true, ptp_message(0x8, clock, seq, false, sent_ns).data(), 44, 0x0100000a, arrival_us + 200);
    // A Follow_Up for another Sync is ignored
    clocks.handle(true, ptp_message(0x8, clock, static_cast<uint16_t>(seq + 100), false, 0).data(), 44, 0x0100000a,
                  arrival_us + 300);
    now_us += 125000;
  }
  CHECK(clocks.offset_ns(clock, now_us, &found));
  // Less the shortest delay, which is not measured, and what the clocks may have drifted since that sample
  CHECK(found <= offset - 1000000 && found > offset - 1100000);
  CHECK(clocks.grandmaster() == clock);
  CHECK(clocks.offset_ns(0, now_us, &found));  // 0 is the grandmaster
  // An Announce names another grandmaster
  std::vector<uint8_t> announce = ptp_message(0xb, clock, 1, false, 0, 64);
  for (int i = 0; i < 8; i++)
    announce[53 + i] = static_cast<uint8_t>(0xaabbccddeeff0011ULL >> (56 - 8 * i));
  clocks.handle(true, announce.data(), announce.size(), 0x0100000a, now_us);
  CHECK(clocks.grandmaster() == 0xaabbccddeeff0011ULL);
  // Unknown or silent clocks have no offset
  CHECK(!clocks.offset_ns(0x99, now_us, &found));
  CHECK(!clocks.offset_ns(clock, now_us + 10000000, &found));
  // Taking part: an Announce to the grandmaster's address every 2 s, passing on its details one step further
  PtpClocks active;
  const uint8_t mac[6] = {0x3c, 0x84, 0x27, 0x14, 0x86, 0x94};
  active.set_identity(mac);
  uint8_t message[PtpClocks::MAX_MESSAGE_SIZE];
  uint32_t to = 0;
  bool general = false;
  CHECK(active.next_message(0, message, 1000000, &to, &general) == 0);  // No grandmaster yet
  now_us = 3000000;
  for (uint16_t seq = 0; seq < 8; seq++) {
    active.handle(false, ptp_message(0x0, clock, seq, true, 0).data(), 44, 0x0200000a, now_us + 1000);
    active.handle(true, ptp_message(0x8, clock, seq, false, now_us * 1000 + offset).data(), 44, 0x0200000a,
                  now_us + 1100);
    now_us += 125000;
  }
  CHECK(active.next_message(0, message, now_us, &to, &general) == 64 && general && to == 0x0200000a);
  CHECK((message[0] & 0x0f) == 0xb && message[47] == 255 && message[48] == 255);
  CHECK(message[20] == 0x3c && message[23] == 0xff && message[24] == 0xfe && message[27] == 0x94);
  CHECK(active.offset_ns(clock, now_us, &found) && std::llabs(found - (offset - 1000000)) < 100000);
  // Then a Delay_Req; the master's answer gives the delay (1 ms each way), which the offset then includes
  CHECK(active.next_message(0, message, now_us, &to, &general) == 44 && !general && to == 0x0200000a);
  CHECK((message[0] & 0x0f) == 0x1);
  std::vector<uint8_t> answer = ptp_message(0x9, clock, static_cast<uint16_t>(message[30] << 8 | message[31]), false,
                                            now_us * 1000 + offset + 1000000, 54);
  std::copy(message + 20, message + 30, answer.begin() + 44);  // To the port that asked
  active.handle(true, answer.data(), answer.size(), 0x0200000a, now_us + 2000);
  CHECK(active.offset_ns(clock, now_us, &found) && std::llabs(found - offset) < 100000);
  CHECK(active.next_message(0, message, now_us + 500000, &to, &general) == 0);  // Not due yet
  CHECK(active.next_message(0, message, now_us + 1000000, &to, &general) == 44);
  CHECK(active.next_message(0, message, now_us + 2000000, &to, &general) == 64);
  // A master that answers none (macOS) gets no more after five
  PtpClocks silent;
  silent.set_identity(mac);
  int requests = 0;
  for (uint16_t seq = 0; seq < 160; seq++) {  // 20 s
    now_us += 125000;
    silent.handle(false, ptp_message(0x0, clock, seq, true, 0).data(), 44, 0x0200000a, now_us + 1000);
    silent.handle(true, ptp_message(0x8, clock, seq, false, now_us * 1000 + offset).data(), 44, 0x0200000a,
                  now_us + 1100);
    if (silent.next_message(0, message, now_us, &to, &general) == 44)
      requests++;
  }
  CHECK(requests == 5);

  // Samples taken late for 3 s while the receiver is busy (50 to 300 ms) barely move the offset; a clock that was
  // set back by a second is followed after 64 samples
  PtpClocks busy;
  now_us = 10000000;
  uint16_t sequence = 0;
  auto sync_at = [&](int64_t delay_us, int64_t clock_offset) {
    busy.handle(false, ptp_message(0x0, clock, sequence, true, 0).data(), 44, 1, now_us + delay_us);
    busy.handle(true, ptp_message(0x8, clock, sequence, false, now_us * 1000 + clock_offset).data(), 44, 1,
                now_us + delay_us);
    sequence++;
    now_us += 125000;
  };
  for (int i = 0; i < 16; i++)
    sync_at(1000, offset);
  for (int i = 0; i < 24; i++)
    sync_at(50000 + (i % 6) * 50000, offset);
  CHECK(busy.offset_ns(clock, now_us, &found) && found <= offset - 1000000 && found > offset - 1400000);
  for (int i = 0; i < 64; i++)
    sync_at(1000, offset - 1000000000LL);
  CHECK(busy.offset_ns(clock, now_us, &found) && std::llabs(found - (offset - 1000000000LL + -1000000)) < 100000);

  // A single sample 100 ms too high (a wrong correction) is ignored; three in a row raise the estimate
  PtpClocks outlier;
  now_us = 20000000;
  auto outlier_sync = [&](int64_t error_ns) {
    outlier.handle(false, ptp_message(0x0, clock, sequence, true, 0).data(), 44, 1, now_us + 1000);
    outlier.handle(true, ptp_message(0x8, clock, sequence, false, now_us * 1000 + offset + error_ns).data(), 44, 1,
                   now_us + 1000);
    sequence++;
    now_us += 125000;
  };
  for (int i = 0; i < 16; i++)
    outlier_sync(0);
  outlier_sync(100000000);
  outlier_sync(0);
  CHECK(outlier.offset_ns(clock, now_us, &found) && std::llabs(found - (offset - 1000000)) < 100000);
  for (int i = 0; i < 3; i++)
    outlier_sync(10000000);
  CHECK(outlier.offset_ns(clock, now_us, &found) && std::llabs(found - (offset + 9000000)) < 100000);

  // Two grandmasters at once (an iPhone and a Mac): messages go to the clock the session follows, with its details
  PtpClocks two;
  two.set_identity(mac);
  const uint64_t phone = 0x10da63d7b20a0008ULL;
  const uint64_t laptop = 0x9e74f47cbea60008ULL;
  now_us = 30000000;
  for (uint16_t seq = 0; seq < 8; seq++) {
    for (const auto &[id, address] : {std::pair{phone, 0x5302a8c0u}, std::pair{laptop, 0x9c02a8c0u}}) {
      std::vector<uint8_t> announce = ptp_message(0xb, id, seq, false, 0, 64);
      announce[47] = id == phone ? 250 : 251;
      for (int i = 0; i < 8; i++)
        announce[53 + i] = static_cast<uint8_t>(id >> (56 - 8 * i));
      two.handle(true, announce.data(), announce.size(), address, now_us);
      two.handle(false, ptp_message(0x0, id, seq, true, 0).data(), 44, address, now_us + 1000);
      two.handle(true, ptp_message(0x8, id, seq, false, now_us * 1000 + offset).data(), 44, address, now_us + 1000);
    }
    now_us += 125000;
  }
  CHECK(two.next_message(phone, message, now_us, &to, &general) == 64 && to == 0x5302a8c0u);
  CHECK(message[47] == 250 && message[53] == 0x10 && message[62] == 1);  // The phone's details, one step more
  CHECK(two.next_message(phone, message, now_us, &to, &general) == 44 && to == 0x5302a8c0u);  // Its Delay_Req
  CHECK(two.next_message(phone, message, now_us, &to, &general) == 0);                        // Nothing else to send

  // A sender that slept comes back with its clock 332 s behind: three samples confirm the jump
  PtpClocks sleeper;
  now_us = 40000000;
  auto sleeper_sync = [&](int64_t clock_offset) {
    sleeper.handle(false, ptp_message(0x0, clock, sequence, true, 0).data(), 44, 1, now_us + 1000);
    sleeper.handle(true, ptp_message(0x8, clock, sequence, false, now_us * 1000 + clock_offset).data(), 44, 1,
                   now_us + 1000);
    sequence++;
    now_us += 125000;
  };
  for (int i = 0; i < 16; i++)
    sleeper_sync(offset);
  for (int i = 0; i < 3; i++)
    sleeper_sync(offset - 332000000000LL);
  CHECK(sleeper.offset_ns(clock, now_us, &found) && std::llabs(found - (offset - 332000000000LL - 1000000)) < 100000);
  int64_t jump_ns = 0;
  CHECK(sleeper.jumps(clock, &jump_ns) == 1 && std::llabs(jump_ns + 332000000000LL) < 1000000);
  // A sender that follows a group's new grandmaster sends that clock's time: forward by 471070 s, which three
  // samples confirm, as a jump too
  for (int i = 0; i < 3; i++)
    sleeper_sync(offset + 471070000000000LL);
  CHECK(sleeper.offset_ns(clock, now_us, &found) &&
        std::llabs(found - (offset + 471070000000000LL - 1000000)) < 100000);
  CHECK(sleeper.jumps(clock, &jump_ns) == 2 && std::llabs(jump_ns - 471070000000000LL - 332000000000LL) < 1000000);

  // One-step Sync carries its own time
  PtpClocks one_step;
  for (uint16_t seq = 0; seq < 4; seq++)
    one_step.handle(false, ptp_message(0x0, clock, seq, false, 2000000000LL + offset).data(), 44, 1, 2000000 + 500);
  CHECK(one_step.offset_ns(clock, 2000000, &found) && found == offset - 500000);
}

int main() {
  test_base64();
  test_md5();
  test_dmap();
  test_dacp();
  test_ptp();
  test_mrp();
  test_ptp_busy_receiver();
  test_image_size();
  return finish("test_util");
}
