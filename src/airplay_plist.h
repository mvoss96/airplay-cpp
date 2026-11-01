#pragma once

#include <cstddef>
#include <cstdint>

namespace airplay {

/// Reads a binary property list ("bplist00"), as AirPlay 2 senders send in SETUP and other requests. Nothing is
/// copied: objects are referred to by index and the data must stay valid.
class PlistReader {
 public:
  using Object = uint32_t;
  static constexpr Object NONE = 0xffffffff;

  /// @return false if the data is not a binary property list this reader understands
  bool parse(const uint8_t *data, size_t length);

  Object root() const { return this->root_; }
  /// Value of a dictionary entry; NONE if missing, or if `dict` is not a dictionary
  Object get(Object dict, const char *key) const;
  /// Entries of a dictionary or array; 0 for other objects
  size_t count(Object container) const;
  /// Element of an array; NONE if out of range, or if `array` is not an array
  Object at(Object array, size_t index) const;

  bool get_integer(Object object, int64_t *value) const;
  /// A real or an integer
  bool get_real(Object object, double *value) const;
  bool get_bool(Object object, bool *value) const;
  bool get_data(Object object, const uint8_t **data, size_t *length) const;
  /// ASCII strings only
  bool get_string(Object object, const char **text, size_t *length) const;
  /// Compares an ASCII or UTF-16 string with ASCII text
  bool string_equals(Object object, const char *text) const;
  /// @brief Writes a short text form of an object for logs, e.g. {type: "x", params: [1, <data 32>]}.
  /// @return the length of the text, which is cut off to fit `size` (null terminated)
  size_t describe(Object object, char *text, size_t size) const;

 private:
  /// Type nibble, length and where the content starts
  bool header_(Object object, uint8_t *type, uint8_t *info, size_t *length, size_t *content) const;
  uint64_t read_uint_(size_t offset, size_t size) const;
  Object ref_(size_t offset) const;
  void describe_(Object object, char *text, size_t size, size_t &length, int depth) const;

  const uint8_t *data_{nullptr};
  size_t length_{0};
  uint8_t offset_size_{0};
  uint8_t ref_size_{0};
  uint32_t object_count_{0};
  size_t offset_table_{0};
  Object root_{NONE};
};

/// Writes a binary property list. Containers are given their number of entries up front; dictionary entries are
/// written as key() followed by the value.
///
///   PlistWriter writer(buffer, sizeof(buffer));
///   writer.begin_dict(1);
///   writer.key("eventPort");
///   writer.integer(5000);
///   size_t length = writer.finish();
class PlistWriter {
 public:
  PlistWriter(uint8_t *buffer, size_t size);

  void begin_dict(size_t entries);
  void begin_array(size_t count);
  void key(const char *key) { this->string(key); }
  void integer(int64_t value);
  void boolean(bool value);
  void real(double value);
  void string(const char *text);
  void data(const uint8_t *data, size_t length);

  /// @return the length of the property list; 0 if it did not fit or containers are incomplete
  size_t finish();

 private:
  static constexpr size_t MAX_OBJECTS = 256;
  static constexpr size_t MAX_DEPTH = 8;
  static constexpr size_t REF_SIZE = 2;

  struct Container {
    size_t refs;  // Offset of the first reference
    uint16_t count;
    uint16_t filled;  // References written; for a dictionary keys and values alternate
    bool dict;
  };

  /// Starts an object: records its offset and puts a reference to it into the open container
  bool begin_object_();
  void begin_container_(uint8_t marker, size_t count, bool dict);
  void write_marker_(uint8_t type, size_t length);
  void write_(const uint8_t *data, size_t length);
  void write_byte_(uint8_t byte) { this->write_(&byte, 1); }
  void close_full_containers_();

  uint8_t *buffer_;
  size_t size_;
  size_t length_{0};
  bool error_{false};
  uint16_t offsets_[MAX_OBJECTS];
  size_t object_count_{0};
  Container stack_[MAX_DEPTH];
  size_t depth_{0};
};

}  // namespace airplay
