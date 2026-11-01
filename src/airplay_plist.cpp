#include "airplay_plist.h"

#include <algorithm>
#include <cinttypes>
#include <cstdarg>
#include <cstdio>
#include <cstring>

namespace airplay {

// Object types: the high nibble of an object's marker byte
static constexpr uint8_t TYPE_SIMPLE = 0x0;  // null, false (0x08), true (0x09)
static constexpr uint8_t TYPE_INTEGER = 0x1;
static constexpr uint8_t TYPE_REAL = 0x2;
static constexpr uint8_t TYPE_DATA = 0x4;
static constexpr uint8_t TYPE_ASCII = 0x5;
static constexpr uint8_t TYPE_UTF16 = 0x6;
static constexpr uint8_t TYPE_ARRAY = 0xa;
static constexpr uint8_t TYPE_DICT = 0xd;

static constexpr size_t HEADER_SIZE = 8;
static constexpr size_t TRAILER_SIZE = 32;

// ===== Reader =====

uint64_t PlistReader::read_uint_(size_t offset, size_t size) const {
  uint64_t value = 0;
  for (size_t i = 0; i < size; i++)
    value = (value << 8) | this->data_[offset + i];
  return value;
}

PlistReader::Object PlistReader::ref_(size_t offset) const {
  if (offset + this->ref_size_ > this->length_)
    return NONE;
  const uint64_t ref = this->read_uint_(offset, this->ref_size_);
  return ref < this->object_count_ ? static_cast<Object>(ref) : NONE;
}

bool PlistReader::parse(const uint8_t *data, size_t length) {
  this->root_ = NONE;
  if (length < HEADER_SIZE + TRAILER_SIZE || std::memcmp(data, "bplist00", HEADER_SIZE) != 0)
    return false;
  this->data_ = data;
  this->length_ = length;
  const size_t trailer = length - TRAILER_SIZE;
  this->offset_size_ = data[trailer + 6];
  this->ref_size_ = data[trailer + 7];
  const uint64_t object_count = this->read_uint_(trailer + 8, 8);
  const uint64_t root = this->read_uint_(trailer + 16, 8);
  const uint64_t offset_table = this->read_uint_(trailer + 24, 8);
  if (this->offset_size_ < 1 || this->offset_size_ > 8 || this->ref_size_ < 1 || this->ref_size_ > 8 ||
      object_count == 0 || object_count > length || root >= object_count || offset_table < HEADER_SIZE ||
      offset_table > trailer || (trailer - offset_table) / this->offset_size_ < object_count) {
    return false;
  }
  this->object_count_ = static_cast<uint32_t>(object_count);
  this->offset_table_ = static_cast<size_t>(offset_table);
  this->root_ = static_cast<Object>(root);
  return true;
}

bool PlistReader::header_(Object object, uint8_t *type, uint8_t *info, size_t *length, size_t *content) const {
  if (object >= this->object_count_)
    return false;
  const uint64_t offset = this->read_uint_(this->offset_table_ + object * this->offset_size_, this->offset_size_);
  if (offset < HEADER_SIZE || offset >= this->offset_table_)
    return false;
  const uint8_t marker = this->data_[offset];
  *type = marker >> 4;
  *info = marker & 0x0f;
  size_t position = static_cast<size_t>(offset) + 1;
  size_t count = *info;
  // Lengths of 15 or more follow as an integer object
  if (*info == 0x0f && *type != TYPE_SIMPLE && *type != TYPE_INTEGER && *type != TYPE_REAL) {
    if (position >= this->offset_table_ || (this->data_[position] >> 4) != TYPE_INTEGER)
      return false;
    const size_t size = size_t{1} << (this->data_[position] & 0x0f);
    if (size > 8 || position + 1 + size > this->offset_table_)
      return false;
    count = static_cast<size_t>(this->read_uint_(position + 1, size));
    position += 1 + size;
  }
  // The content must lie before the offset table
  size_t content_size = count;
  if (*type == TYPE_INTEGER || *type == TYPE_REAL) {
    content_size = size_t{1} << *info;
  } else if (*type == TYPE_UTF16) {
    content_size = count * 2;
  } else if (*type == TYPE_ARRAY) {
    content_size = count * this->ref_size_;
  } else if (*type == TYPE_DICT) {
    content_size = count * 2 * this->ref_size_;
  } else if (*type == TYPE_SIMPLE) {
    content_size = 0;
  }
  if (count > this->length_ || content_size > this->offset_table_ - position)
    return false;
  *length = count;
  *content = position;
  return true;
}

size_t PlistReader::count(Object container) const {
  uint8_t type, info;
  size_t length, content;
  if (!this->header_(container, &type, &info, &length, &content) || (type != TYPE_ARRAY && type != TYPE_DICT))
    return 0;
  return length;
}

PlistReader::Object PlistReader::at(Object array, size_t index) const {
  uint8_t type, info;
  size_t length, content;
  if (!this->header_(array, &type, &info, &length, &content) || type != TYPE_ARRAY || index >= length)
    return NONE;
  return this->ref_(content + index * this->ref_size_);
}

PlistReader::Object PlistReader::get(Object dict, const char *key) const {
  uint8_t type, info;
  size_t length, content;
  if (!this->header_(dict, &type, &info, &length, &content) || type != TYPE_DICT)
    return NONE;
  for (size_t i = 0; i < length; i++) {
    if (this->string_equals(this->ref_(content + i * this->ref_size_), key))
      return this->ref_(content + (length + i) * this->ref_size_);
  }
  return NONE;
}

bool PlistReader::get_integer(Object object, int64_t *value) const {
  uint8_t type, info;
  size_t length, content;
  if (!this->header_(object, &type, &info, &length, &content) || type != TYPE_INTEGER || info > 4)
    return false;
  // 16 byte integers hold large unsigned values; their lower 8 bytes are taken
  const size_t size = size_t{1} << info;
  *value = static_cast<int64_t>(this->read_uint_(content + (size > 8 ? size - 8 : 0), size > 8 ? 8 : size));
  return true;
}

bool PlistReader::get_real(Object object, double *value) const {
  uint8_t type, info;
  size_t length, content;
  if (!this->header_(object, &type, &info, &length, &content))
    return false;
  if (type == TYPE_INTEGER) {
    int64_t integer;
    if (!this->get_integer(object, &integer))
      return false;
    *value = static_cast<double>(integer);
    return true;
  }
  if (type != TYPE_REAL)
    return false;
  if (info == 2) {
    const auto bits = static_cast<uint32_t>(this->read_uint_(content, 4));
    float f;
    std::memcpy(&f, &bits, sizeof(f));
    *value = f;
    return true;
  }
  if (info == 3) {
    const uint64_t bits = this->read_uint_(content, 8);
    std::memcpy(value, &bits, sizeof(*value));
    return true;
  }
  return false;
}

bool PlistReader::get_bool(Object object, bool *value) const {
  uint8_t type, info;
  size_t length, content;
  if (!this->header_(object, &type, &info, &length, &content) || type != TYPE_SIMPLE || (info != 8 && info != 9))
    return false;
  *value = info == 9;
  return true;
}

bool PlistReader::get_data(Object object, const uint8_t **data, size_t *length) const {
  uint8_t type, info;
  size_t content;
  if (!this->header_(object, &type, &info, length, &content) || type != TYPE_DATA)
    return false;
  *data = this->data_ + content;
  return true;
}

bool PlistReader::get_string(Object object, const char **text, size_t *length) const {
  uint8_t type, info;
  size_t content;
  if (!this->header_(object, &type, &info, length, &content) || type != TYPE_ASCII)
    return false;
  *text = reinterpret_cast<const char *>(this->data_ + content);
  return true;
}

bool PlistReader::string_equals(Object object, const char *text) const {
  uint8_t type, info;
  size_t length, content;
  if (!this->header_(object, &type, &info, &length, &content) || std::strlen(text) != length)
    return false;
  if (type == TYPE_ASCII)
    return std::memcmp(this->data_ + content, text, length) == 0;
  if (type != TYPE_UTF16)
    return false;
  for (size_t i = 0; i < length; i++) {
    if (this->data_[content + 2 * i] != 0 || this->data_[content + 2 * i + 1] != static_cast<uint8_t>(text[i]))
      return false;
  }
  return true;
}

static void append(char *text, size_t size, size_t &length, const char *format, ...) {
  if (length + 1 >= size)
    return;
  va_list args;
  va_start(args, format);
  const int written = std::vsnprintf(text + length, size - length, format, args);
  va_end(args);
  if (written > 0)
    length = std::min(length + static_cast<size_t>(written), size - 1);
}

void PlistReader::describe_(Object object, char *text, size_t size, size_t &length, int depth) const {
  int64_t integer;
  double real;
  bool flag;
  const uint8_t *data;
  const char *string;
  size_t count;
  uint8_t type, info;
  size_t content;
  if (object == NONE || !this->header_(object, &type, &info, &count, &content)) {
    append(text, size, length, "?");
  } else if (this->get_bool(object, &flag)) {
    append(text, size, length, flag ? "true" : "false");
  } else if (this->get_integer(object, &integer)) {
    append(text, size, length, "%" PRId64, integer);
  } else if (this->get_real(object, &real)) {
    append(text, size, length, "%g", real);
  } else if (this->get_string(object, &string, &count)) {
    append(text, size, length, "\"%.*s\"", static_cast<int>(count < 48 ? count : 48), string);
  } else if (this->get_data(object, &data, &count)) {
    append(text, size, length, "<data %u>", static_cast<unsigned>(count));
  } else if (type == TYPE_UTF16) {
    append(text, size, length, "<utf16 %u>", static_cast<unsigned>(count));
  } else if ((type == TYPE_DICT || type == TYPE_ARRAY) && depth >= 6) {
    append(text, size, length, type == TYPE_DICT ? "{...}" : "[...]");
  } else if (type == TYPE_DICT) {
    append(text, size, length, "{");
    for (size_t i = 0; i < count; i++) {
      const Object key = this->ref_(content + i * this->ref_size_);
      const char *key_text = nullptr;
      size_t key_length = 0;
      append(text, size, length, i == 0 ? "" : ", ");
      if (this->get_string(key, &key_text, &key_length)) {
        append(text, size, length, "%.*s: ", static_cast<int>(key_length), key_text);
      } else {
        this->describe_(key, text, size, length, depth + 1);
        append(text, size, length, ": ");
      }
      this->describe_(this->ref_(content + (count + i) * this->ref_size_), text, size, length, depth + 1);
    }
    append(text, size, length, "}");
  } else if (type == TYPE_ARRAY) {
    append(text, size, length, "[");
    for (size_t i = 0; i < count; i++) {
      append(text, size, length, i == 0 ? "" : ", ");
      this->describe_(this->ref_(content + i * this->ref_size_), text, size, length, depth + 1);
    }
    append(text, size, length, "]");
  } else {
    append(text, size, length, "<type %u>", type);
  }
}

size_t PlistReader::describe(Object object, char *text, size_t size) const {
  if (size == 0)
    return 0;
  text[0] = '\0';
  size_t length = 0;
  this->describe_(object, text, size, length, 0);
  return length;
}

// ===== Writer =====

PlistWriter::PlistWriter(uint8_t *buffer, size_t size) : buffer_(buffer), size_(size) {
  this->write_(reinterpret_cast<const uint8_t *>("bplist00"), HEADER_SIZE);
}

void PlistWriter::write_(const uint8_t *data, size_t length) {
  if (this->error_ || this->length_ + length > this->size_) {
    this->error_ = true;
    return;
  }
  std::memcpy(this->buffer_ + this->length_, data, length);
  this->length_ += length;
}

void PlistWriter::write_marker_(uint8_t type, size_t length) {
  if (length < 15) {
    this->write_byte_(static_cast<uint8_t>((type << 4) | length));
    return;
  }
  this->write_byte_(static_cast<uint8_t>((type << 4) | 0x0f));
  if (length <= 0xff) {
    const uint8_t bytes[] = {0x10, static_cast<uint8_t>(length)};
    this->write_(bytes, sizeof(bytes));
  } else {
    const uint8_t bytes[] = {0x11, static_cast<uint8_t>(length >> 8), static_cast<uint8_t>(length)};
    this->write_(bytes, sizeof(bytes));
  }
}

bool PlistWriter::begin_object_() {
  // Offsets are 2 bytes; the whole list must stay below 64 KiB
  if (this->error_ || this->object_count_ >= MAX_OBJECTS || this->length_ > 0xffff) {
    this->error_ = true;
    return false;
  }
  if (this->depth_ == 0 && this->object_count_ > 0) {
    this->error_ = true;  // A second top level object
    return false;
  }
  const auto index = static_cast<uint16_t>(this->object_count_);
  this->offsets_[this->object_count_++] = static_cast<uint16_t>(this->length_);
  if (this->depth_ > 0) {
    Container &container = this->stack_[this->depth_ - 1];
    // Dictionaries hold all key references, then all value references
    size_t slot = container.filled;
    if (container.dict)
      slot = (container.filled % 2 == 0 ? 0 : container.count) + container.filled / 2;
    uint8_t *ref = this->buffer_ + container.refs + slot * REF_SIZE;
    ref[0] = static_cast<uint8_t>(index >> 8);
    ref[1] = static_cast<uint8_t>(index);
    container.filled++;
  }
  return true;
}

void PlistWriter::close_full_containers_() {
  while (this->depth_ > 0) {
    const Container &container = this->stack_[this->depth_ - 1];
    if (container.filled < (container.dict ? 2 * container.count : container.count))
      return;
    this->depth_--;
  }
}

void PlistWriter::begin_container_(uint8_t type, size_t count, bool dict) {
  if (!this->begin_object_())
    return;
  if (this->depth_ == MAX_DEPTH || count > 0xffff) {
    this->error_ = true;
    return;
  }
  this->write_marker_(type, count);
  Container &container = this->stack_[this->depth_++];
  container.refs = this->length_;
  container.count = static_cast<uint16_t>(count);
  container.filled = 0;
  container.dict = dict;
  // Room for the references, filled in as the entries are written
  const size_t refs = (dict ? 2 : 1) * count * REF_SIZE;
  if (this->length_ + refs > this->size_) {
    this->error_ = true;
    return;
  }
  std::memset(this->buffer_ + this->length_, 0, refs);
  this->length_ += refs;
  this->close_full_containers_();  // Empty
}

void PlistWriter::begin_dict(size_t entries) { this->begin_container_(TYPE_DICT, entries, true); }

void PlistWriter::begin_array(size_t count) { this->begin_container_(TYPE_ARRAY, count, false); }

void PlistWriter::integer(int64_t value) {
  if (!this->begin_object_())
    return;
  size_t size = 8;
  uint8_t info = 3;
  if (value >= 0 && value <= 0xff) {
    size = 1;
    info = 0;
  } else if (value >= 0 && value <= 0xffff) {
    size = 2;
    info = 1;
  } else if (value >= 0 && value <= 0xffffffffLL) {
    size = 4;
    info = 2;
  }
  this->write_byte_(static_cast<uint8_t>((TYPE_INTEGER << 4) | info));
  const auto bits = static_cast<uint64_t>(value);
  for (size_t i = size; i-- > 0;)
    this->write_byte_(static_cast<uint8_t>(bits >> (8 * i)));
  this->close_full_containers_();
}

void PlistWriter::boolean(bool value) {
  if (!this->begin_object_())
    return;
  this->write_byte_(value ? 0x09 : 0x08);
  this->close_full_containers_();
}

void PlistWriter::real(double value) {
  if (!this->begin_object_())
    return;
  uint64_t bits;
  std::memcpy(&bits, &value, sizeof(bits));
  this->write_byte_((TYPE_REAL << 4) | 3);
  for (size_t i = 8; i-- > 0;)
    this->write_byte_(static_cast<uint8_t>(bits >> (8 * i)));
  this->close_full_containers_();
}

void PlistWriter::string(const char *text) {
  if (!this->begin_object_())
    return;
  const size_t length = std::strlen(text);
  this->write_marker_(TYPE_ASCII, length);
  this->write_(reinterpret_cast<const uint8_t *>(text), length);
  this->close_full_containers_();
}

void PlistWriter::data(const uint8_t *data, size_t length) {
  if (!this->begin_object_())
    return;
  this->write_marker_(TYPE_DATA, length);
  this->write_(data, length);
  this->close_full_containers_();
}

size_t PlistWriter::finish() {
  if (this->error_ || this->depth_ != 0 || this->object_count_ == 0)
    return 0;
  const size_t offset_table = this->length_;
  for (size_t i = 0; i < this->object_count_; i++) {
    const uint8_t bytes[] = {static_cast<uint8_t>(this->offsets_[i] >> 8), static_cast<uint8_t>(this->offsets_[i])};
    this->write_(bytes, sizeof(bytes));
  }
  uint8_t trailer[TRAILER_SIZE] = {};
  trailer[6] = 2;         // Offset size
  trailer[7] = REF_SIZE;  // Reference size
  for (int i = 0; i < 8; i++) {
    trailer[8 + i] = static_cast<uint8_t>(static_cast<uint64_t>(this->object_count_) >> (56 - 8 * i));
    trailer[24 + i] = static_cast<uint8_t>(static_cast<uint64_t>(offset_table) >> (56 - 8 * i));
  }
  this->write_(trailer, sizeof(trailer));
  return this->error_ ? 0 : this->length_;
}

}  // namespace airplay
