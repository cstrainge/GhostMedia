#include <ghostmedia/gm_core.h>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <initializer_list>
#include <limits>
#include <new>
#include <string>
#include <string_view>
#include <vector>

namespace {
enum class JsonKind {
    object,
    array,
    string,
    number,
    boolean
};

struct JsonValue;

struct JsonMember {
    std::string name;
    JsonValue *value;
};

struct JsonValue {
    JsonKind kind = JsonKind::string;
    std::string string_value;
    uint64_t number_value = 0;
    bool bool_value = false;
    std::vector<std::pair<std::string, JsonValue>> object_values;
    std::vector<JsonValue> array_values;
};

bool has_readable_data(gm_bytes bytes) {
    return bytes.size == 0 || bytes.data != nullptr;
}

bool is_json_whitespace(uint8_t value) {
    return value == 0x20u || value == 0x09u || value == 0x0au || value == 0x0du;
}

bool is_digit(uint8_t value) {
    return value >= static_cast<uint8_t>('0') && value <= static_cast<uint8_t>('9');
}

bool is_hex_digit(uint8_t value) {
    return (value >= static_cast<uint8_t>('0') && value <= static_cast<uint8_t>('9')) ||
           (value >= static_cast<uint8_t>('a') && value <= static_cast<uint8_t>('f')) ||
           (value >= static_cast<uint8_t>('A') && value <= static_cast<uint8_t>('F'));
}

uint32_t hex_value(uint8_t value) {
    if (value >= static_cast<uint8_t>('0') && value <= static_cast<uint8_t>('9')) {
        return value - static_cast<uint8_t>('0');
    }
    if (value >= static_cast<uint8_t>('a') && value <= static_cast<uint8_t>('f')) {
        return 10u + value - static_cast<uint8_t>('a');
    }
    return 10u + value - static_cast<uint8_t>('A');
}

bool is_valid_utf8(gm_bytes bytes) {
    size_t index = 0;
    while (index < bytes.size) {
        const uint8_t first = bytes.data[index];
        if (first <= 0x7fu) {
            ++index;
            continue;
        }

        if (first >= 0xc2u && first <= 0xdfu) {
            if (index + 1 >= bytes.size || (bytes.data[index + 1] & 0xc0u) != 0x80u) {
                return false;
            }
            index += 2;
            continue;
        }

        if (first >= 0xe0u && first <= 0xefu) {
            if (index + 2 >= bytes.size) {
                return false;
            }
            const uint8_t second = bytes.data[index + 1];
            const uint8_t third = bytes.data[index + 2];
            if ((second & 0xc0u) != 0x80u || (third & 0xc0u) != 0x80u) {
                return false;
            }
            if ((first == 0xe0u && second < 0xa0u) || (first == 0xedu && second >= 0xa0u)) {
                return false;
            }
            index += 3;
            continue;
        }

        if (first >= 0xf0u && first <= 0xf4u) {
            if (index + 3 >= bytes.size) {
                return false;
            }
            const uint8_t second = bytes.data[index + 1];
            const uint8_t third = bytes.data[index + 2];
            const uint8_t fourth = bytes.data[index + 3];
            if ((second & 0xc0u) != 0x80u || (third & 0xc0u) != 0x80u ||
                (fourth & 0xc0u) != 0x80u) {
                return false;
            }
            if ((first == 0xf0u && second < 0x90u) || (first == 0xf4u && second > 0x8fu)) {
                return false;
            }
            index += 4;
            continue;
        }

        return false;
    }

    return true;
}

void append_utf8(uint32_t code_point, std::string &out) {
    if (code_point <= 0x7fu) {
        out.push_back(static_cast<char>(code_point));
    } else if (code_point <= 0x7ffu) {
        out.push_back(static_cast<char>(0xc0u | (code_point >> 6)));
        out.push_back(static_cast<char>(0x80u | (code_point & 0x3fu)));
    } else if (code_point <= 0xffffu) {
        out.push_back(static_cast<char>(0xe0u | (code_point >> 12)));
        out.push_back(static_cast<char>(0x80u | ((code_point >> 6) & 0x3fu)));
        out.push_back(static_cast<char>(0x80u | (code_point & 0x3fu)));
    } else {
        out.push_back(static_cast<char>(0xf0u | (code_point >> 18)));
        out.push_back(static_cast<char>(0x80u | ((code_point >> 12) & 0x3fu)));
        out.push_back(static_cast<char>(0x80u | ((code_point >> 6) & 0x3fu)));
        out.push_back(static_cast<char>(0x80u | (code_point & 0x3fu)));
    }
}

class JsonParser {
public:
    explicit JsonParser(gm_bytes input) : input_(input) {}

    gm_status parse(JsonValue &out) {
        skip_ws();
        gm_status status = parse_value(1u, out);
        if (status != GM_OK) {
            return status;
        }
        skip_ws();
        return position_ == input_.size ? GM_OK : GM_BAD_MESSAGE;
    }

private:
    gm_status parse_value(uint32_t depth, JsonValue &out) {
        if (depth > GM_CONTROL_MAX_DEPTH) {
            return GM_LIMIT_EXCEEDED;
        }
        if (position_ >= input_.size) {
            return GM_BAD_MESSAGE;
        }

        const uint8_t value = input_.data[position_];
        if (value == static_cast<uint8_t>('{')) {
            return parse_object(depth, out);
        }
        if (value == static_cast<uint8_t>('[')) {
            return parse_array(depth, out);
        }
        if (value == static_cast<uint8_t>('"')) {
            out.kind = JsonKind::string;
            return parse_string(out.string_value);
        }
        if (is_digit(value)) {
            out.kind = JsonKind::number;
            return parse_number(out.number_value);
        }
        if (match_literal("true")) {
            out.kind = JsonKind::boolean;
            out.bool_value = true;
            return GM_OK;
        }
        if (match_literal("false")) {
            out.kind = JsonKind::boolean;
            out.bool_value = false;
            return GM_OK;
        }

        return GM_BAD_MESSAGE;
    }

    gm_status parse_object(uint32_t depth, JsonValue &out) {
        out.kind = JsonKind::object;
        ++position_;
        skip_ws();
        if (position_ < input_.size && input_.data[position_] == static_cast<uint8_t>('}')) {
            ++position_;
            return GM_OK;
        }

        while (position_ < input_.size) {
            if (out.object_values.size() >= GM_CONTROL_MAX_OBJECT_MEMBERS ||
                total_members_ >= GM_CONTROL_MAX_MESSAGE_MEMBERS) {
                return GM_LIMIT_EXCEEDED;
            }

            std::string name;
            gm_status status = parse_string(name);
            if (status != GM_OK) {
                return status;
            }
            for (const auto &member : out.object_values) {
                if (member.first == name) {
                    return GM_BAD_MESSAGE;
                }
            }
            ++total_members_;

            skip_ws();
            if (position_ >= input_.size || input_.data[position_] != static_cast<uint8_t>(':')) {
                return GM_BAD_MESSAGE;
            }
            ++position_;
            skip_ws();

            JsonValue value;
            status = parse_value(depth + 1u, value);
            if (status != GM_OK) {
                return status;
            }
            out.object_values.emplace_back(std::move(name), std::move(value));

            skip_ws();
            if (position_ >= input_.size) {
                return GM_BAD_MESSAGE;
            }
            if (input_.data[position_] == static_cast<uint8_t>('}')) {
                ++position_;
                return GM_OK;
            }
            if (input_.data[position_] != static_cast<uint8_t>(',')) {
                return GM_BAD_MESSAGE;
            }
            ++position_;
            skip_ws();
        }

        return GM_BAD_MESSAGE;
    }

    gm_status parse_array(uint32_t depth, JsonValue &out) {
        out.kind = JsonKind::array;
        ++position_;
        skip_ws();
        if (position_ < input_.size && input_.data[position_] == static_cast<uint8_t>(']')) {
            ++position_;
            return GM_OK;
        }

        while (position_ < input_.size) {
            if (out.array_values.size() >= GM_CONTROL_MAX_ARRAY_ELEMENTS) {
                return GM_LIMIT_EXCEEDED;
            }
            JsonValue value;
            gm_status status = parse_value(depth + 1u, value);
            if (status != GM_OK) {
                return status;
            }
            out.array_values.emplace_back(std::move(value));

            skip_ws();
            if (position_ >= input_.size) {
                return GM_BAD_MESSAGE;
            }
            if (input_.data[position_] == static_cast<uint8_t>(']')) {
                ++position_;
                return GM_OK;
            }
            if (input_.data[position_] != static_cast<uint8_t>(',')) {
                return GM_BAD_MESSAGE;
            }
            ++position_;
            skip_ws();
        }

        return GM_BAD_MESSAGE;
    }

    gm_status parse_string(std::string &out) {
        if (position_ >= input_.size || input_.data[position_] != static_cast<uint8_t>('"')) {
            return GM_BAD_MESSAGE;
        }
        ++position_;
        out.clear();

        while (position_ < input_.size) {
            const uint8_t value = input_.data[position_++];
            if (value == static_cast<uint8_t>('"')) {
                return GM_OK;
            }
            if (value < 0x20u) {
                return GM_BAD_MESSAGE;
            }
            if (value != static_cast<uint8_t>('\\')) {
                out.push_back(static_cast<char>(value));
                if (out.size() > GM_CONTROL_MAX_STRING_BYTES) {
                    return GM_LIMIT_EXCEEDED;
                }
                continue;
            }

            if (position_ >= input_.size) {
                return GM_BAD_MESSAGE;
            }
            const uint8_t escape = input_.data[position_++];
            switch (escape) {
            case static_cast<uint8_t>('"'):
            case static_cast<uint8_t>('\\'):
            case static_cast<uint8_t>('/'):
                out.push_back(static_cast<char>(escape));
                break;
            case static_cast<uint8_t>('b'):
                out.push_back('\b');
                break;
            case static_cast<uint8_t>('f'):
                out.push_back('\f');
                break;
            case static_cast<uint8_t>('n'):
                out.push_back('\n');
                break;
            case static_cast<uint8_t>('r'):
                out.push_back('\r');
                break;
            case static_cast<uint8_t>('t'):
                out.push_back('\t');
                break;
            case static_cast<uint8_t>('u'): {
                uint32_t code_unit = 0;
                gm_status status = parse_hex4(code_unit);
                if (status != GM_OK) {
                    return status;
                }
                if (code_unit >= 0xd800u && code_unit <= 0xdbffu) {
                    if (position_ + 6u > input_.size || input_.data[position_] != static_cast<uint8_t>('\\') ||
                        input_.data[position_ + 1u] != static_cast<uint8_t>('u')) {
                        return GM_BAD_MESSAGE;
                    }
                    position_ += 2u;
                    uint32_t low = 0;
                    status = parse_hex4(low);
                    if (status != GM_OK || low < 0xdc00u || low > 0xdfffu) {
                        return GM_BAD_MESSAGE;
                    }
                    const uint32_t high_ten = code_unit - 0xd800u;
                    const uint32_t low_ten = low - 0xdc00u;
                    append_utf8(0x10000u + ((high_ten << 10u) | low_ten), out);
                } else if (code_unit >= 0xdc00u && code_unit <= 0xdfffu) {
                    return GM_BAD_MESSAGE;
                } else {
                    append_utf8(code_unit, out);
                }
                break;
            }
            default:
                return GM_BAD_MESSAGE;
            }

            if (out.size() > GM_CONTROL_MAX_STRING_BYTES) {
                return GM_LIMIT_EXCEEDED;
            }
        }

        return GM_BAD_MESSAGE;
    }

    gm_status parse_hex4(uint32_t &out) {
        if (position_ + 4u > input_.size) {
            return GM_BAD_MESSAGE;
        }
        uint32_t value = 0;
        for (size_t count = 0; count < 4u; ++count) {
            const uint8_t digit = input_.data[position_++];
            if (!is_hex_digit(digit)) {
                return GM_BAD_MESSAGE;
            }
            value = (value << 4u) | hex_value(digit);
        }
        out = value;
        return GM_OK;
    }

    gm_status parse_number(uint64_t &out) {
        if (position_ >= input_.size || !is_digit(input_.data[position_])) {
            return GM_BAD_MESSAGE;
        }

        uint64_t value = 0;
        if (input_.data[position_] == static_cast<uint8_t>('0')) {
            ++position_;
            if (position_ < input_.size && is_digit(input_.data[position_])) {
                return GM_BAD_MESSAGE;
            }
            out = 0;
        } else {
            while (position_ < input_.size && is_digit(input_.data[position_])) {
                const uint64_t digit = input_.data[position_] - static_cast<uint8_t>('0');
                if (value > (std::numeric_limits<uint64_t>::max() - digit) / 10u) {
                    return GM_BAD_MESSAGE;
                }
                value = (value * 10u) + digit;
                ++position_;
            }
            out = value;
        }

        if (position_ < input_.size && (input_.data[position_] == static_cast<uint8_t>('.') ||
                                       input_.data[position_] == static_cast<uint8_t>('e') ||
                                       input_.data[position_] == static_cast<uint8_t>('E'))) {
            return GM_BAD_MESSAGE;
        }

        return GM_OK;
    }

    bool match_literal(const char *literal) {
        const size_t length = std::strlen(literal);
        if (position_ + length > input_.size) {
            return false;
        }
        if (std::memcmp(input_.data + position_, literal, length) != 0) {
            return false;
        }
        position_ += length;
        return true;
    }

    void skip_ws() {
        while (position_ < input_.size && is_json_whitespace(input_.data[position_])) {
            ++position_;
        }
    }

    gm_bytes input_{};
    size_t position_ = 0;
    uint32_t total_members_ = 0;
};

gm_status parse_json(gm_bytes json_text, JsonValue &root) {
    if (!has_readable_data(json_text)) {
        return GM_BAD_ARGUMENT;
    }
    if (json_text.size < GM_CONTROL_FRAME_MIN_PAYLOAD_BYTES) {
        return GM_BAD_MESSAGE;
    }
    if (json_text.size > GM_CONTROL_HELLO_MAX_BYTES) {
        return GM_LIMIT_EXCEEDED;
    }
    if (json_text.size >= 3u && json_text.data[0] == 0xefu && json_text.data[1] == 0xbbu &&
        json_text.data[2] == 0xbfu) {
        return GM_BAD_MESSAGE;
    }
    if (!is_valid_utf8(json_text)) {
        return GM_BAD_MESSAGE;
    }

    JsonParser parser(json_text);
    gm_status status = parser.parse(root);
    if (status != GM_OK) {
        return status;
    }
    if (root.kind != JsonKind::object) {
        return GM_BAD_MESSAGE;
    }
    return GM_OK;
}

const JsonValue *find_member(const JsonValue &object, std::string_view name) {
    if (object.kind != JsonKind::object) {
        return nullptr;
    }
    for (const auto &member : object.object_values) {
        if (member.first == name) {
            return &member.second;
        }
    }
    return nullptr;
}

bool object_has_exact_keys(const JsonValue &object, std::initializer_list<std::string_view> keys) {
    if (object.kind != JsonKind::object || object.object_values.size() != keys.size()) {
        return false;
    }
    for (const auto &member : object.object_values) {
        bool found = false;
        for (std::string_view key : keys) {
            if (member.first == key) {
                found = true;
                break;
            }
        }
        if (!found) {
            return false;
        }
    }
    return true;
}

bool get_required_string(const JsonValue &object, std::string_view name, const std::string **out) {
    const JsonValue *value = find_member(object, name);
    if (value == nullptr || value->kind != JsonKind::string) {
        return false;
    }
    *out = &value->string_value;
    return true;
}

bool get_optional_string(const JsonValue &object, std::string_view name, const std::string **out) {
    const JsonValue *value = find_member(object, name);
    if (value == nullptr) {
        *out = nullptr;
        return true;
    }
    if (value->kind != JsonKind::string) {
        return false;
    }
    *out = &value->string_value;
    return true;
}

bool get_required_object(const JsonValue &object, std::string_view name, const JsonValue **out) {
    const JsonValue *value = find_member(object, name);
    if (value == nullptr || value->kind != JsonKind::object) {
        return false;
    }
    *out = value;
    return true;
}

bool get_required_array(const JsonValue &object, std::string_view name, const JsonValue **out) {
    const JsonValue *value = find_member(object, name);
    if (value == nullptr || value->kind != JsonKind::array) {
        return false;
    }
    *out = value;
    return true;
}

bool get_required_bool(const JsonValue &object, std::string_view name, bool *out) {
    const JsonValue *value = find_member(object, name);
    if (value == nullptr || value->kind != JsonKind::boolean) {
        return false;
    }
    *out = value->bool_value;
    return true;
}

bool get_required_u32(const JsonValue &object, std::string_view name, uint32_t min, uint32_t max, uint32_t *out) {
    const JsonValue *value = find_member(object, name);
    if (value == nullptr || value->kind != JsonKind::number || value->number_value < min ||
        value->number_value > max) {
        return false;
    }
    *out = static_cast<uint32_t>(value->number_value);
    return true;
}

bool is_ascii(const std::string &value) {
    for (unsigned char character : value) {
        if (character > 0x7fu) {
            return false;
        }
    }
    return true;
}

bool is_type_string(const std::string &value) {
    if (value.empty() || value.size() > GM_CONTROL_TYPE_MAX_BYTES) {
        return false;
    }
    for (char character : value) {
        if (!((character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') ||
              character == '.')) {
            return false;
        }
    }
    return true;
}

bool is_lower_hex_session_id(const std::string &value) {
    if (value.size() != GM_CONTROL_SESSION_ID_HEX_BYTES) {
        return false;
    }
    for (char character : value) {
        if (!((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f'))) {
            return false;
        }
    }
    return true;
}

bool is_reason_string(const std::string &value) {
    if (value.empty() || value.size() > GM_CONTROL_REASON_MAX_BYTES || !is_ascii(value)) {
        return false;
    }
    for (unsigned char character : value) {
        if (character < 0x20u || character == 0x7fu) {
            return false;
        }
    }
    return true;
}

bool parse_decimal_u64_string(const std::string &value, uint64_t *out) {
    if (value.empty() || value.size() > 20u) {
        return false;
    }
    if (value.size() > 1u && value[0] == '0') {
        return false;
    }

    uint64_t parsed = 0;
    for (char character : value) {
        if (character < '0' || character > '9') {
            return false;
        }
        const uint64_t digit = static_cast<uint64_t>(character - '0');
        if (parsed > (std::numeric_limits<uint64_t>::max() - digit) / 10u) {
            return false;
        }
        parsed = (parsed * 10u) + digit;
    }

    if (out != nullptr) {
        *out = parsed;
    }
    return true;
}

void copy_string_field(char *destination, size_t destination_size, const std::string &value) {
    std::memset(destination, 0, destination_size);
    if (destination_size == 0u) {
        return;
    }
    const size_t copy_size = value.size() < destination_size - 1u ? value.size() : destination_size - 1u;
    std::memcpy(destination, value.data(), copy_size);
}

gm_status enforce_v1_message_size(gm_bytes json_text, const JsonValue &root) {
    const JsonValue *type = find_member(root, "type");
    const bool is_hello = type != nullptr && type->kind == JsonKind::string && type->string_value == "session.hello";
    if (!is_hello && json_text.size > GM_CONTROL_MESSAGE_MAX_BYTES) {
        return GM_LIMIT_EXCEEDED;
    }
    return GM_OK;
}

gm_status parse_profile(const JsonValue &object, gm_audio_profile *out_profile) {
    if (!object_has_exact_keys(object, {"codec", "sample_rate_hz", "channels", "channel_layout", "frames_per_packet"})) {
        return GM_BAD_MESSAGE;
    }

    const std::string *codec_text = nullptr;
    const std::string *layout_text = nullptr;
    uint32_t sample_rate = 0;
    uint32_t channels = 0;
    uint32_t frames_per_packet = 0;
    if (!get_required_string(object, "codec", &codec_text) ||
        !get_required_u32(object, "sample_rate_hz", 0u, std::numeric_limits<uint32_t>::max(), &sample_rate) ||
        !get_required_u32(object, "channels", 0u, std::numeric_limits<uint16_t>::max(), &channels) ||
        !get_required_string(object, "channel_layout", &layout_text) ||
        !get_required_u32(object, "frames_per_packet", 0u, std::numeric_limits<uint16_t>::max(), &frames_per_packet)) {
        return GM_BAD_MESSAGE;
    }

    gm_audio_profile profile{};
    profile.struct_size = sizeof(gm_audio_profile);
    profile.abi_version = GM_ABI_VERSION;
    profile.sample_rate_hz = sample_rate;
    profile.channels = static_cast<uint16_t>(channels);
    profile.frames_per_packet = static_cast<uint16_t>(frames_per_packet);

    if (*codec_text == "pcm_s16le") {
        profile.codec = GM_AUDIO_CODEC_PCM_S16LE;
        profile.packet_interval_us = 5000u;
        profile.payload_bytes = GM_AUDIO_PCM_S16LE_PAYLOAD_BYTES;
    } else if (*codec_text == "opus") {
        profile.codec = GM_AUDIO_CODEC_OPUS;
        profile.packet_interval_us = 10000u;
        profile.payload_bytes = GM_AUDIO_OPUS_MAX_PAYLOAD_BYTES;
    } else {
        return GM_BAD_MESSAGE;
    }

    if (*layout_text != "stereo") {
        return GM_BAD_MESSAGE;
    }
    profile.channel_layout = GM_CHANNEL_LAYOUT_STEREO;

    gm_status status = gm_audio_profile_validate(&profile);
    if (status != GM_OK) {
        return status;
    }

    *out_profile = profile;
    return GM_OK;
}

gm_status validate_versions(const JsonValue &array, gm_control_message_info *out_info) {
    if (array.array_values.empty() || array.array_values.size() > GM_CONTROL_MAX_ARRAY_ELEMENTS) {
        return GM_BAD_MESSAGE;
    }

    uint64_t previous = 256u;
    bool saw_v1 = false;
    out_info->versions_count = static_cast<uint8_t>(array.array_values.size());
    for (size_t index = 0; index < array.array_values.size(); ++index) {
        const JsonValue &value = array.array_values[index];
        if (value.kind != JsonKind::number || value.number_value < 1u || value.number_value > 255u ||
            value.number_value >= previous) {
            return GM_BAD_MESSAGE;
        }
        previous = value.number_value;
        saw_v1 = saw_v1 || value.number_value == 1u;
        out_info->versions[index] = static_cast<uint8_t>(value.number_value);
    }

    return saw_v1 ? GM_OK : GM_UNSUPPORTED_VERSION;
}

bool is_known_error_code(const std::string &code) {
    return code == "BAD_REQUEST" || code == "UNSUPPORTED_VERSION" || code == "UNAUTHORIZED" ||
           code == "FORBIDDEN" || code == "NOT_FOUND" || code == "STATE_CONFLICT" ||
           code == "RESOURCE_BUSY" || code == "DEVICE_UNAVAILABLE" || code == "PATH_UNVALIDATED" ||
           code == "UNSUPPORTED_PROFILE" || code == "LIMIT_EXCEEDED" || code == "TIMEOUT" ||
           code == "INTERNAL";
}

bool is_endpoint_state(const std::string &state) {
    return state == "available" || state == "unavailable" || state == "faulted";
}

gm_status validate_required_decimal_string(const JsonValue &object, std::string_view name) {
    const std::string *value = nullptr;
    if (!get_required_string(object, name, &value) || !parse_decimal_u64_string(*value, nullptr)) {
        return GM_BAD_MESSAGE;
    }
    return GM_OK;
}

gm_status validate_request(const JsonValue &root, const std::string &type, gm_control_message_info *out_info) {
    if (type == "session.hello") {
        if (!object_has_exact_keys(root, {"v", "id", "type", "role", "client_name", "versions", "udp_port"})) {
            return GM_BAD_MESSAGE;
        }
        const std::string *role = nullptr;
        const std::string *client_name = nullptr;
        const JsonValue *versions = nullptr;
        if (!get_required_string(root, "role", &role) || *role != "mac-client" ||
            !get_required_string(root, "client_name", &client_name) ||
            client_name->size() > GM_CONTROL_CLIENT_NAME_MAX_BYTES ||
            !get_required_array(root, "versions", &versions) ||
            !get_required_u32(root, "udp_port", 1u, 65535u, &out_info->udp_port)) {
            return GM_BAD_MESSAGE;
        }
        gm_status status = validate_versions(*versions, out_info);
        if (status != GM_OK) {
            return status;
        }
        out_info->kind = GM_CONTROL_REQUEST_SESSION_HELLO;
        out_info->mutating = 1u;
        copy_string_field(out_info->role, sizeof(out_info->role), *role);
        copy_string_field(out_info->client_name, sizeof(out_info->client_name), *client_name);
        return GM_OK;
    }

    if (type == "transport.bind") {
        if (!object_has_exact_keys(root, {"v", "id", "type", "session_id", "udp_port"})) {
            return GM_BAD_MESSAGE;
        }
        const std::string *session_id = nullptr;
        if (!get_required_string(root, "session_id", &session_id) || !is_lower_hex_session_id(*session_id) ||
            !get_required_u32(root, "udp_port", 1u, 65535u, &out_info->udp_port)) {
            return GM_BAD_MESSAGE;
        }
        out_info->kind = GM_CONTROL_REQUEST_TRANSPORT_BIND;
        out_info->mutating = 1u;
        copy_string_field(out_info->session_id, sizeof(out_info->session_id), *session_id);
        return GM_OK;
    }

    if (type == "stream.open") {
        if (!object_has_exact_keys(root, {"v", "id", "type", "kind", "direction", "profile", "playout_target_ms"})) {
            return GM_BAD_MESSAGE;
        }
        const std::string *kind = nullptr;
        const std::string *direction = nullptr;
        const JsonValue *profile = nullptr;
        if (!get_required_string(root, "kind", &kind) || *kind != "audio" ||
            !get_required_string(root, "direction", &direction) || *direction != "win_to_mac" ||
            !get_required_object(root, "profile", &profile) ||
            !get_required_u32(root, "playout_target_ms", 15u, 120u, &out_info->playout_target_ms)) {
            return GM_BAD_MESSAGE;
        }
        gm_status status = parse_profile(*profile, &out_info->profile);
        if (status != GM_OK) {
            return status;
        }
        out_info->kind = GM_CONTROL_REQUEST_STREAM_OPEN;
        out_info->mutating = 1u;
        return GM_OK;
    }

    if (type == "stream.start" || type == "stream.stop" || type == "stream.close") {
        if (!object_has_exact_keys(root, {"v", "id", "type", "stream_id"}) ||
            !get_required_u32(root, "stream_id", 1u, std::numeric_limits<uint32_t>::max(), &out_info->stream_id)) {
            return GM_BAD_MESSAGE;
        }
        out_info->kind = type == "stream.start"   ? GM_CONTROL_REQUEST_STREAM_START
                         : type == "stream.stop"  ? GM_CONTROL_REQUEST_STREAM_STOP
                                                    : GM_CONTROL_REQUEST_STREAM_CLOSE;
        out_info->mutating = 1u;
        return GM_OK;
    }

    if (type == "stream.rekey") {
        if (!object_has_exact_keys(root, {"v", "id", "type", "stream_id", "key_epoch"}) ||
            !get_required_u32(root, "stream_id", 1u, std::numeric_limits<uint32_t>::max(), &out_info->stream_id) ||
            !get_required_u32(root, "key_epoch", 1u, std::numeric_limits<uint32_t>::max(), &out_info->key_epoch)) {
            return GM_BAD_MESSAGE;
        }
        out_info->kind = GM_CONTROL_REQUEST_STREAM_REKEY;
        out_info->mutating = 1u;
        return GM_OK;
    }

    if (type == "status.get") {
        if (!object_has_exact_keys(root, {"v", "id", "type"})) {
            return GM_BAD_MESSAGE;
        }
        out_info->kind = GM_CONTROL_REQUEST_STATUS_GET;
        out_info->mutating = 0u;
        return GM_OK;
    }

    if (type == "ping") {
        if (!object_has_exact_keys(root, {"v", "id", "type", "token"})) {
            return GM_BAD_MESSAGE;
        }
        const std::string *token = nullptr;
        if (!get_required_string(root, "token", &token) || token->empty() || token->size() > GM_CONTROL_TOKEN_MAX_BYTES ||
            !is_ascii(*token)) {
            return GM_BAD_MESSAGE;
        }
        out_info->kind = GM_CONTROL_REQUEST_PING;
        out_info->mutating = 0u;
        copy_string_field(out_info->token, sizeof(out_info->token), *token);
        return GM_OK;
    }

    if (type == "session.close") {
        const bool has_reason = find_member(root, "reason") != nullptr;
        if (!(has_reason ? object_has_exact_keys(root, {"v", "id", "type", "reason"})
                         : object_has_exact_keys(root, {"v", "id", "type"}))) {
            return GM_BAD_MESSAGE;
        }
        const std::string *reason = nullptr;
        if (!get_optional_string(root, "reason", &reason)) {
            return GM_BAD_MESSAGE;
        }
        if (reason != nullptr) {
            if (!is_reason_string(*reason)) {
                return GM_BAD_MESSAGE;
            }
            out_info->has_reason = 1u;
            copy_string_field(out_info->reason, sizeof(out_info->reason), *reason);
        }
        out_info->kind = GM_CONTROL_REQUEST_SESSION_CLOSE;
        out_info->mutating = 1u;
        return GM_OK;
    }

    return GM_BAD_MESSAGE;
}

gm_status validate_error(const JsonValue &root, gm_control_message_info *out_info) {
    if (!object_has_exact_keys(root, {"v", "id", "type", "error"})) {
        return GM_BAD_MESSAGE;
    }
    const JsonValue *error = nullptr;
    const std::string *code = nullptr;
    const std::string *message = nullptr;
    bool retryable = false;
    if (!get_required_object(root, "error", &error) ||
        !object_has_exact_keys(*error, {"code", "message", "retryable"}) ||
        !get_required_string(*error, "code", &code) || !is_known_error_code(*code) ||
        !get_required_string(*error, "message", &message) || message->size() > 256u ||
        !get_required_bool(*error, "retryable", &retryable)) {
        return GM_BAD_MESSAGE;
    }
    (void)retryable;
    out_info->kind = GM_CONTROL_RESPONSE_ERROR;
    return GM_OK;
}

gm_status validate_result(const JsonValue &root, gm_control_message_info *out_info) {
    const JsonValue *result = nullptr;
    if (!object_has_exact_keys(root, {"v", "id", "type", "result"}) ||
        !get_required_object(root, "result", &result)) {
        return GM_BAD_MESSAGE;
    }
    out_info->kind = GM_CONTROL_RESPONSE_RESULT;
    return GM_OK;
}

gm_status validate_event(const JsonValue &root, const std::string &type, gm_control_message_info *out_info) {
    if (type == "event.path.validated") {
        if (!object_has_exact_keys(root, {"v", "type", "stream_id", "key_epoch"}) ||
            !get_required_u32(root, "stream_id", 1u, std::numeric_limits<uint32_t>::max(), &out_info->stream_id) ||
            !get_required_u32(root, "key_epoch", 1u, std::numeric_limits<uint32_t>::max(), &out_info->key_epoch)) {
            return GM_BAD_MESSAGE;
        }
        out_info->kind = GM_CONTROL_EVENT_PATH_VALIDATED;
        return GM_OK;
    }

    if (type == "event.path.failed") {
        if (!object_has_exact_keys(root, {"v", "type", "stream_id", "key_epoch", "reason"}) ||
            !get_required_u32(root, "stream_id", 1u, std::numeric_limits<uint32_t>::max(), &out_info->stream_id) ||
            !get_required_u32(root, "key_epoch", 1u, std::numeric_limits<uint32_t>::max(), &out_info->key_epoch)) {
            return GM_BAD_MESSAGE;
        }
        const std::string *reason = nullptr;
        if (!get_required_string(root, "reason", &reason) || !is_reason_string(*reason)) {
            return GM_BAD_MESSAGE;
        }
        out_info->kind = GM_CONTROL_EVENT_PATH_FAILED;
        out_info->has_reason = 1u;
        copy_string_field(out_info->reason, sizeof(out_info->reason), *reason);
        return GM_OK;
    }

    if (type == "event.stream.started") {
        if (!object_has_exact_keys(root, {"v", "type", "stream_id", "first_media_timestamp"}) ||
            !get_required_u32(root, "stream_id", 1u, std::numeric_limits<uint32_t>::max(), &out_info->stream_id)) {
            return GM_BAD_MESSAGE;
        }
        gm_status status = validate_required_decimal_string(root, "first_media_timestamp");
        if (status != GM_OK) {
            return status;
        }
        out_info->kind = GM_CONTROL_EVENT_STREAM_STARTED;
        return GM_OK;
    }

    if (type == "event.stream.stopped") {
        if (!object_has_exact_keys(root, {"v", "type", "stream_id", "reason"}) ||
            !get_required_u32(root, "stream_id", 1u, std::numeric_limits<uint32_t>::max(), &out_info->stream_id)) {
            return GM_BAD_MESSAGE;
        }
        const std::string *reason = nullptr;
        if (!get_required_string(root, "reason", &reason) || !is_reason_string(*reason)) {
            return GM_BAD_MESSAGE;
        }
        out_info->kind = GM_CONTROL_EVENT_STREAM_STOPPED;
        out_info->has_reason = 1u;
        copy_string_field(out_info->reason, sizeof(out_info->reason), *reason);
        return GM_OK;
    }

    if (type == "event.stream.rekey_required") {
        if (!object_has_exact_keys(root, {"v", "type", "stream_id", "key_epoch", "deadline_monotonic_ns"}) ||
            !get_required_u32(root, "stream_id", 1u, std::numeric_limits<uint32_t>::max(), &out_info->stream_id) ||
            !get_required_u32(root, "key_epoch", 1u, std::numeric_limits<uint32_t>::max(), &out_info->key_epoch)) {
            return GM_BAD_MESSAGE;
        }
        gm_status status = validate_required_decimal_string(root, "deadline_monotonic_ns");
        if (status != GM_OK) {
            return status;
        }
        out_info->kind = GM_CONTROL_EVENT_STREAM_REKEY_REQUIRED;
        return GM_OK;
    }

    if (type == "event.stream.rekeyed") {
        uint32_t old_epoch = 0;
        if (!object_has_exact_keys(root, {"v", "type", "stream_id", "old_key_epoch", "key_epoch", "first_media_timestamp"}) ||
            !get_required_u32(root, "stream_id", 1u, std::numeric_limits<uint32_t>::max(), &out_info->stream_id) ||
            !get_required_u32(root, "old_key_epoch", 1u, std::numeric_limits<uint32_t>::max(), &old_epoch) ||
            !get_required_u32(root, "key_epoch", 1u, std::numeric_limits<uint32_t>::max(), &out_info->key_epoch)) {
            return GM_BAD_MESSAGE;
        }
        (void)old_epoch;
        gm_status status = validate_required_decimal_string(root, "first_media_timestamp");
        if (status != GM_OK) {
            return status;
        }
        out_info->kind = GM_CONTROL_EVENT_STREAM_REKEYED;
        return GM_OK;
    }

    if (type == "event.driver.state") {
        const std::string *state = nullptr;
        const std::string *reason = nullptr;
        if (!object_has_exact_keys(root, {"v", "type", "state", "reason"}) ||
            !get_required_string(root, "state", &state) || !is_endpoint_state(*state) ||
            !get_required_string(root, "reason", &reason) || !is_reason_string(*reason)) {
            return GM_BAD_MESSAGE;
        }
        out_info->kind = GM_CONTROL_EVENT_DRIVER_STATE;
        out_info->has_reason = 1u;
        copy_string_field(out_info->reason, sizeof(out_info->reason), *reason);
        return GM_OK;
    }

    if (type == "event.session.expiring") {
        const std::string *reason = nullptr;
        if (!object_has_exact_keys(root, {"v", "type", "reason", "deadline_monotonic_ns"}) ||
            !get_required_string(root, "reason", &reason) || !is_reason_string(*reason)) {
            return GM_BAD_MESSAGE;
        }
        gm_status status = validate_required_decimal_string(root, "deadline_monotonic_ns");
        if (status != GM_OK) {
            return status;
        }
        out_info->kind = GM_CONTROL_EVENT_SESSION_EXPIRING;
        out_info->has_reason = 1u;
        copy_string_field(out_info->reason, sizeof(out_info->reason), *reason);
        return GM_OK;
    }

    return GM_BAD_MESSAGE;
}

gm_status parse_message_impl(gm_bytes json_text, gm_control_message_info *out_info) {
    if (out_info == nullptr || out_info->struct_size < sizeof(gm_control_message_info)) {
        return GM_BAD_ARGUMENT;
    }

    const size_t caller_size = out_info->struct_size;
    std::memset(out_info, 0, sizeof(gm_control_message_info));
    out_info->struct_size = caller_size;
    out_info->abi_version = GM_ABI_VERSION;
    out_info->profile.struct_size = sizeof(gm_audio_profile);
    out_info->profile.abi_version = GM_ABI_VERSION;

    JsonValue root;
    gm_status status = parse_json(json_text, root);
    if (status != GM_OK) {
        return status;
    }
    status = enforce_v1_message_size(json_text, root);
    if (status != GM_OK) {
        return status;
    }

    uint32_t version = 0;
    const std::string *type = nullptr;
    if (!get_required_u32(root, "v", 1u, 255u, &version) || !get_required_string(root, "type", &type) ||
        !is_type_string(*type)) {
        return GM_BAD_MESSAGE;
    }
    if (version != GM_PROTOCOL_MAJOR) {
        return GM_UNSUPPORTED_VERSION;
    }
    copy_string_field(out_info->type, sizeof(out_info->type), *type);

    if (type->rfind("event.", 0u) == 0u) {
        return validate_event(root, *type, out_info);
    }

    if (!get_required_u32(root, "id", 1u, std::numeric_limits<uint32_t>::max(), &out_info->id)) {
        return GM_BAD_MESSAGE;
    }

    if (*type == "result") {
        return validate_result(root, out_info);
    }
    if (*type == "error") {
        return validate_error(root, out_info);
    }
    return validate_request(root, *type, out_info);
}
}

gm_status gm_control_validate_json_text(gm_bytes json_text) {
    try {
        JsonValue root;
        gm_status status = parse_json(json_text, root);
        if (status != GM_OK) {
            return status;
        }
        return enforce_v1_message_size(json_text, root);
    } catch (const std::bad_alloc &) {
        return GM_LIMIT_EXCEEDED;
    } catch (...) {
        return GM_INTERNAL;
    }
}

gm_status gm_control_parse_message(gm_bytes json_text, gm_control_message_info *out_info) {
    try {
        return parse_message_impl(json_text, out_info);
    } catch (const std::bad_alloc &) {
        return GM_LIMIT_EXCEEDED;
    } catch (...) {
        return GM_INTERNAL;
    }
}

gm_status gm_audio_profile_validate(const gm_audio_profile *profile) {
    if (profile == nullptr || profile->struct_size < sizeof(gm_audio_profile) || profile->abi_version != GM_ABI_VERSION) {
        return GM_BAD_ARGUMENT;
    }
    if (profile->sample_rate_hz != 48000u || profile->channels != 2u ||
        profile->channel_layout != GM_CHANNEL_LAYOUT_STEREO) {
        return GM_BAD_MESSAGE;
    }

    if (profile->codec == GM_AUDIO_CODEC_PCM_S16LE) {
        if (profile->frames_per_packet != 240u) {
            return GM_BAD_MESSAGE;
        }
        if ((profile->packet_interval_us != 0u && profile->packet_interval_us != 5000u) ||
            (profile->payload_bytes != 0u && profile->payload_bytes != GM_AUDIO_PCM_S16LE_PAYLOAD_BYTES)) {
            return GM_BAD_MESSAGE;
        }
        return GM_OK;
    }

    if (profile->codec == GM_AUDIO_CODEC_OPUS) {
        if (profile->frames_per_packet != 480u) {
            return GM_BAD_MESSAGE;
        }
        if ((profile->packet_interval_us != 0u && profile->packet_interval_us != 10000u) ||
            (profile->payload_bytes != 0u && profile->payload_bytes != GM_AUDIO_OPUS_MAX_PAYLOAD_BYTES)) {
            return GM_BAD_MESSAGE;
        }
        return GM_OK;
    }

    return GM_BAD_MESSAGE;
}