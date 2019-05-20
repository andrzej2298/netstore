#include <algorithm>
#include <iterator>

std::size_t CMD_LEN = 10;
std::size_t BSIZE = 256;

void serialize_string(char *to, const std::string &from, std::size_t &i, std::size_t n) {
    for (std::size_t j = 0; j < n; ++i, ++j) {
        to[i] = from[j];
    }
}

void serialize_uint64(char *to, uint64_t from, std::size_t &i) {
    uint64_t from_be = htobe64(from);
    char *from_ptr = (char *) &from_be;
    for (std::size_t j = 0; j < sizeof from; ++i, ++j) {
        to[i] = from_ptr[j];
    }
}

void deserialize_string(std::string &to, const char *from, std::size_t &i, std::size_t n) {
    for (std::size_t j = 0; j < n; ++i, ++j) {
        to.push_back(from[i]);
    }
}

void deserialize_uint64(uint64_t &to, const char *from, std::size_t &i) {
    uint64_t to_be;
    char *to_be_ptr = (char *) &to_be;
    for (std::size_t j = 0; j < sizeof to; ++i, ++j) {
        to_be_ptr[j] = from[i];
    }
    to = be64toh(to_be);
}

struct SIMPL_CMD {
    std::string cmd;
    uint64_t cmd_seq = 0;
    std::string data;

    char *serialized;
    ssize_t serialized_length;

    SIMPL_CMD(std::string _cmd, uint64_t _cmd_seq, std::string _data)
            : cmd(std::move(_cmd)), cmd_seq(_cmd_seq), data(std::move(_data)) {
        if (_cmd.length() > CMD_LEN) {
            throw std::invalid_argument("wrong command");
        }
        serialize();
    }

    SIMPL_CMD(const char *input, std::size_t length) {
        serialized = new char[length];
        memcpy(serialized, input, length);
        serialized_length = length;

        deserialize();
    }

    ~SIMPL_CMD() {
        delete[] serialized;
    }

    void deserialize() {
        std::size_t i = 0;

        deserialize_string(cmd, serialized, i, CMD_LEN);
        i = CMD_LEN;
        deserialize_uint64(cmd_seq, serialized, i);
        /* czy na pewno? */
        deserialize_string(data, serialized, i, serialized_length - i);
    }

    void serialize() {
        serialized_length = CMD_LEN + sizeof cmd_seq + data.length();
        serialized = new char[serialized_length];
        memset(serialized, 0, serialized_length);

        std::size_t i = 0;
        serialize_string(serialized, cmd, i, cmd.length());
        i = CMD_LEN;
        serialize_uint64(serialized, cmd_seq, i);
        serialize_string(serialized, data, i, data.length());
    }
};

struct CMPLX_CMD {
    std::string cmd;
    uint64_t cmd_seq = 0;
    uint64_t param = 0;
    std::string data;

    char *serialized;
    ssize_t serialized_length;

    CMPLX_CMD(std::string _cmd, uint64_t _cmd_seq, uint64_t _param, std::string _data)
    : cmd(std::move(_cmd)), cmd_seq(_cmd_seq), param(_param), data(std::move(_data)) {
        if (_cmd.length() > CMD_LEN) {
            throw std::invalid_argument("wrong command");
        }
        serialize();
    }

    CMPLX_CMD(const char *input, ssize_t length) {
        serialized = new char[length];
        memcpy(serialized, input, length);
        serialized_length = length;

        deserialize();
    }

    ~CMPLX_CMD() {
        delete[] serialized;
    }

    void deserialize() {
        std::size_t i = 0;

        deserialize_string(cmd, serialized, i, CMD_LEN);
        i = CMD_LEN;
        deserialize_uint64(cmd_seq, serialized, i);
        deserialize_uint64(param, serialized, i);
        deserialize_string(data, serialized, i, serialized_length - i);
    }

    void serialize() {
        serialized_length = CMD_LEN + sizeof cmd_seq + sizeof param + data.length();
        serialized = new char[serialized_length];
        memset(serialized, 0, serialized_length);

        std::size_t i = 0;
        serialize_string(serialized, cmd, i, cmd.length());
        i = CMD_LEN;
        serialize_uint64(serialized, cmd_seq, i);
        serialize_uint64(serialized, param, i);
        serialize_string(serialized, data, i, data.length());
    }
};


void set_socket_option(int socket, int optval, int level, int optname, const std::string &error_message) {
    if (setsockopt(socket, level, optname, (void *) &optval, sizeof optval) < 0) {
        throw std::runtime_error(error_message);
    }
}
