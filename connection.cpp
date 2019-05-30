#include "connection.h"

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

SIMPL_CMD::SIMPL_CMD(std::string _cmd, uint64_t _cmd_seq, std::string _data)
        : cmd(std::move(_cmd)), cmd_seq(_cmd_seq), data(std::move(_data)) {
    if (_cmd.length() > CMD_LEN) {
        throw std::invalid_argument("wrong command");
    }
    serialize();
}

SIMPL_CMD::SIMPL_CMD(const char *input, ssize_t length) {
    if (length < (ssize_t) MIN_SIMPL_LEN) {
        throw std::runtime_error("wrong message format");
    }
    serialized = new char[length];
    memcpy(serialized, input, length);
    serialized_length = length;

    deserialize();
}

SIMPL_CMD::SIMPL_CMD(SIMPL_CMD &other) {
    serialized_length = other.serialized_length;
    serialized = new char[other.serialized_length];
    memcpy(serialized, other.serialized, serialized_length);
    deserialize();
}

SIMPL_CMD::SIMPL_CMD(SIMPL_CMD &&other) noexcept {
    serialized_length = other.serialized_length;
    serialized = other.serialized;
    other.serialized = nullptr;
    deserialize();
}


SIMPL_CMD::~SIMPL_CMD() {
    delete[] serialized;
}

void SIMPL_CMD::deserialize() {
    std::size_t i = 0;

    deserialize_string(cmd, serialized, i, CMD_LEN);
    i = CMD_LEN;
    deserialize_uint64(cmd_seq, serialized, i);
    deserialize_string(data, serialized, i, serialized_length - i);
}

void SIMPL_CMD::serialize() {
    serialized_length = CMD_LEN + sizeof cmd_seq + data.length();
    serialized = new char[serialized_length];
    memset(serialized, 0, serialized_length);

    std::size_t i = 0;
    serialize_string(serialized, cmd, i, cmd.length());
    i = CMD_LEN;
    serialize_uint64(serialized, cmd_seq, i);
    serialize_string(serialized, data, i, data.length());
}

CMPLX_CMD::CMPLX_CMD(std::string _cmd, uint64_t _cmd_seq, uint64_t _param, std::string _data)
        : cmd(std::move(_cmd)), cmd_seq(_cmd_seq), param(_param), data(std::move(_data)) {
    if (_cmd.length() > CMD_LEN) {
        throw std::invalid_argument("wrong command");
    }
    serialize();
}

CMPLX_CMD::CMPLX_CMD(const char *input, ssize_t length) {
    if (length < (ssize_t) MIN_CMPLX_LEN) {
        throw std::runtime_error("wrong message format");
    }
    serialized = new char[length];
    memcpy(serialized, input, length);
    serialized_length = length;

    deserialize();
}

CMPLX_CMD::CMPLX_CMD(CMPLX_CMD &other) {
    serialized_length = other.serialized_length;
    serialized = new char[other.serialized_length];
    memcpy(serialized, other.serialized, serialized_length);
    deserialize();
}

CMPLX_CMD::CMPLX_CMD(CMPLX_CMD &&other) noexcept {
    serialized_length = other.serialized_length;
    serialized = other.serialized;
    other.serialized = nullptr;
    deserialize();
}

CMPLX_CMD::~CMPLX_CMD() {
    delete[] serialized;
}

void CMPLX_CMD::deserialize() {
    std::size_t i = 0;

    deserialize_string(cmd, serialized, i, CMD_LEN);
    i = CMD_LEN;
    deserialize_uint64(cmd_seq, serialized, i);
    deserialize_uint64(param, serialized, i);
    deserialize_string(data, serialized, i, serialized_length - i);
}

void CMPLX_CMD::serialize() {
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

void set_socket_option(int socket, int optval, int level, int optname, const std::string &error_message) {
    if (setsockopt(socket, level, optname, (void *) &optval, sizeof optval) < 0) {
        throw std::runtime_error(error_message);
    }
}

uint64_t
send_simple_message(int socket, const struct sockaddr_in &address, const std::string &cmd, const std::string &data,
                    uint64_t cmd_seq) {
    SIMPL_CMD command(cmd, cmd_seq, data);
    if (sendto(socket, command.serialized, command.serialized_length, 0,
               (struct sockaddr *) &address, sizeof address) != command.serialized_length) {
        throw std::runtime_error("write");
    }
    return cmd_seq;
}

uint64_t
send_complex_message(int socket, const struct sockaddr_in &address, const std::string &cmd, const std::string &data,
                     uint64_t cmd_seq, uint64_t param) {
    CMPLX_CMD command(cmd, cmd_seq, param, data);
    if (sendto(socket, command.serialized, command.serialized_length, 0,
               (struct sockaddr *) &address, sizeof address) != command.serialized_length) {
        throw std::runtime_error("write");
    }
    return cmd_seq;
}

void set_socket_receive_timeout(int socket, struct timeval wait_time) {
    if (setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, (void *) &wait_time,
                   sizeof wait_time) < 0) {
        throw std::runtime_error("setsockopt");
    }
}

void error_message(struct sockaddr_in address, const std::string &message) {
    std::cerr << "[PCKG ERROR] Skipping invalid package from " << inet_ntoa(address.sin_addr)
              << ":"
              << ntohs(address.sin_port) << ". " << message << "\n";
}
