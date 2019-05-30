#include <algorithm>
#include <iterator>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <iostream>

#define CMD_LEN 10 /** max length of a command */
#define BSIZE 65507 /** UDP max data size */
#define MIN_SIMPL_LEN (CMD_LEN + sizeof(uint64_t)) /** min length of @ref SIMPL_CMD */
#define MIN_CMPLX_LEN (CMD_LEN + 2 * sizeof(uint64_t)) /** min length of @ref CMPLX_CMD */
#define MAX_SIMPL_DATA_LEN (BSIZE - MIN_SIMPL_LEN) /** max length of data in @ref CMPLX_CMD */

/**
 * Serializes a string @ref from into a an array @ref to.
 * @param [out] to Result array.
 * @param [in] from Input string.
 * @param [in/out] i Position to start at in @ref to.
 * @param [in] n Number of characters to copy.
 */
void serialize_string(char *to, const std::string &from, std::size_t &i, std::size_t n);

/**
 * Serializes a uint64_t @ref from into a an array @ref to.
 * @param [out] to Result array.
 * @param [in] from Input uint64_t.
 * @param [in/out] i Position to start at in @ref to.
 */
void serialize_uint64(char *to, uint64_t from, std::size_t &i);

/** Deserializes a string. See @ref serialize_string. */
void deserialize_string(std::string &to, const char *from, std::size_t &i, std::size_t n);

/** Deserializes a uint64_t. See @ref serialize_uint64_t. */
void deserialize_uint64(uint64_t &to, const char *from, std::size_t &i);

struct SIMPL_CMD {
    std::string cmd;
    uint64_t cmd_seq = 0;
    std::string data;

    char *serialized; /** buffer to be sent on the network */
    ssize_t serialized_length; /** length of that buffer */

    /**
     * Creates a SIMPL_CMD from an array @ref input of size @ref length.
     * @param [in] input Character array containing the message.
     * @param [in] length Length of the message.
     */
    SIMPL_CMD(const char *input, ssize_t length);
    SIMPL_CMD(std::string _cmd, uint64_t _cmd_seq, std::string _data);
    SIMPL_CMD(SIMPL_CMD &other);
    SIMPL_CMD(SIMPL_CMD &&other) noexcept;
    ~SIMPL_CMD();

    void deserialize();
    void serialize();
};

struct CMPLX_CMD {
    std::string cmd;
    uint64_t cmd_seq = 0;
    uint64_t param = 0;
    std::string data;

    char *serialized; /** buffer to be sent on the network */
    ssize_t serialized_length; /** length of that buffer */

    /**
     * Creates a SIMPL_CMD from an array @ref input of size @ref length.
     * @param [in] input Character array containing the message.
     * @param [in] length Length of the message.
     */
    CMPLX_CMD(std::string _cmd, uint64_t _cmd_seq, uint64_t _param, std::string _data);
    CMPLX_CMD(const char *input, ssize_t length);
    CMPLX_CMD(CMPLX_CMD &other);
    CMPLX_CMD(CMPLX_CMD &&other) noexcept;
    ~CMPLX_CMD();

    void deserialize();
    void serialize();
};

void set_socket_option(int socket, int optval, int level, int optname, const std::string &error_message);
uint64_t send_simple_message(int socket, const struct sockaddr_in &address, const std::string &cmd, const std::string &data, uint64_t cmd_seq);
uint64_t send_complex_message(int socket, const struct sockaddr_in &address, const std::string &cmd, const std::string &data, uint64_t cmd_seq, uint64_t param);
void set_socket_receive_timeout(int socket, struct timeval wait_time);
/** Prints an error message about a connection with address. */
void error_message(struct sockaddr_in address, const std::string &message);

/**
 *
 * template functions, necessary to be defined in the header file
 *
 * */

template <typename T>
bool check_cmd_seq(T command, uint64_t cmd_seq, struct sockaddr_in address) {
    if (command.cmd_seq != cmd_seq) {
        /* TODO jak wypisywać porty (czy zmieniać kolejność bajtów) */
        error_message(address, "Wrong cmd_seq.");
    }
    return command.cmd_seq == cmd_seq;
}

template <typename T>
bool check_data_not_empty(T command, struct sockaddr_in address) {
    if (command.data.length() == 0) {
        error_message(address, "No data.");
    }
    return command.data.length() != 0;
}

template <typename T>
bool check_data_empty(T command, struct sockaddr_in address) {
    if (command.data.length() != 0) {
        error_message(address, "Data should be empty.");
    }
    return command.data.length() == 0;
}

template <typename T>
bool check_cmd(T command, const std::string &cmd, struct sockaddr_in address) {
    if (command.cmd.substr(0, cmd.size()) != cmd) {
        error_message(address, "Wrong cmd.");
    }
    return command.cmd.substr(0, cmd.size()) == cmd;
}

template <typename T>
bool message_too_short(struct sockaddr_in address, ssize_t len) {
    ssize_t min_len;
    if (std::is_same<T, SIMPL_CMD>::value) {
        min_len = MIN_SIMPL_LEN;
    }
    else {
        min_len = MIN_CMPLX_LEN;
    }

    if (len < min_len) {
        error_message(address, "Message too short.");
        return true;
    }
    return false;
}
