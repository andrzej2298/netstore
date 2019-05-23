#include <algorithm>
#include <iterator>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>

#define CMD_LEN 10
#define BSIZE 65507
#define MIN_SIMPL_LEN (CMD_LEN + sizeof(uint64_t))
#define MAX_SIMPL_DATA_LEN (BSIZE - MIN_SIMPL_LEN)

void serialize_string(char *to, const std::string &from, std::size_t &i, std::size_t n);

void serialize_uint64(char *to, uint64_t from, std::size_t &i);

void deserialize_string(std::string &to, const char *from, std::size_t &i, std::size_t n);

void deserialize_uint64(uint64_t &to, const char *from, std::size_t &i);

struct SIMPL_CMD {
    std::string cmd;
    uint64_t cmd_seq = 0;
    std::string data;

    char *serialized;
    ssize_t serialized_length;

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

    char *serialized;
    ssize_t serialized_length;

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
uint64_t receive_complex_message(int socket, const struct sockaddr_in &address, const std::string &cmd, const std::string &data, uint64_t cmd_seq, uint64_t param);

void set_socket_receive_timeout(int socket, struct timeval wait_time);
