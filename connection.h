#include <algorithm>
#include <iterator>
#include <cstring>
#include <sys/socket.h>

#define CMD_LEN 10
#define BSIZE 256

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

    SIMPL_CMD(std::string _cmd, uint64_t _cmd_seq, std::string _data);
    SIMPL_CMD(const char *input, std::size_t length);
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
    ~CMPLX_CMD();

    void deserialize();
    void serialize();
};


void set_socket_option(int socket, int optval, int level, int optname, const std::string &error_message);
