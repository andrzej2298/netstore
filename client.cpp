#include <iostream>
#include <algorithm>
#include <chrono>
#include <vector>

#include <boost/config.hpp>
#include <boost/filesystem.hpp>
#include <boost/program_options.hpp>
#include <boost/tokenizer.hpp>
#include <boost/regex.hpp>

#include <csignal>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>

#include "connection.h"

namespace po = boost::program_options;
namespace fs = boost::filesystem;
namespace chr = std::chrono;

std::size_t TIMEOUT_DEFAULT = 5;
std::size_t TIMEOUT_MAX = 300;
int TTL_VALUE = 4;
int ENABLE_BROADCAST = 1;

struct server_info;

using server_infos = std::vector<server_info>;

struct client_options {
    std::string MCAST_ADDR = "";
    int CMD_PORT = 0;
    std::string OUT_FLDR = "";
    unsigned int TIMEOUT = 0;
};

struct server_info {
    uint64_t available_space = 0;
    struct sockaddr_in address{};
};

template<typename T>
struct message {
    struct sockaddr_in address;
    T command;
};

struct client_state {
    int socket{};
    struct sockaddr_in remote_address{};
    std::vector<message<SIMPL_CMD>> previous_search;
    server_infos previous_servers;
    std::set<std::string> open_files;
};

client_state current_client_state{};

void clean_up(client_state &state) {
    close(state.socket);
    for (const std::string &file : state.open_files) {
        unlink(file.c_str());
    }
}

uint64_t get_cmd_seq() {
    static uint64_t cmd_seq = 0;
    return cmd_seq++;
}

client_options read_options(int argc, char const *argv[]) {
    po::options_description description("Allowed options");
    client_options options;

    description.add_options()
            ("help", "help message")
            ("mcast-addr,g", po::value<std::string>(&options.MCAST_ADDR))
            ("cmd-port,p", po::value<int>(&options.CMD_PORT))
            ("out-fldr,o", po::value<std::string>(&options.OUT_FLDR))
            ("timeout,t", po::value<unsigned int>(&options.TIMEOUT)->default_value(TIMEOUT_DEFAULT));
    std::string mandatory_variables[] = {"mcast-addr", "cmd-port", "out-fldr"};

    po::variables_map variables;
    po::store(po::parse_command_line(argc, argv, description), variables);
    po::notify(variables);

    for (const std::string &variable: mandatory_variables) {
        if (!variables.count(variable)) {
            throw std::invalid_argument(variable);
        }
    }
    if (options.TIMEOUT > TIMEOUT_MAX || options.TIMEOUT == 0) {
        throw std::invalid_argument("timeout");
    }
    if (options.CMD_PORT < 0) {
        throw std::invalid_argument("port");
    }

    return options;
}

boost::tokenizer<boost::char_separator<char>> tokenize(const message<SIMPL_CMD> &message) {
    /* splitting the file list on '\n' */
    boost::char_separator<char> newline("\n");
    boost::tokenizer<boost::char_separator<char>> t(message.command.data, newline);
    return t;
}

void add_remote_address(const client_options &options, client_state &state) {
    /* multicast address */
    state.remote_address.sin_family = AF_INET;
    state.remote_address.sin_port = htons(options.CMD_PORT);
    if (inet_aton(options.MCAST_ADDR.c_str(), &state.remote_address.sin_addr) == 0) {
        throw std::runtime_error("inet aton");
    }
}

void initialize_socket(int &sock) {
    /* socket info */
    struct sockaddr_in local_address{};

    /* opening the socket */
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        throw std::runtime_error("socket");
    }

    /* host address */
    local_address.sin_family = AF_INET;
    local_address.sin_addr.s_addr = htonl(INADDR_ANY);
    local_address.sin_port = htons(0);
    if (bind(sock, (struct sockaddr *) &local_address, sizeof local_address) < 0) {
        throw std::runtime_error("bind");
    }

    /* enabling broadcast */
    set_socket_option(sock, ENABLE_BROADCAST, SOL_SOCKET, SO_BROADCAST, "setsockopt broadcast");

    /* setting TTL */
    set_socket_option(sock, TTL_VALUE, IPPROTO_IP, IP_MULTICAST_TTL, "setsockopt multicast ttl");
}

void initialize_connection(const client_options &options, client_state &state) {
    initialize_socket(state.socket);
    add_remote_address(options, state);
}

uint64_t send_simple_client_message(int socket, client_state &state, const std::string &cmd, const std::string &data) {
    return send_simple_message(socket, state.remote_address, cmd, data, get_cmd_seq());
}

void receive_message(int sock, char *buffer, struct sockaddr_in &server_address, ssize_t &rcv_len, socklen_t &addr_len) {
    rcv_len = recvfrom(sock, buffer, BSIZE, 0, (struct sockaddr *) &server_address, &addr_len);
    if (rcv_len < 0) {
        if (rcv_len != -1 ||
            (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINPROGRESS)) {
            /* not caused by timeout */
            throw std::runtime_error("read");
        }
    }
}

template<typename T>
void receive_timeouted_message(int socket, const chr::system_clock::time_point &end_point,
                               const chr::system_clock::time_point &current_time, struct timeval &wait_time,
                               char *buffer,
                               std::vector<message<T>> &server_messages) {
    struct sockaddr_in server_address{};
    socklen_t addr_len = sizeof server_address;
    ssize_t rcv_len;
    chr::nanoseconds remaining_time = end_point - current_time;
    chr::seconds sec = chr::duration_cast<chr::seconds>(remaining_time);
    wait_time.tv_sec = sec.count();
    wait_time.tv_usec = chr::duration_cast<chr::microseconds>(remaining_time - sec).count();

    set_socket_receive_timeout(socket, wait_time);
    receive_message(socket, buffer, server_address, rcv_len, addr_len);

    if (rcv_len != -1 && !message_too_short<T>(server_address, rcv_len)) {
        server_messages.push_back({server_address, {buffer, rcv_len}});
    }
}

template<typename T>
void
receive_timeouted_messages(int socket, client_options &options, std::vector<message<T>> &server_messages,
                           std::size_t limit) {
    char buffer[BSIZE];

    chr::system_clock::time_point start_point = chr::system_clock::now();
    std::chrono::seconds timeout(options.TIMEOUT);
    chr::system_clock::time_point end_point = start_point + timeout;
    struct timeval wait_time{};
    for (;;) {
        chr::system_clock::time_point current_time = chr::system_clock::now();
        if (end_point < current_time || server_messages.size() >= limit) {
            break;
        }
        else {
            receive_timeouted_message(socket, end_point, current_time, wait_time, buffer, server_messages);
        }
    }

    /* revert socket timeout */
    wait_time.tv_sec = 0;
    wait_time.tv_usec = 0;
    set_socket_receive_timeout(socket, wait_time);
}

void hello(int socket, client_state &state, client_options &options, bool print) {
    uint64_t cmd_seq = send_simple_client_message(socket, state, "HELLO", "");
    std::vector<message<CMPLX_CMD>> server_messages;
    receive_timeouted_messages(socket, options, server_messages, SIZE_MAX);
    state.previous_servers.clear();

    for (auto &info : server_messages) {
        if (check_data_not_empty(info.command, info.address) &&
            check_cmd(info.command, "GOOD_DAY", info.address) &&
            check_cmd_seq(info.command, cmd_seq, info.address)) {
            state.previous_servers.push_back({info.command.param, info.address});
            if (print) {
                std::cout << "Found " << inet_ntoa(info.address.sin_addr) << " (" << info.command.data << ") ";
                std::cout << "with free space " << info.command.param << "\n";
            }
        }
    }
}

void discover(client_state &state, client_options &options) {
    hello(state.socket, state, options, true);
}

void search(client_state &state, client_options &options, const std::string &argument) {
    uint64_t cmd_seq = send_simple_client_message(state.socket, state, "LIST", argument);
    std::vector<message<SIMPL_CMD>> server_messages;
    receive_timeouted_messages(state.socket, options, server_messages, SIZE_MAX);

    for (auto &info : server_messages) {
        if (check_data_not_empty(info.command, info.address) &&
            check_cmd(info.command, "MY_LIST", info.address) &&
            check_cmd_seq(info.command, cmd_seq, info.address)) {
            std::string address(inet_ntoa(info.address.sin_addr));
            auto t = tokenize(info);
            for (auto it = t.begin(); it != t.end(); ++it) {
                std::cout << *it << " (" << address << ")" << "\n";
            }
        }
    }

    if (!state.previous_search.empty()) {
        state.previous_search.clear();
    }
    for (message<SIMPL_CMD> &msg : server_messages) {
        state.previous_search.emplace_back(message<SIMPL_CMD>(msg));
    }
}

void create_tcp_socket(int &sock, struct sockaddr_in &server_tcp) {
    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0) {
        throw std::runtime_error("socket");
    }

    if (connect(sock, (struct sockaddr *) &server_tcp, sizeof server_tcp) < 0) {
        throw std::runtime_error("connect");
    }
}

void receive_file(client_state &state, client_options &options, const message<SIMPL_CMD> &info,
                  const std::string &argument) {
    int sock;
    initialize_socket(sock);
    char buffer[BSIZE];
    uint64_t cmd_seq = send_simple_message(sock, info.address, "GET", argument, get_cmd_seq());
    set_socket_receive_timeout(sock, {options.TIMEOUT, 0});

    ssize_t rcv_len;
    socklen_t addr_len = sizeof info.address;
    rcv_len = recvfrom(sock, buffer, BSIZE, 0, (struct sockaddr *) &info.address, &addr_len);
    if (rcv_len < 0) {
        if (rcv_len != -1 ||
            (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINPROGRESS)) {
            /* not caused by timeout */
            throw std::runtime_error("read");
        }
        else {
            std::cout << "File " <<  argument << " downloading failed (:) server didn't answer\n";
        }
    }

    CMPLX_CMD message(buffer, rcv_len);
    if (!check_data_not_empty(message, info.address) ||
        !check_cmd(message, "CONNECT_ME", info.address) ||
        !check_cmd_seq(message, cmd_seq, info.address)) {
        exit(0);
    }

    int tcp_socket;
    struct sockaddr_in server_address{info.address};
    server_address.sin_port = htons(message.param);
    std::string server_address_string(inet_ntoa(info.address.sin_addr));

    create_tcp_socket(tcp_socket, server_address);

    rcv_len = 1;
    std::string filename(options.OUT_FLDR + "/" + argument);
    int fd = open(filename.c_str(), O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    state.open_files.insert(filename);
    while (rcv_len > 0) {
        rcv_len = read(tcp_socket, buffer, BSIZE);
        if (write(fd, buffer, rcv_len) < 0) {
            throw std::runtime_error("write");
        }
    }
    if (rcv_len < 0) {
        throw std::runtime_error("read");
    }
    state.open_files.erase(filename);
    std::cout << "File " << argument << " downloaded (" << server_address_string << ":"
              << ntohs(server_address.sin_port) << ")\n";
    close(tcp_socket);
    exit(0);
}

void fetch(client_state &state, client_options &options, const std::string &argument) {
    for (auto &info : state.previous_search) {
        auto t = tokenize(info);
        for (auto it = t.begin(); it != t.end(); ++it) {
            if (*it == argument) {
                switch (fork()) {
                    case -1:
                        throw std::runtime_error("fork");
                    case 0:
                        receive_file(state, options, info, argument);
                        return;
                    default:
                        break;
                }
                return;
            }
        }
    }

    std::cout << "File " << argument << " wasn't found\n";
}

void file_transfer(const message<CMPLX_CMD> &message, const server_info &server, const std::string &argument,
                   fs::path &uploaded_file) {
    bool success = true;
    int tcp_socket;
    struct sockaddr_in server_address{server.address};
    server_address.sin_port = htons(message.command.param);
    char buffer[BSIZE];
    ssize_t read_len, write_len;

    create_tcp_socket(tcp_socket, server_address);

    std::string server_address_string(inet_ntoa(server_address.sin_addr));
    read_len = 1;
    const std::string &filename = uploaded_file.string();
    int fd = open(filename.c_str(), O_RDONLY);
    while (success && read_len > 0) {
        read_len = read(fd, buffer, BSIZE);
        if (read_len > 0) {
            if ((write_len = write(tcp_socket, buffer, read_len)) < 0 || write_len != read_len) {
                success = false;
            }
        }
    }
    if (read_len < 0) {
        throw std::runtime_error("read");
    }

    if (!success) {
        std::cout << "File " << argument << " uploading failed (" << server_address_string << ":"
                  << ntohs(server_address.sin_port)
                  << ") tcp connection error\n";
    }
    else {
        std::cout << "File " << filename << " uploaded (" << server_address_string << ":"
                  << ntohs(server_address.sin_port) << ")\n";
    }
    exit(0);
}

void send_file(client_options &options, client_state &state, const std::string &argument, fs::path &uploaded_file) {
    int sock;
    initialize_socket(sock);
    hello(sock, state, options, false);
    if (state.previous_servers.empty()) {
        std::cout << "File " << argument << " uploading failed (:) no server available\n";
        return;
    }

    std::sort(state.previous_servers.begin(), state.previous_servers.end(),
              [](const server_info &lhs, const server_info &rhs) -> bool {
                  return lhs.available_space > rhs.available_space;
              });

    for (const auto &server : state.previous_servers) {
        char buffer[BSIZE];
        ssize_t rcv_len;
        struct sockaddr_in server_address{};
        socklen_t addr_len;
        uint64_t cmd_seq = send_complex_message(sock, server.address, "ADD", uploaded_file.filename().string(),
                                                get_cmd_seq(),
                                                file_size(uploaded_file));
        struct timeval wait_time{options.TIMEOUT, 0};
        set_socket_receive_timeout(sock, wait_time);
        receive_message(sock, buffer, server_address, rcv_len, addr_len);
        if (rcv_len > 0 && buffer[0] == 'C') {
            if (message_too_short<CMPLX_CMD>(server_address, rcv_len)) {
                continue;
            }
            else {
                CMPLX_CMD message(buffer, rcv_len);
                if (check_cmd(message, "CAN_ADD", server_address) &&
                    check_cmd_seq(message, cmd_seq, server_address) &&
                    check_data_empty(message, server_address)) {
                    file_transfer({server_address, message}, server, argument, uploaded_file);
                }
            }
        }
        else if (rcv_len > 0 && buffer[0] == 'N') {
            if (message_too_short<SIMPL_CMD>(server_address, rcv_len)) {
                continue;
            }
            else {
                SIMPL_CMD message(buffer, rcv_len);
                check_cmd(message, "NO_WAY", server_address) &&
                check_cmd_seq(message, cmd_seq, server_address) &&
                check_data_equal(message, server_address, uploaded_file.filename().string());
            }
        }
        else {
            error_message(server_address, "Invalid cmd.");
        }
    }
    std::cout << "File " << argument << " too big\n";
    exit(0);
}

void upload(client_state &state, client_options &options, const std::string &argument) {
    fs::path uploaded_file(argument);
    if (!fs::exists(uploaded_file)) {
        std::cout << "File " << argument << " does not exist\n";
        return;
    }

    switch (fork()) {
        case -1:
            throw std::runtime_error("fork");
        case 0:
            send_file(options, state, argument, uploaded_file);
            return;
        default:
            break;
    }
}

void remove(client_state &state, const std::string &argument) {
    send_simple_client_message(state.socket, state, "DEL", argument);
}

void handle_client_command(const boost::smatch &match, client_state &state, client_options &options) {
    std::string command, argument;
    if (match.size() == 1) {
        command = match[0];
        std::transform(command.begin(), command.end(), command.begin(), ::tolower);
        if (command == "discover") {
            discover(state, options);
        }
        else if (command == "exit") {
            clean_up(state);
        }
        else {
            assert(false);
        }
    }
    else {
        command = match[1];
        argument = match[2];
        std::transform(command.begin(), command.end(), command.begin(), ::tolower);
        if (command == "search") {
            search(state, options, argument);
        }
        else if (command == "remove") {
            remove(state, argument);
        }
        else if (command == "fetch") {
            fetch(state, options, argument);
        }
        else if (command == "upload") {
            upload(state, options, argument);
        }
        else {
            assert(false);
        }
    }
}

void client_loop(client_state &state, client_options &options) {
    static const boost::regex discover_r("discover",
                                         boost::regex_constants::ECMAScript | boost::regex_constants::icase);
    static const boost::regex search_r("(search) ?(.*)",
                                       boost::regex_constants::ECMAScript | boost::regex_constants::icase);
    static const boost::regex fetch_r("(fetch) (.+)",
                                      boost::regex_constants::ECMAScript | boost::regex_constants::icase);
    static const boost::regex upload_r("(upload) (.+)",
                                       boost::regex_constants::ECMAScript | boost::regex_constants::icase);
    static const boost::regex remove_r("(remove) (.+)",
                                       boost::regex_constants::ECMAScript | boost::regex_constants::icase);
    static const boost::regex exit_r("exit", boost::regex_constants::ECMAScript | boost::regex_constants::icase);
    static const boost::regex expressions[] = {discover_r, search_r, fetch_r,
                                               upload_r, remove_r, exit_r};

    for (;;) {
        std::string line;
        std::getline(std::cin, line);
        boost::smatch match;

        for (const boost::regex &r : expressions) {
            if (boost::regex_match(line, match, r)) {
                handle_client_command(match, state, options);
                break;
            }
        }
    }
}

void catch_sigint(int) {
    clean_up(current_client_state);
    exit(-1);
}

void add_signal_handlers() {
    struct sigaction signal_handler{};
    signal_handler.sa_handler = catch_sigint;
    sigemptyset(&signal_handler.sa_mask);
    signal_handler.sa_flags = 0;

    sigaction(SIGINT, &signal_handler, nullptr);

    struct sigaction sigchld_handler{};
    sigchld_handler.sa_handler = SIG_IGN;
    sigemptyset(&sigchld_handler.sa_mask);
    sigchld_handler.sa_flags = 0;

    if (sigaction(SIGCHLD, &sigchld_handler, nullptr)) {
        throw std::runtime_error("sigaction");
    }
}

int main(int argc, char const *argv[]) {
    try {
        add_signal_handlers();
        client_options options = read_options(argc, argv);
        initialize_connection(options, current_client_state);
        client_loop(current_client_state, options);
        clean_up(current_client_state);
    }
    catch (const std::exception &e) {
        std::cerr << "error: " << e.what();
        if (errno != 0) {
            std::cerr << " " << strerror(errno);
        }
        std::cerr << "\n";
    }
}

