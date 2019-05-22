#include <iostream>
#include <vector>
#include <regex>
#include <cassert>
#include <boost/filesystem.hpp>
#include <boost/program_options.hpp>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <csignal>
#include <netdb.h>

#include "connection.h"

#define QUEUE_LENGTH 1

namespace po = boost::program_options;
namespace fs = boost::filesystem;

std::size_t MAX_SPACE_DEFAULT = 52428800;
std::size_t TIMEOUT_DEFAULT = 5;
std::size_t TIMEOUT_MAX = 300;

struct server_options;
struct server_state;
struct file_info;

using file_infos = std::vector<fs::path>;

struct server_options {
    std::string MCAST_ADDR = "";
    int CMD_PORT = 0;
    std::size_t MAX_SPACE = 0;
    std::string SHRD_FLDR = "";
    unsigned int TIMEOUT = 0;
};

struct server_state {
    uint64_t available_space = 0;
    int socket = 0;
    struct ip_mreq ip_mreq{};
    file_infos files;
};

server_state current_server_state{};
int parent_pid = getpid();

void clean_up(server_state &state) {
    kill(-getpid(), SIGINT);

    if (getpid() == parent_pid) {
        /* dropping multicast group membership (only once) */
        if (setsockopt(state.socket, IPPROTO_IP, IP_DROP_MEMBERSHIP,
                       (void *) &state.ip_mreq, sizeof state.ip_mreq) < 0) {
            throw std::runtime_error("setsockopt");
        }
    }
    close(state.socket);
}

void catch_signal(int) {
//    std::cout << "signal caught: " << getpid() << "\n";
    clean_up(current_server_state);
    exit(0);
}

void add_signal_handlers() {
    struct sigaction sigint_handler{};
    sigint_handler.sa_handler = catch_signal;
    sigemptyset(&sigint_handler.sa_mask);
    sigint_handler.sa_flags = 0;

    if (sigaction(SIGINT, &sigint_handler, nullptr) == -1) {
        throw std::runtime_error("sigaction");
    }

    struct sigaction sigchld_handler{};
    sigchld_handler.sa_handler = SIG_IGN;
    sigemptyset(&sigchld_handler.sa_mask);
    sigchld_handler.sa_flags = 0;

    if (sigaction(SIGCHLD, &sigchld_handler, nullptr)) {
        throw std::runtime_error("sigaction");
    }
}

server_options read_options(int argc, char const *argv[]) {
    po::options_description description("Allowed options");
    server_options options;

    description.add_options()
            ("help", "help message")
            ("mcast-addr,g", po::value<std::string>(&options.MCAST_ADDR))
            ("cmd-port,p", po::value<int>(&options.CMD_PORT))
            ("max-space,b", po::value<std::size_t>(&options.MAX_SPACE)->default_value(MAX_SPACE_DEFAULT))
            ("shrd-fldr,f", po::value<std::string>(&options.SHRD_FLDR))
            ("timeout,t", po::value<unsigned int>(&options.TIMEOUT)->default_value(TIMEOUT_DEFAULT));
    std::string mandatory_variables[] = {"mcast-addr", "cmd-port", "shrd-fldr"};

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

    return options;
}

void index_files(const server_options &options, server_state &state) {
    fs::path dir_path(options.SHRD_FLDR);
    state.available_space = options.MAX_SPACE;

    if (fs::exists(dir_path) && fs::is_directory(dir_path)) {
        std::vector<fs::path> files;

        for (fs::directory_iterator it(dir_path); it != fs::directory_iterator(); ++it) {
            if (fs::is_regular_file(it->path())) {
                fs::path file_path = it->path();
                std::size_t current_file_size = file_size(file_path);
                state.files.push_back(file_path);
                assert(state.available_space > current_file_size);
                state.available_space -= current_file_size;
            }
        }
    }
    else {
        throw std::invalid_argument("wrong directory");
    }
}

void initialize_connection(const server_options &options, server_state &state) {
    struct sockaddr_in local_address{};

    /* opening socket */
    state.socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (state.socket < 0) {
        throw std::runtime_error("socket");
    }

    /* joining the multicast group */
    state.ip_mreq.imr_interface.s_addr = htonl(INADDR_ANY);
    if (inet_aton(options.MCAST_ADDR.c_str(), &state.ip_mreq.imr_multiaddr) == 0) {
        throw std::runtime_error("inet_aton");
    }

    if (setsockopt(state.socket, IPPROTO_IP, IP_ADD_MEMBERSHIP,
                   (void *) &state.ip_mreq, sizeof state.ip_mreq) < 0) {
        throw std::runtime_error("setsockopt");
    }

    set_socket_option(state.socket, 1, SOL_SOCKET, SO_REUSEADDR, "reuseaddr");

    /* local address and port */
    local_address.sin_family = AF_INET;
    local_address.sin_addr.s_addr = htonl(INADDR_ANY);
    local_address.sin_port = htons(options.CMD_PORT);
    if (bind(state.socket, (struct sockaddr *) &local_address, sizeof local_address) < 0) {
        throw std::runtime_error("bind");
    }
}

bool command_equal(const SIMPL_CMD &request, const std::string &command) {
    return request.cmd.substr(0, command.length()) == command;
}

void discover(server_state &state, server_options &options, const struct sockaddr_in &client_address, SIMPL_CMD &request) {
    send_complex_message(state.socket, client_address, "GOOD_DAY", options.MCAST_ADDR, request.cmd_seq, state.available_space);
}

void remove(server_options &options, server_state &state, const std::string &target_file_name) {
    auto it = state.files.begin();

    for (; (it != state.files.end()) && (it->filename().string() != target_file_name); ++it) {}
    if (it != state.files.end()) {
        std::cout << it->filename().string() << "\n";
        state.available_space += it->size();
        fs::remove(*it);
        state.files.erase(it);
    }
}

void list(server_options &options, server_state &state, const struct sockaddr_in &client_address, SIMPL_CMD &request) {
    std::string &target_file_name = request.data;
    std::vector<std::string> results;
    for (const fs::path &file : state.files) {
        const std::string &file_name = file.filename().string();
        if (file_name.find(target_file_name) != std::string::npos) {
            results.push_back(file_name);
        }
    }

    std::string data;
    if (!results.empty()) {
        data = results[0];
        for (const std::string &file_name : results) {
            data += "\n" + file_name;
        }
    }

    /* TODO many messages if list too big */
    send_simple_message(state.socket, client_address, "MY_LIST", data, request.cmd_seq);
}

void initialize_file_transfer(server_options &options, server_state &state, const struct sockaddr_in &client_udp, SIMPL_CMD &request) {
    struct addrinfo addr_hints;
    struct addrinfo *addr_result;
    int sock, msg_sock;
    struct sockaddr_in server_tcp;
    struct sockaddr_in client_tcp;
    socklen_t client_tcp_len = sizeof client_tcp;
    socklen_t server_tcp_len = sizeof server_tcp;

    ssize_t len, snd_len;

    /* IPv4 TCP socket */
    sock = socket(PF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        throw std::runtime_error("socket");
    }

    server_tcp.sin_family = AF_INET;
    server_tcp.sin_addr.s_addr = htonl(INADDR_ANY);
    /* ephemeral port */
    server_tcp.sin_port = htons(0);

    if (bind(sock, (struct sockaddr *) &server_tcp, server_tcp_len) < 0) {
        throw std::runtime_error("bind");
    }
    if (listen(sock, QUEUE_LENGTH) < 0) {
        throw std::runtime_error("listen");
    }
    if (getsockname(sock, (struct sockaddr *)&server_tcp, &server_tcp_len) < 0){
        throw std::runtime_error("getsockname");
    }

    std::cout << "port: " << server_tcp.sin_port << "\n";

    std::cout << "accepting\n";

    struct timeval wait_time{options.TIMEOUT, 0};
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(sock, &fds);
    char buffer[BSIZE];

    send_complex_message(state.socket, client_udp, "CONNECT_ME", request.data, request.cmd_seq, server_tcp.sin_port);

    if (select(sock + 1, &fds, nullptr, nullptr, &wait_time)) {
        client_tcp_len = sizeof(client_tcp);
        msg_sock = accept(sock, (struct sockaddr *) &client_tcp, &client_tcp_len);
        if (msg_sock < 0) {
            throw std::runtime_error("accept");
        }
        snd_len = write(msg_sock, "ABC", 3);
        if (snd_len != 3) {
            throw std::runtime_error("writing to client socket");
        }
        printf("ending connection\n");
        if (close(msg_sock) < 0)
            throw std::runtime_error("close");
    }
    else {
        std::cout << "not connected\n";
    }
    std::cout << "after accepting\n";


    close(state.socket);
    close(msg_sock);
    std::cout << "child ending\n";
    exit(0);
}

void fetch(server_options &options, server_state &state, const struct sockaddr_in &client_address, SIMPL_CMD &request) {
    for (auto &file : state.files) {
        if (file.filename().string() == request.data) {
            switch (fork())  {
                case -1:
                    throw std::runtime_error("fork");
                case 0:
                    initialize_file_transfer(options, state, client_address, request);
                    break;
                default:
                    std::cout << "parent\n";
                    break;
            }
            return;
        }
    }
}

void read_requests(server_options &options, server_state &state) {
    /* data received */
    char buffer[BSIZE];
    ssize_t rcv_len;
    struct sockaddr_in client_address{};
    socklen_t addrlen = sizeof client_address;

    for (;;) {
        /* read */
        rcv_len = recvfrom(state.socket, buffer, sizeof buffer, 0, (struct sockaddr *) &client_address, &addrlen);
        if (rcv_len < 0) {
            throw std::runtime_error("read");
        }
        else {
            if (rcv_len < MIN_CMD_LEN) {
                /* TODO odnotować */
                continue;
            }

            SIMPL_CMD request(buffer, rcv_len);
            std::cout << request.cmd << " " << request.cmd_seq << "\n";
            std::cout << "port: " << htons(client_address.sin_port) << "\n";
            std::cout << "addr: " << inet_ntoa(client_address.sin_addr) << "\n";
//            std::string cmd(buffer);

            if (command_equal(request, "HELLO")) {
                discover(state, options, client_address, request);
            }
            else if (command_equal(request, "DEL")) {
                remove(options, state, request.data);
            }
            else if (command_equal(request, "LIST")) {
                list(options, state, client_address, request);
            }
            else if (command_equal(request, "GET")) {
                fetch(options, state, client_address, request);
            }
            else {
                /* TODO tak naprawdę to chyba drop packet */
                assert(false);
            }
        }
    }
}


int main(int argc, char const *argv[]) {
    try {
        add_signal_handlers();
        server_options options = read_options(argc, argv);
        index_files(options, current_server_state);
        initialize_connection(options, current_server_state);
        read_requests(options, current_server_state);
        clean_up(current_server_state);
    } catch (const std::exception &e) {
        std::cerr << "error: " << e.what() << "\n" << strerror(errno) << "\n";
    }
}