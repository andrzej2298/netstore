#include <iostream>
#include <list>
#include <regex>
#include <cassert>
#include <algorithm>

#include <boost/filesystem.hpp>
#include <boost/program_options.hpp>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <csignal>
#include <netdb.h>
#include <fcntl.h>

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

void catch_sigint(int) {
//    std::cout << "signal caught: " << getpid() << "\n";
    clean_up(current_server_state);
    exit(0);
}

void catch_sigusr(int, siginfo_t *info, void *) {
    std::cout << "caught sigusr from " << info->si_pid << "\n";
}

void add_signal_handlers() {
    struct sigaction sigint_handler{};
    sigint_handler.sa_handler = catch_sigint;
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

void
discover(server_state &state, server_options &options, const struct sockaddr_in &client_address, SIMPL_CMD &request) {
    send_complex_message(state.socket, client_address, "GOOD_DAY", options.MCAST_ADDR, request.cmd_seq,
                         state.available_space);
}

void remove(server_state &state, const std::string &target_file_name) {
    auto it = state.files.begin();

    for (; (it != state.files.end()) && (it->filename().string() != target_file_name); ++it) {}
    if (it != state.files.end()) {
        std::cout << it->filename().string() << "\n";
        state.available_space += file_size(*it);
        fs::remove(*it);
        state.files.erase(it);
    }
}

void list(server_state &state, const struct sockaddr_in &client_address, SIMPL_CMD &request) {
    std::string &target_file_name = request.data;
    std::list<std::string> results;
    for (const fs::path &file : state.files) {
        std::string file_name = file.filename().string();
//        std::cout << file_name << "\n";
        if (file_name.find(target_file_name) != std::string::npos) {
            results.push_back(file_name);
        }
    }

    std::string data;

    while (!results.empty()) {
        if (!results.empty()) {
            std::string current = results.front();
            data = current;
            results.pop_front();
            while (!results.empty() && data.size() + current.size() + 1 < MAX_SIMPL_DATA_LEN) {
                current = results.front();
                results.pop_front();
                data += "\n" + current;
            }
        }
        std::cout << data.length();
        send_simple_message(state.socket, client_address, "MY_LIST", data, request.cmd_seq);
        data.clear();
    }
}

void
create_tcp_socket(int &sock, struct sockaddr_in &server_tcp,
                  socklen_t &server_tcp_len) {
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
    if (getsockname(sock, (struct sockaddr *) &server_tcp, &server_tcp_len) < 0) {
        throw std::runtime_error("getsockname");
    }

    std::cout << "port: " << ntohs(server_tcp.sin_port) << "\n";
    std::cout << "accepting\n";
}

void send_file(server_options &options, server_state &state, const struct sockaddr_in &client_udp,
               SIMPL_CMD &request, const fs::path &path) {
    int sock, msg_sock;
    struct sockaddr_in server_tcp{};
    struct sockaddr_in client_tcp{};
    socklen_t client_tcp_len = sizeof client_tcp;
    socklen_t server_tcp_len = sizeof server_tcp;
    ssize_t snd_len;

    create_tcp_socket(sock, server_tcp, server_tcp_len);
    struct timeval wait_time{options.TIMEOUT, 0};
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(sock, &fds);
    char buffer[BSIZE];

    send_complex_message(state.socket, client_udp, "CONNECT_ME", request.data, request.cmd_seq,
                         server_tcp.sin_port);

    if (select(sock + 1, &fds, nullptr, nullptr, &wait_time)) {
        client_tcp_len = sizeof(client_tcp);
        msg_sock = accept(sock, (struct sockaddr *) &client_tcp, &client_tcp_len);
        if (msg_sock < 0) {
            throw std::runtime_error("accept");
        }

        int fd, readlen;
        if ((fd = open(path.string().c_str(), O_RDONLY)) < 0) {
            throw std::runtime_error("open");
        }
        while ((readlen = read(fd, buffer, BSIZE)) > 0) {
            snd_len = write(msg_sock, buffer, readlen);
            if (snd_len != readlen) {
                throw std::runtime_error("writing to client socket");
            }
        }
        if (readlen < 0) {
            throw std::runtime_error("read");
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
    close(sock);
    std::cout << "child ending\n";
    exit(0);
}

void
fetch(server_options &options, server_state &state, const struct sockaddr_in &client_address, SIMPL_CMD &request) {
    for (const fs::path &file : state.files) {
        if (file.filename().string() == request.data) {
            switch (fork()) {
                case -1:
                    throw std::runtime_error("fork");
                case 0:
                    send_file(options, state, client_address, request, file);
                    break;
                default:
                    std::cout << "parent fetch\n";
                    break;
            }
            return;
        }
    }
    std::cerr << "[PCKG ERROR] Skipping invalid package from " << inet_ntoa(client_address.sin_addr) << ":"
              << client_address.sin_port << ". Invalid file name.\n";
}


void receive_file(server_options &options, server_state &state, const struct sockaddr_in &client_udp,
                  CMPLX_CMD &request) {
        int sock, msg_sock;
    struct sockaddr_in server_tcp{};
    struct sockaddr_in client_tcp{};
    socklen_t client_tcp_len = sizeof client_tcp;
    socklen_t server_tcp_len = sizeof server_tcp;
    ssize_t write_len;
    ssize_t remaining_file_size = request.param;

    create_tcp_socket(sock, server_tcp, server_tcp_len);
    struct timeval wait_time{options.TIMEOUT, 0};
    fd_set fds;
    bool error_occurred = false;
    FD_ZERO(&fds);
    FD_SET(sock, &fds);
    char buffer[BSIZE];
    std::string filename = options.SHRD_FLDR + "/" + request.data;

    send_complex_message(state.socket, client_udp, "CAN_ADD", request.data, request.cmd_seq,
                         server_tcp.sin_port);

    if (select(sock + 1, &fds, nullptr, nullptr, &wait_time)) {
        client_tcp_len = sizeof(client_tcp);
        msg_sock = accept(sock, (struct sockaddr *) &client_tcp, &client_tcp_len);
        if (msg_sock < 0) {
            throw std::runtime_error("accept");
        }

        int fd;
        ssize_t read_len;
        if ((fd = open(filename.c_str(), O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)) < 0) {
            throw std::runtime_error("open");
        }
        while (remaining_file_size > 0 && (read_len = read(msg_sock, buffer, BSIZE)) > 0 && !error_occurred) {
            ssize_t to_write_len = std::min(read_len, remaining_file_size);
            write_len = write(fd, buffer, to_write_len);
            if (write_len != to_write_len) {
                error_occurred = true;
            }
            remaining_file_size -= write_len;
        }
        if (read_len < 0 || remaining_file_size != 0) {
//            throw std::runtime_error("reading from client socket");
            /* TODO może nie zabijać serwera */
//            kill(parent_pid, SIGUSR1);
            error_occurred = true;
        }
        printf("ending connection\n");
        if (close(msg_sock) < 0)
            throw std::runtime_error("close");
    }
    else {
    }

    if (error_occurred) {
        unlink(filename.c_str());
    }

    std::cout << "after accepting\n";


    close(state.socket);
    close(sock);
    std::cout << "child ending\n";
    exit(0);
}

void
upload(server_options &options, server_state &state, const struct sockaddr_in &client_address, CMPLX_CMD &request) {
    bool exists = false;
    for (auto &file : state.files) {
        if (file.filename().string() == request.data) {
            exists = true;
        }
    }

    if (state.available_space < request.param || exists ||
        request.data.find('/') != std::string::npos || request.data.empty()) {
        send_simple_message(state.socket, client_address, "NO_WAY", request.data, request.cmd_seq);
    }
    else {
        state.available_space -= request.param;
        std::cout << "parent upload\n";
        fs::path new_file(options.SHRD_FLDR + "/" + request.data);
        std::cout << new_file << "\n";
        state.files.push_back(new_file);
        switch (fork()) {
            case -1:
                throw std::runtime_error("fork");
            case 0:
                receive_file(options, state, client_address, request);
                break;
            default:
                break;
        }
    }
}

void read_requests(server_options &options, server_state &state) {
    /* data received */
    char buffer[BSIZE];
    ssize_t rcv_len;
    struct sockaddr_in client_address{};
    socklen_t addrlen = sizeof client_address;
    ssize_t min_len = MIN_SIMPL_LEN;

    for (;;) {
        /* read */
        rcv_len = recvfrom(state.socket, buffer, sizeof buffer, 0, (struct sockaddr *) &client_address, &addrlen);
        if (rcv_len < 0) {
            throw std::runtime_error("read");
        }
        else {
            if (rcv_len < min_len) {
                /* TODO odnotować */
                std::cerr << "[PCKG ERROR] Skipping invalid package from " << inet_ntoa(client_address.sin_addr)
                          << ":"
                          << client_address.sin_port << ". Message too short.\n";
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
                remove(state, request.data);
            }
            else if (command_equal(request, "LIST")) {
                list(state, client_address, request);
            }
            else if (command_equal(request, "GET")) {
                fetch(options, state, client_address, request);
            }
            else if (command_equal(request, "ADD")) {
                CMPLX_CMD complex_request(buffer, rcv_len);
                upload(options, state, client_address, complex_request);
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