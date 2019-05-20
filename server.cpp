#include <iostream>
#include <vector>
#include <cassert>
#include <boost/filesystem.hpp>
#include <boost/program_options.hpp>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <csignal>

#include "connection.h"

namespace po = boost::program_options;
namespace fs = boost::filesystem;

std::size_t MAX_SPACE_DEFAULT = 52428800;
std::size_t TIMEOUT_DEFAULT = 5;
std::size_t TIMEOUT_MAX = 300;

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
};

server_state current_server_state{};

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
        try {
            std::vector<fs::path> files;

            for (fs::directory_iterator it(dir_path); it != fs::directory_iterator(); ++it) {
                if (fs::is_regular_file(it->path())) {
                    std::size_t current_file_size = file_size(it->path());
                    std::cout << *it << " " << current_file_size << "\n";
                    assert(state.available_space > current_file_size);
                    state.available_space -= current_file_size;
                }
            }
        }
        catch (const fs::filesystem_error &err) {
            std::cout << err.what();
        }
    } else {
        throw std::invalid_argument("wrong directory");
    }
}

void initialize_connection(const server_options &options, server_state &state) {
    /* zmienne i struktury opisujące gniazda */
    struct sockaddr_in local_address{};

    /* otworzenie gniazda */
    state.socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (state.socket < 0) {
        throw std::runtime_error("socket");
    }

    /* podpięcie się do grupy rozsyłania (ang. multicast) */
    state.ip_mreq.imr_interface.s_addr = htonl(INADDR_ANY);
    if (inet_aton(options.MCAST_ADDR.c_str(), &state.ip_mreq.imr_multiaddr) == 0) {
        throw std::runtime_error("inet_aton");
    }

    if (setsockopt(state.socket, IPPROTO_IP, IP_ADD_MEMBERSHIP,
                   (void *) &state.ip_mreq, sizeof state.ip_mreq) < 0) {
        throw std::runtime_error("setsockopt");
    }

    /* podpięcie się pod lokalny adres i port */
    local_address.sin_family = AF_INET;
    local_address.sin_addr.s_addr = htonl(INADDR_ANY);
    local_address.sin_port = htons(options.CMD_PORT);
    if (bind(state.socket, (struct sockaddr *) &local_address, sizeof local_address) < 0) {
        throw std::runtime_error("bind");
    }

}

void read_requests(server_options &options, server_state &state) {
    /* zmienne obsługujące komunikację */
    char buffer[BSIZE];
    memset(buffer, 0, BSIZE);
    ssize_t rcv_len;
    struct sockaddr_in client_address{};
    socklen_t addrlen = sizeof client_address;

    for (;;) {
        /* czytanie tego, co odebrano */
        rcv_len = recvfrom(state.socket, buffer, sizeof buffer, 0, (struct sockaddr *) &client_address, &addrlen);
        if (rcv_len < 0) {
            printf("read %zd bytes\n", rcv_len);
            throw std::runtime_error("read");
        } else {
            printf("read %zd bytes: %.*s\n", rcv_len, (int) rcv_len, buffer);
            SIMPL_CMD request(buffer, rcv_len);
            std::cout << request.cmd << " " << request.cmd_seq << "\n";
            std::cout << "port: " << htons(client_address.sin_port) << "\n";
            std::cout << "addr: " << inet_ntoa(client_address.sin_addr) << "\n";

            CMPLX_CMD good_day("GOOD_DAY", request.cmd_seq, state.available_space, options.MCAST_ADDR);
            ssize_t sent = sendto(state.socket, good_day.serialized, good_day.serialized_length, 0,
                       (struct sockaddr *) &client_address, addrlen);
            if (sent != good_day.serialized_length) {
                throw std::runtime_error("write");
            }
        }
    }
}

void clean_up(server_state &state) {
    /* w taki sposób można odpiąć się od grupy rozsyłania */
    if (setsockopt(state.socket, IPPROTO_IP, IP_DROP_MEMBERSHIP,
                   (void *) &state.ip_mreq, sizeof state.ip_mreq) < 0) {
        throw std::runtime_error("setsockopt");
    }
    close(state.socket);
}

void catch_signal(int s) {
    std::cout << "signal received\n";
    clean_up(current_server_state);
    exit(0);
}

void add_signal_handler() {
    struct sigaction signal_handler{};
    signal_handler.sa_handler = catch_signal;
    sigemptyset(&signal_handler.sa_mask);
    signal_handler.sa_flags = 0;

    sigaction(SIGINT, &signal_handler, nullptr);
}

int main(int argc, char const *argv[]) {
    try {
        add_signal_handler();
        server_options options = read_options(argc, argv);
        index_files(options, current_server_state);
        std::cerr << current_server_state.available_space << "\n";
        initialize_connection(options, current_server_state);
        read_requests(options, current_server_state);
        clean_up(current_server_state);
    } catch (const std::exception &e) {

        std::cerr << e.what() << "\n" << strerror(errno) << "\n";
    }
}