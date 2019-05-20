#include <iostream>
#include <regex>
#include <algorithm>

#include <boost/program_options.hpp>
#include <boost/tokenizer.hpp>

#include <csignal>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "connection.h"

namespace po = boost::program_options;

std::size_t TIMEOUT_DEFAULT = 5;
std::size_t TIMEOUT_MAX = 300;
int TTL_VALUE = 4;
int ENABLE_BROADCAST = 1;

struct client_options {
    std::string MCAST_ADDR = "";
    int CMD_PORT = 0;
    std::string OUT_FLDR = "";
    unsigned int TIMEOUT = 0;
};

struct client_state {
    int socket{};
    struct sockaddr_in remote_address{};
};

client_state current_client_state{};

void clean_up(client_state &state) {
    close(state.socket);
    exit(0);
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

    return options;
}

void initialize_connection(const client_options &options, client_state &state) {
    /* socket info */
    struct sockaddr_in local_address{};

    /* opening the socket */
    state.socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (state.socket < 0) {
        throw std::runtime_error("socket");
    }

    /* podpięcie się pod lokalny adres i port */
    local_address.sin_family = AF_INET;
    local_address.sin_addr.s_addr = htonl(INADDR_ANY);
    local_address.sin_port = htons(0);
    if (bind(state.socket, (struct sockaddr *) &local_address, sizeof local_address) < 0) {
        throw std::runtime_error("bind");
    }

    std::cout << "port: " << htons(local_address.sin_port) << "\n";
    std::cout << "addr: " << inet_ntoa(local_address.sin_addr) << "\n";

    /* enabling broadcast */
    set_socket_option(state.socket, ENABLE_BROADCAST, SOL_SOCKET, SO_BROADCAST, "setsockopt broadcast");

    /* setting TTL */
    set_socket_option(state.socket, TTL_VALUE, IPPROTO_IP, IP_MULTICAST_TTL, "setsockopt multicast ttl");

    /* ustawienie adresu i portu odbiorcy */
    state.remote_address.sin_family = AF_INET;
    state.remote_address.sin_port = htons(options.CMD_PORT);
    if (inet_aton(options.MCAST_ADDR.c_str(), &state.remote_address.sin_addr) == 0) {
        throw std::runtime_error("inet aton");
    }

}

void discover(client_state &state) {
    /* TODO z czy bez nawiasów */
    SIMPL_CMD hello("HELLO", get_cmd_seq(), "");
    if (sendto(state.socket, hello.serialized, hello.serialized_length, 0,
               (struct sockaddr *) &state.remote_address,
               sizeof state.remote_address) != hello.serialized_length) {
        throw std::runtime_error("write");
    }

    /* TODO sprawdzić czy wiadomość jest poprawna, bo będą błędy przy deserializacji */
    ssize_t rcv_len;
    char buffer[BSIZE];
    memset(buffer, 0, BSIZE);
    rcv_len = read(state.socket, buffer, sizeof buffer);
    if (rcv_len < 0) {
        throw std::runtime_error("read");
    }
    else {
        printf("read %zd bytes: %.*s\n", rcv_len, (int) rcv_len, buffer);
        CMPLX_CMD good_day(buffer, rcv_len);

        std::cout << good_day.cmd << " " << good_day.cmd_seq << " " << good_day.param << " ";
        std::cout << good_day.data << "\n";
    }
}

void handle_client_command(const std::smatch &match, client_state &state) {
    std::string command, argument;
    if (match.size() == 1) {
        command = match[0];
        if (command == "discover") {
            discover(state);
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
        std::cout << "command: " << command << ", argument" << argument << "\n";
    }
}

void client_loop(client_state &state) {
    /* TODO co ze spacjami przed i po oraz np. z danymi "search " oraz "search" */
    static const std::regex discover_r("discover");
    static const std::regex search_r("(search) (.*)");
    static const std::regex fetch_r("(fetch) (.*)");
    static const std::regex upload_r("(upload) (.*)");
    static const std::regex remove_r("(remove) (.*)");
    static const std::regex exit_r("exit");
    static const std::regex regexes[] = {discover_r, search_r, fetch_r,
                                         upload_r, remove_r, exit_r};

    for (;;) {
        std::string line;
        std::getline(std::cin, line);
        std::transform(line.begin(), line.end(), line.begin(), ::tolower);
        std::smatch match;

        for (const std::regex &r : regexes) {
            if (std::regex_match(line, match, r)) {
                handle_client_command(match, state);
                break;
            }
        }
    }
}

void catch_signal(int s) {
    std::cout << "signal received\n";
    clean_up(current_client_state);
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
        client_options options = read_options(argc, argv);
        initialize_connection(options, current_client_state);
        client_loop(current_client_state);
        clean_up(current_client_state);
    }
    catch (const std::exception &exception) {
        std::cerr << "error " << exception.what() << "\n";
    }
}

