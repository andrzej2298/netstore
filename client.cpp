/* TODO
 * - sprawdzanie cmd_seq
 * */

#include <iostream>
#include <regex>
#include <algorithm>
#include <chrono>
#include <vector>

#include <boost/program_options.hpp>
#include <boost/tokenizer.hpp>

#include <csignal>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "connection.h"

namespace po = boost::program_options;
namespace chr = std::chrono;

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

struct simple_command {
    std::string address;
    SIMPL_CMD command;
};

struct complex_command {
    std::string address;
    CMPLX_CMD command;
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

uint64_t send_simple_message(client_state &state, const std::string &cmd, const std::string &data) {
    /* TODO z czy bez nawiasów */
    uint64_t cmd_seq = get_cmd_seq();
    SIMPL_CMD hello(cmd, cmd_seq, data);
    if (sendto(state.socket, hello.serialized, hello.serialized_length, 0,
               (struct sockaddr *) &state.remote_address,
               sizeof state.remote_address) != hello.serialized_length) {
        throw std::runtime_error("write");
    }
}

void discover_single_address(client_state &state, const chr::system_clock::time_point &end_point,
        const chr::system_clock::time_point &current_time, struct timeval &wait_time, char *buffer,
        std::vector<simple_command> &server_messages) {
    struct sockaddr_in server_address{};
    socklen_t addrlen = sizeof server_address;
    ssize_t rcv_len;
    chr::nanoseconds remaining_time = end_point - current_time;
    chr::seconds sec = chr::duration_cast<chr::seconds>(remaining_time);
    wait_time.tv_sec = sec.count();
    wait_time.tv_usec = chr::duration_cast<chr::microseconds>(remaining_time - sec).count();
    if (setsockopt(state.socket, SOL_SOCKET, SO_RCVTIMEO, (void *)&wait_time,
                   sizeof wait_time) < 0) {
        throw std::runtime_error("setsockopt");
    }

    rcv_len = recvfrom(state.socket, buffer, BSIZE, 0, (struct sockaddr *) &server_address, &addrlen);
    if (rcv_len < 0) {
        if (rcv_len != -1 ||
            (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINPROGRESS)) {
            /* not caused by timeout */
            throw std::runtime_error("read");
        }
    } else {
        CMPLX_CMD good_day(buffer, rcv_len);
        server_messages.push_back({inet_ntoa(server_address.sin_addr), good_day.data, good_day.param});
    }
}

void send_command(client_state &state, client_options &options) {
    /* TODO sprawdzanie seq */
    uint64_t cmd_seq = send_simple_message(state, "HELLO", "");

    /* TODO sprawdzić czy wiadomość jest poprawna, bo będą błędy przy deserializacji */
    char buffer[BSIZE];

    std::vector<simple_command> server_infos;
    chr::system_clock::time_point start_point = chr::system_clock::now();
    std::chrono::seconds timeout(options.TIMEOUT);
    chr::system_clock::time_point end_point = start_point + timeout;
    struct timeval wait_time{};
    for (;;) {
        chr::system_clock::time_point current_time = chr::system_clock::now();
        if (end_point < current_time) {
            break;
        } else {
            discover_single_address(state, end_point, current_time, wait_time, buffer, server_infos);
        }
    }

    for (simple_command &info : server_infos) {
        std::cout << "Found " << info.address << " (" << info.multicast_address << ") ";
        std::cout << "with free space " << info.free_space << "\n";
    }

    /* revert socket timeout */
    wait_time.tv_sec = 0;
    wait_time.tv_usec = 0;
    if (setsockopt(state.socket, SOL_SOCKET, SO_RCVTIMEO, (void *)&wait_time,
                   sizeof wait_time) < 0) {
        throw std::runtime_error("setsockopt");
    }
}

void discover(client_state &state, client_options &options) {
    send_command(state, options);
}

void search(client_state &state, client_options &options) {

}

void remove(client_state &state, client_options &options, const std::string &argument) {
    send_simple_message(state, "DEL", argument);
}

void handle_client_command(const std::smatch &match, client_state &state, client_options &options) {
    std::string command, argument;
    if (match.size() == 1) {
        command = match[0];
        if (command == "discover") {
            discover(state, options);
        } else if (command == "exit") {
            clean_up(state);
        } else {
            assert(false);
        }
    } else {
        command = match[1];
        argument = match[2];
        if (command == "search") {

        }
        else if (command == "remove") {
            remove(state, options, argument);
        }
        std::cout << "command: " << command << ", argument " << argument << "\n";
    }
}

void client_loop(client_state &state, client_options &options) {
    /* TODO co ze spacjami przed i po oraz np. z danymi "search " oraz "search" */
    static const std::regex discover_r("discover");
    static const std::regex search_r("(search) ?(.*)");
    static const std::regex fetch_r("(fetch) ?(.*)");
    static const std::regex upload_r("(upload) ?(.*)");
    static const std::regex remove_r("(remove) (.*)");
    static const std::regex exit_r("exit");
    static const std::regex expressions[] = {discover_r, search_r, fetch_r,
                                         upload_r, remove_r, exit_r};

    for (;;) {
        std::string line;
        std::getline(std::cin, line);
        std::transform(line.begin(), line.end(), line.begin(), ::tolower);
        std::smatch match;

        for (const std::regex &r : expressions) {
            if (std::regex_match(line, match, r)) {
                handle_client_command(match, state, options);
                break;
            }
        }
    }
}

void catch_signal(int) {
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
        client_loop(current_client_state, options);
        clean_up(current_client_state);
    }
    catch (const std::exception &exception) {
        std::cerr << "error " << exception.what() << "\n";
    }
}

