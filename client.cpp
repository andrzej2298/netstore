/* TODO
 * - sprawdzanie cmd_seq
 * - dzielenie listy plików
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

template<typename T>
struct message {
    struct sockaddr_in address;
    T command;
};

struct client_state {
    int socket{};
    struct sockaddr_in remote_address{};
    std::vector<message<SIMPL_CMD>> previous_search;
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

boost::tokenizer<boost::char_separator<char>> tokenize(const message<SIMPL_CMD> &message) {
    /* splitting the file list on '\n' */
    boost::char_separator<char> newline("\n");
    boost::tokenizer<boost::char_separator<char>> t(message.command.data, newline);
    return t;
}

void initialize_connection(const client_options &options, client_state &state) {
    /* socket info */
    struct sockaddr_in local_address{};

    /* opening the socket */
    state.socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (state.socket < 0) {
        throw std::runtime_error("socket");
    }

    /* host address */
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

    /* multicast address */
    state.remote_address.sin_family = AF_INET;
    state.remote_address.sin_port = htons(options.CMD_PORT);
    if (inet_aton(options.MCAST_ADDR.c_str(), &state.remote_address.sin_addr) == 0) {
        throw std::runtime_error("inet aton");
    }
}

uint64_t send_simple_client_message(client_state &state, const std::string &cmd, const std::string &data) {
    return send_simple_message(state.socket, state.remote_address, cmd, data, get_cmd_seq());
}

template<typename T>
void receive_timeouted_message(client_state &state, const chr::system_clock::time_point &end_point,
                               const chr::system_clock::time_point &current_time, struct timeval &wait_time,
                               char *buffer,
                               std::vector<message<T>> &server_messages) {
    struct sockaddr_in server_address{};
    socklen_t addrlen = sizeof server_address;
    ssize_t rcv_len;
    chr::nanoseconds remaining_time = end_point - current_time;
    chr::seconds sec = chr::duration_cast<chr::seconds>(remaining_time);
    wait_time.tv_sec = sec.count();
    wait_time.tv_usec = chr::duration_cast<chr::microseconds>(remaining_time - sec).count();
    if (setsockopt(state.socket, SOL_SOCKET, SO_RCVTIMEO, (void *) &wait_time,
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
    }
    else {
//        server_messages.push_back({inet_ntoa(server_address.sin_addr), {buffer, rcv_len}});
        server_messages.push_back({server_address, {buffer, rcv_len}});
    }
}

template<typename T>
void
receive_timeouted_messages(client_state &state, client_options &options, std::vector<message<T>> &server_messages) {
    /* TODO sprawdzić czy wiadomość jest poprawna (np. długość), bo będą błędy przy deserializacji */
    char buffer[BSIZE];


    chr::system_clock::time_point start_point = chr::system_clock::now();
    std::chrono::seconds timeout(options.TIMEOUT);
    chr::system_clock::time_point end_point = start_point + timeout;
    struct timeval wait_time{};
    for (;;) {
        chr::system_clock::time_point current_time = chr::system_clock::now();
        if (end_point < current_time) {
            break;
        }
        else {
            receive_timeouted_message(state, end_point, current_time, wait_time, buffer, server_messages);
        }
    }

    /* revert socket timeout */
    wait_time.tv_sec = 0;
    wait_time.tv_usec = 0;
    if (setsockopt(state.socket, SOL_SOCKET, SO_RCVTIMEO, (void *) &wait_time,
                   sizeof wait_time) < 0) {
        throw std::runtime_error("setsockopt");
    }
}

void discover(client_state &state, client_options &options) {
    /* TODO sprawdzanie seq */
    uint64_t cmd_seq = send_simple_client_message(state, "HELLO", "");
    std::vector<message<CMPLX_CMD>> server_messages;
    receive_timeouted_messages(state, options, server_messages);

    for (auto &info : server_messages) {
        std::cout << "Found " << inet_ntoa(info.address.sin_addr) << " (" << info.command.data << ") ";
        std::cout << "with free space " << info.command.param << "\n";
    }
}

void search(client_state &state, client_options &options, const std::string &argument) {
    uint64_t cmd_seq = send_simple_client_message(state, "LIST", argument);
    std::vector<message<SIMPL_CMD>> server_messages;
    receive_timeouted_messages(state, options, server_messages);

    for (auto &info : server_messages) {
        std::string address(inet_ntoa(info.address.sin_addr));
        auto t = tokenize(info);
        for (auto it = t.begin(); it != t.end(); ++it) {
            std::cout << *it << " ("<< address << ")" << "\n";
        }
    }

    if (!state.previous_search.empty()) {
        state.previous_search.clear();
    }
    for (message<SIMPL_CMD> &msg : server_messages) {
        state.previous_search.emplace_back(message<SIMPL_CMD>(msg));
    }
}

void fetch(client_state &state, client_options &options, const std::string &argument) {
    for (auto &info : state.previous_search) {
        auto t = tokenize(info);
        for (auto it = t.begin(); it != t.end(); ++it) {
            if (*it == argument) {
                std::cout << *it << " " << inet_ntoa(info.address.sin_addr) << "\n";
                send_simple_client_message(state, "GET", argument);
                return;
            }
        }
    }

    std::cout << "File " << argument << " wasn't found\n";
}

void remove(client_state &state, client_options &options, const std::string &argument) {
    uint64_t cmd_seq = send_simple_client_message(state, "DEL", argument);
}

void handle_client_command(const std::smatch &match, client_state &state, client_options &options) {
    std::string command, argument;
    if (match.size() == 1) {
        command = match[0];
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
        if (command == "search") {
            search(state, options, argument);
        }
        else if (command == "remove") {
            remove(state, options, argument);
        }
        else if (command == "fetch") {
            fetch(state, options, argument);
        }
        else {
            assert(false);
        }
    }
}

void client_loop(client_state &state, client_options &options) {
    /* TODO co ze spacjami przed i po oraz np. z danymi "search " oraz "search" */
    /* TODO czy na pewno te spacje, plusy i gwiazdki są dobrze obsłużone */
    static const std::regex discover_r("discover");
    static const std::regex search_r("(search) ?(.*)");
    static const std::regex fetch_r("(fetch) (.+)");
    static const std::regex upload_r("(upload) ?(.*)");
    static const std::regex remove_r("(remove) (.+)");
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

void add_signal_handlers() {
    struct sigaction signal_handler{};
    signal_handler.sa_handler = catch_signal;
    sigemptyset(&signal_handler.sa_mask);
    signal_handler.sa_flags = 0;

    sigaction(SIGINT, &signal_handler, nullptr);
}

int main(int argc, char const *argv[]) {
    try {
        add_signal_handlers();
        client_options options = read_options(argc, argv);
        initialize_connection(options, current_client_state);
        client_loop(current_client_state, options);
        clean_up(current_client_state);
    }
    catch (const std::exception &exception) {
        std::cerr << "error " << exception.what() << "\n";
    }
}

