#include <iostream>
#include <boost/program_options.hpp>

namespace po = boost::program_options;

std::size_t TIMEOUT_DEFAULT = 5;
std::size_t TIMEOUT_MAX = 300;

struct client_options {
    std::string MCAST_ADDR = "";
    int CMD_PORT = 0;
    std::string OUT_FLDR = "";
    unsigned int TIMEOUT = 0;
};

client_options read_options(int argc, char const *argv[]) {
    po::options_description description("Allowed options");
    client_options options;

    description.add_options()
            ("help", "help message")
            ("mcast-addr,g", po::value<std::string>(&options.MCAST_ADDR))
            ("cmd-port,p", po::value<int>(&options.CMD_PORT))
            ("out-fldr,o", po::value<std::string>(&options.OUT_FLDR))
            ("timeout,t", po::value<unsigned int>(&options.TIMEOUT)->default_value(TIMEOUT_DEFAULT))
            ;
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

int main(int argc, char const *argv[]) {
    client_options options = read_options(argc, argv);

}
