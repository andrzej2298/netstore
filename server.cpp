#include <iostream>
#include <vector>
#include <boost/filesystem.hpp>
#include <boost/program_options.hpp>

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

server_options read_options(int argc, char const *argv[]) {
    po::options_description description("Allowed options");
    server_options options;

    description.add_options()
            ("help", "help message")
            ("mcast-addr,g", po::value<std::string>(&options.MCAST_ADDR))
            ("cmd-port,p", po::value<int>(&options.CMD_PORT))
            ("max-space,b", po::value<std::size_t>(&options.MAX_SPACE)->default_value(MAX_SPACE_DEFAULT))
            ("shrd-fldr,f", po::value<std::string>(&options.SHRD_FLDR))
            ("timeout,t", po::value<unsigned int>(&options.TIMEOUT)->default_value(TIMEOUT_DEFAULT))
    ;
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

int main(int argc, char const *argv[]) {
    server_options options = read_options(argc, argv);

    fs::path dir_path(options.SHRD_FLDR);

    try {
        if (fs::exists(dir_path) && fs::is_directory(dir_path)) {
            std::vector<fs::path> files;

            for (fs::directory_iterator it(dir_path); it != fs::directory_iterator(); ++it) {
                if (fs::is_regular_file(it->path())) {
                    std::cout << *it << " " << file_size(it->path()) << "\n";
                }
            }
        }
        else {
            std::cout << "BAD DIR";
        }
    }
    catch (const fs::filesystem_error &err) {
        std::cout << err.what();
    }
}