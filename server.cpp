#include <iostream>
#include <boost/program_options.hpp>

namespace po = boost::program_options;

void read_options(int argc, char const *argv[]) {
    po::options_description description("Allowed options");
    description.add_options()
            ("help", "help message")
            ("mcast-addr,g", "multicast address")
    ;

    po::variables_map variables;
    po::store(po::parse_command_line(argc, argv, description), variables);
    po::notify(variables);

    if (variables.count("mcast-addr")) {
        std::cout << "GOOD\n";
    }
    else {
        std::cout << "BAD\n";
    }
}

int main(int argc, char const *argv[]) {
    read_options(argc, argv);
}