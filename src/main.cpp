#include "NetworkAnalyzer.hpp"
#include <iostream>

int main() {
    try {
        NetworkAnalyzer analyzer;
        analyzer.run();
    } catch (const std::exception& e) {
        std::cerr << "Unhandled exception in main: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}