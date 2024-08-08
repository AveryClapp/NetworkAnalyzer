#include "logging.hpp"
#include <sstream>
#include <iostream>
#include <chrono>
#include <iomanip>


Logger* Logger::instance = nullptr;
std::mutex Logger::mutex;

Logger::Logger(const std::string& filename, LogLevel level, bool to_console) : level(level), to_console(to_console) {
    log_file.open(filename, std::ios::app);
    if (!log_file.is_open()) {
        throw std::runtime_error("Failed to open log file: " + filename);
    }
}

Logger::~Logger() {
    if (log_file.is_open()) {
        log_file.close();
    }
}

Logger& Logger::getInstance(const std::string &filename, LogLevel level, bool to_console) {
    std::lock_guard<std::mutex> lock(mutex);
    if (instance == nullptr) {
        instance = new Logger(filename, level, to_console);
    }
    return *instance;
}


void Logger::log_message(const std::string& message, LogLevel msg_level) const {
    if (msg_level >= level) {
        std::string output = format_message(message, msg_level);
        if (log_file.is_open()) {
            log_file << output << "\n";
        } 
        if (to_console) {
            std::cout << output << std::endl;
        }
    }
}

std::string to_string(LogLevel level) {
    switch (level) {
        case LogLevel::DEBUG: return "DEBUG";
        case LogLevel::INFO: return "INFO";
        case LogLevel::WARNING: return "WARNING";
        case LogLevel::ERROR: return "ERROR";
        case LogLevel::CRITICAL: return "CRITICAL";
        default: return "UNKNOWN";
    }
}

std::string Logger::format_message(const std::string& message, LogLevel msg_level) const {
    std::ostringstream oss;
    auto now = std::chrono::system_clock::now();
    auto now_c = std::chrono::system_clock::to_time_t(now);

    oss << std::put_time(std::localtime(&now_c), "%m-%d %H:%M:%S");
    oss << " [" << to_string(msg_level) << "] " << message;
    return oss.str();
}