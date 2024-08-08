#ifndef LOGGING_H
#define LOGGING_H

#include <string>
#include <fstream>
#include <mutex>

enum class LogLevel { DEBUG, INFO, WARNING, ERROR, CRITICAL };

class Logger {
private:
    static Logger* instance;
    static std::mutex mutex;
    
    mutable std::ofstream log_file;
    LogLevel level;
    bool to_console;

    // Private constructor
    Logger(const std::string &filename, LogLevel level, bool to_console);

    // Delete copy constructor and assignment operator
    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;

public:
    // Destructor
    ~Logger();

    // Static method to get the instance
    static Logger& getInstance(const std::string &filename = "", LogLevel level = LogLevel::INFO, bool to_console = false);

    void set_log_level(LogLevel new_level) { level = new_level; }
    LogLevel get_log_level() const { return level; }
    
    // Log a message to the file the object holds
    void log_message(const std::string& message, LogLevel msg_level) const;

private:
    // Helper function used to format the message to be logged
    std::string format_message(const std::string& message, LogLevel msg_level) const;
};

#endif // LOGGING_H