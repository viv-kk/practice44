#ifndef SIEM_AGENT_H
#define SIEM_AGENT_H

#include "HashMap.h"
#include "vector.h"
#include <string>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <thread>
#include <cstdint>
#include "event_processor.h"
#include "persistent_buffer.h"
#include "inotify_wrapper.h"

class PersistentBuffer;
class DBClient;

struct AgentConfig {
    string server_host;
    int server_port;
    string database;
    string collection;
    string agent_id;
    string log_file;
    int send_interval;
    int batch_size;
    int max_buffer_size;
    Vector<string> enabled_sources;
    HashMap<string, string> source_paths;
    Vector<string> exclude_patterns;
    string persistent_buffer_path;

    static AgentConfig loadFromFile(const string& config_path);
};

struct SecurityEvent {
    string timestamp;
    string hostname;
    string source;
    string event_type;
    string severity;
    string user;
    string process;
    string command;
    string raw_log;
    string agent_id;

    string toJson() const;
    HashMap<string, string> toHashMap() const;
};

class LogCollector {
private:
    string source_name;
    string log_path;
    string pattern;
    int inotify_fd;
    int watch_fd;
    static HashMap<string, size_t> file_positions;
    static HashMap<string, string> file_inodes; 

public:
    LogCollector(const string& name, const string& path, const string& pattern = "");
    ~LogCollector();

    Vector<SecurityEvent> collectNewEvents();
    bool setupInotify();
    string extractUsernameFromPath(const string& path);
    bool checkForChanges();
    string getSourceName() const { return source_name; }

private:
    bool loadPosition();
    bool savePosition();
    Vector<SecurityEvent> readFromSpecificPath(const string& specific_path);
    Vector<string> expandPathPattern();
    bool handleFileRotation(const string& path); 
    void updateFilePosition(const string& path, size_t position); 
};

class SIEMAgent {
private:
    AgentConfig config;
    atomic<bool> running;
    EventProcessor* processor;
    PersistentBuffer* buffer;
    DBClient* db_client;
    Vector<LogCollector*> collectors;
    thread monitor_thread;
    thread sender_thread;
    condition_variable cv;
    mutex cv_mutex;
    bool stop_requested;

public:
    SIEMAgent(const string& config_path);
    ~SIEMAgent();

    bool start();
    void stop();
    void run();

private:
    void initializeCollectors();
    bool connectToDB();
    void sendEventsToDB(const Vector<SecurityEvent>& events);
    void logMessage(const string& message, const string& level = "INFO");
    void monitoringLoop();
    void sendingLoop();
    void handleLogRotation(const string& source_name);
};

#endif