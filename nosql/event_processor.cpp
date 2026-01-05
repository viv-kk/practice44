#include "event_processor.h"
#include "siem_agent.h"
#include <iostream>
#include <iomanip>
#include <chrono>
#include <sstream>
#include <regex>
#include <ctime>
#include <cstring>
#include <algorithm>
#include <unistd.h>
#include <pwd.h>
#include <map>
#include <vector>

using namespace std;

EventProcessor::EventProcessor(const Vector<string>& filters)
    : exclude_patterns(filters) {
}

SecurityEvent EventProcessor::processEvent(SecurityEvent& base_event,
                                          const string& log_line,
                                          const string& agent_id) {
    SecurityEvent event = base_event;

    if (shouldExclude(log_line)) {
        return event;
    }
    event.agent_id = agent_id;

    if (event.hostname.empty()) {
        char hostname[256];
        gethostname(hostname, sizeof(hostname));
        event.hostname = hostname;
    }
    if (event.timestamp.empty()) {
        auto now = chrono::system_clock::now();
        auto time_t_now = chrono::system_clock::to_time_t(now);
        stringstream ss;
        ss << put_time(gmtime(&time_t_now), "%Y-%m-%dT%H:%M:%SZ");
        event.timestamp = ss.str();
    } else {
        cout << "[PROCESS_EVENT] Using existing timestamp: " << event.timestamp << endl;
    }

    if (!event.user.empty() && (event.user.find('-') != string::npos || 
                                event.user.find(':') != string::npos ||
                                event.user.find('T') != string::npos)) {
        regex timestamp_pattern(R"(\d{4}-\d{2}-\d{2}[T ]?\d{2}:\d{2}:\d{2})");
        if (regex_search(event.user, timestamp_pattern)) {
            event.user = "unknown";
        }
    }

    if (event.source == "auditd") {
        processAuditdDetails(log_line, event);
    } else if (event.source == "syslog" || event.source == "auth") {
        processSyslogDetails(log_line, event);
    } else if (event.source == "bash_history" || event.source == "bash_history_user") {
        string username = event.user;
        processBashHistoryDetails(log_line, event, username);
    }

    if (event.event_type.empty()) {
        event.event_type = determineEventType(event.source, log_line);
    }

    if (event.severity.empty()) {
        event.severity = determineSeverity(event.event_type, log_line);
    }

    if (event.user.empty() || event.user == "unknown") {
        event.user = extractUser(log_line);
    } else {
        string checked_user = validateAndFixUsername(event.user, log_line);
        if (checked_user != event.user) {
            event.user = checked_user;
        }
        if (event.user.empty()) {
            event.user = "unknown";
        }
    }

    if (event.process.empty() || event.process == "unknown") {
        event.process = extractProcess(log_line);
    }
    if (event.command.empty()) {
        event.command = extractCommand(log_line);
    }
    return event;
}

string generateEventId(const SecurityEvent& event) {
    string unique_str = event.timestamp + event.source + event.raw_log;

    size_t hash = 0;
    for (char c : unique_str) {
        hash = hash * 31 + c;
    }
    return "evt_" + to_string(hash);
}

SecurityEvent EventProcessor::processLogLine(const string& source,
                                           const string& log_line,
                                           const string& agent_id) {
    SecurityEvent event;

    if (shouldExclude(log_line)) {
        return event;
    }
    event.source = source;
    event.agent_id = agent_id;
    event.raw_log = log_line;

    char hostname[256];
    gethostname(hostname, sizeof(hostname));
    event.hostname = hostname;
    event.timestamp = extractTimestampFromLog(source, log_line);
    
    if (event.timestamp.empty()) {
        auto now = chrono::system_clock::now();
        auto time_t_now = chrono::system_clock::to_time_t(now);
        stringstream ss;
        ss << put_time(gmtime(&time_t_now), "%Y-%m-%dT%H:%M:%SZ");
        event.timestamp = ss.str();
    } else {
        cout << "[PROCESS_LOG] Extracted timestamp from log: " << event.timestamp << endl;
    }
    if (source == "auditd") {
        processAuditdDetails(log_line, event);
    } else if (source == "syslog" || source == "auth") {
        processSyslogDetails(log_line, event);
    } else if (source == "bash_history" || source == "bash_history_user") {
        string username = event.user;
        processBashHistoryDetails(log_line, event, username);
    }
    if (event.event_type.empty()) {
        event.event_type = determineEventType(source, log_line);
    }

    if (event.severity.empty()) {
        event.severity = determineSeverity(event.event_type, log_line);
    }
    if (event.user.empty() || event.user == "unknown") {
        event.user = extractUser(log_line);
    } else {
        string checked_user = validateAndFixUsername(event.user, log_line);
        if (checked_user != event.user) {
            event.user = checked_user;
        }
        if (event.user.empty()) {
            event.user = "unknown";
        }
    }

    if (event.process.empty() || event.process == "unknown") {
        event.process = extractProcess(log_line);
    }
    if (event.command.empty()) {
        event.command = extractCommand(log_line);
    }
    return event;
}

void EventProcessor::processAuditdDetails(const string& log_line, SecurityEvent& event) {
    if (event.event_type.empty()) {
        string extracted_type = extractAuditdField(log_line, "type");
        if (!extracted_type.empty() && extracted_type != "type=") {
            event.event_type = extracted_type;
        } else {
            event.event_type = determineEventType("auditd", log_line);
        }
    }
    if (event.user.empty() || event.user == "unknown") {
        string audit_user;
        audit_user = extractAuditdField(log_line, "auid");
        
        if (audit_user.empty() || audit_user == "unset" || audit_user == "-1" || 
            audit_user.find("type=") == 0 || audit_user.find("msg=") == 0) {
            audit_user = extractAuditdField(log_line, "uid");
        }
        
        if (audit_user.empty() || audit_user == "unset" || audit_user == "-1" ||
            audit_user.find("type=") == 0 || audit_user.find("msg=") == 0) {
            size_t msg_pos = log_line.find("msg=");
            if (msg_pos != string::npos) {
                string msg_part = log_line.substr(msg_pos);
                
                size_t uid_pos = msg_part.find("uid=");
                if (uid_pos != string::npos) {
                    size_t start = uid_pos + 4;
                    size_t end = msg_part.find_first_of(" \n)", start);
                    if (end != string::npos) {
                        audit_user = msg_part.substr(start, end - start);
                    }
                }
                if (audit_user.empty() || audit_user == "unset" || audit_user == "-1") {
                    size_t auid_pos = msg_part.find("auid=");
                    if (auid_pos != string::npos) {
                        size_t start = auid_pos + 5;
                        size_t end = msg_part.find_first_of(" \n)", start);
                        if (end != string::npos) {
                            audit_user = msg_part.substr(start, end - start);
                        }
                    }
                }
            }
        }
        
        if (!audit_user.empty() && audit_user != "unset" && audit_user != "-1" &&
            audit_user.find("type=") != 0 && audit_user.find("msg=") != 0) {
            
            if (!isTimestampOrInvalidUsername(audit_user)) {
                event.user = audit_user;
            } else {
                event.user = "unknown";
            }
        } else {
            event.user = "unknown";
        }
    }
    if (event.process.empty() || event.process == "unknown" || 
        event.process.find("type=") == 0 || event.process.find("msg=") == 0) {
        
        string process_name = "unknown";
        string comm = extractAuditdField(log_line, "comm");
        
        if (!comm.empty() && comm != "?" && comm != "\"?\"" && 
            comm.find("type=") != 0 && comm.find("msg=") != 0 &&
            comm.length() < 50) { 
            process_name = comm;
        }
        
        if (process_name == "unknown" || process_name.find("type=") == 0) {
            string exe = extractAuditdField(log_line, "exe");            
            if (!exe.empty() && exe != "?" && exe != "\"?\"" &&
                exe.find("type=") != 0 && exe.find("msg=") != 0) {
                size_t last_slash = exe.find_last_of('/');
                if (last_slash != string::npos && last_slash + 1 < exe.length()) {
                    process_name = exe.substr(last_slash + 1);
                } else {
                    process_name = exe;
                }
                if (process_name.length() >= 2 && 
                    process_name[0] == '"' && process_name[process_name.length()-1] == '"') {
                    process_name = process_name.substr(1, process_name.length() - 2);
                }
            }
        }
        if ((process_name == "unknown" || process_name.find("type=") == 0) && 
            event.event_type == "PROCTITLE") {
            string proctitle = extractAuditdField(log_line, "proctitle");            
            if (!proctitle.empty() && proctitle != "?" && proctitle != "\"?\"" &&
                proctitle.find("type=") != 0 && proctitle.find("msg=") != 0) {
                size_t space_pos = proctitle.find(' ');
                if (space_pos != string::npos) {
                    process_name = proctitle.substr(0, space_pos);
                } else {
                    process_name = proctitle;
                }
            }
        }
        if (process_name == "unknown" || process_name.find("type=") == 0) {
            if (event.event_type == "AVC") {
                process_name = "apparmor";
            } else if (event.event_type == "SYSCALL") {
                process_name = "syscall";
            } else if (event.event_type == "PROCTITLE") {
                process_name = "unknown_proc";
            } else if (event.event_type == "USER_LOGIN") {
                process_name = "login";
            } else if (event.event_type == "USER_CMD") {
                process_name = "user_cmd";
            } else {
                process_name = "auditd";
            }
        }
        if (process_name != "unknown" && process_name.find("type=") != 0 && 
            process_name.find("msg=") != 0) {
            event.process = process_name;
        } else {
            event.process = "unknown";
        }
    }
    if (event.command.empty()) {
        if (event.event_type == "PROCTITLE") {
            string proctitle = extractAuditdField(log_line, "proctitle");
            if (!proctitle.empty() && proctitle != "?" && proctitle != "\"?\"") {
                event.command = decodeProctitle(proctitle);
                if (event.command.empty()) {
                    event.command = proctitle; 
                }
            }
        }
        else if (event.event_type == "EXECVE") {
            event.command = extractExecveCommand(log_line);
        }
        else if (event.event_type == "USER_CMD") {
            event.command = extractAuditdField(log_line, "cmd");
        }
        if (event.command.empty()) {
            event.command = extractAuditdField(log_line, "cmd");
        }
    }
    if (event.severity.empty()) {
        event.severity = determineSeverity(event.event_type, log_line);
    }
}

void EventProcessor::processSyslogDetails(const string& log_line, SecurityEvent& event) {
    if (event.user.empty() || event.user == "unknown") {
        string syslog_user = extractSyslogUser(log_line);
        if (!syslog_user.empty() && syslog_user != "unknown") {
            event.user = syslog_user;
        }
    }
    if (log_line.find('[') == string::npos && log_line.find(']') == string::npos) {
        if (event.process == "unknown") {
            event.process = "system";  
        }
        return;
    }
    regex syslog_regex("^[^ ]+\\s+(\\S+)\\s+(\\S+?)\\[(\\d+)\\]:\\s+(.*)$");
    smatch match;
    if (regex_search(log_line, match, syslog_regex) && match.size() > 4) {
        string log_hostname = match[1].str();
        string process_name = match[2].str();
        string pid = match[3].str();
        string message = match[4].str();
        if (event.process.empty() || event.process == "unknown") {
            event.process = process_name;
        }

        if (event.event_type.empty()) {
            event.event_type = determineEventType("syslog", message);
        }

        if (event.severity.empty()) {
            event.severity = determineSeverity(event.event_type, message);
        }
        if (event.user.empty() || event.user == "unknown") {
            string extracted_user = extractUser(message);
            if (!extracted_user.empty() && extracted_user != "unknown" && 
                !isTimestampOrInvalidUsername(extracted_user)) {
                event.user = extracted_user;
            }
        }

        if (event.command.empty()) {
            event.command = extractCommand(message);
        }
    } else {
        event.event_type = determineEventType("syslog", log_line);
        event.severity = determineSeverity(event.event_type, log_line);
        if ((event.user.empty() || event.user == "unknown") && 
            !isTimestampOrInvalidUsername(log_line)) {
            event.user = extractUser(log_line);
        }
    }
}

string EventProcessor::extractSyslogUser(const string& log_line) {
    regex timestamp_only_regex("^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}\\.\\d+[+-]\\d{2}:\\d{2}$");
    if (regex_match(log_line, timestamp_only_regex)) {
        return "unknown";
    }
    if (log_line.find("Accepted") != string::npos || log_line.find("Failed") != string::npos) {
        regex ssh_user_regex("(?:Accepted|Failed).*?(?:for|user)\\s+(\\S+)");
        smatch match;
        if (regex_search(log_line, match, ssh_user_regex) && match.size() > 1) {
            string user = match[1].str();
            if (user == "invalid") {
                size_t invalid_pos = log_line.find("invalid user");
                if (invalid_pos != string::npos) {
                    size_t start = invalid_pos + 12;
                    while (start < log_line.length() && log_line[start] == ' ') start++;
                    size_t end = log_line.find(' ', start);
                    if (end == string::npos) end = log_line.length();
                    user = log_line.substr(start, end - start);
                }
            }
            if (!user.empty() && user != "invalid" && 
                !isTimestampOrInvalidUsername(user)) {
                bool is_all_digits = true;
                for (char c : user) {
                    if (!isdigit(c)) {
                        is_all_digits = false;
                        break;
                    }
                }                
                if (is_all_digits) {
                    try {
                        long pid = stol(user);
                        if (pid > 100 && pid < 100000) {
                            return "unknown";
                        }
                    } catch (...) {
                    }
                }
                return user;
            }
        }
    }
    
    if (log_line.find("sudo:") != string::npos) {
        regex sudo_user_regex("(?:session\\s+(?:opened|closed)\\s+for\\s+user|USER=)\\s*(\\S+)");
        smatch match;
        
        if (regex_search(log_line, match, sudo_user_regex) && match.size() > 1) {
            string user = match[1].str();
            if (user.back() == ';') {
                user.pop_back();
            }
            
            if (!user.empty() && !isTimestampOrInvalidUsername(user)) {
                return user;
            }
        }
        size_t user_pos = log_line.find("user=");
        if (user_pos != string::npos) {
            size_t start = user_pos + 5;
            size_t end = log_line.find_first_of(" ;\n", start);
            if (end == string::npos) end = log_line.length();           
            string user = log_line.substr(start, end - start);
            if (!user.empty() && !isTimestampOrInvalidUsername(user)) {
                return user;
            }
        }
    }
    
    if (log_line.find("pam_unix") != string::npos) {
        size_t colon_pos = log_line.find(":");
        if (colon_pos != string::npos && colon_pos + 2 < log_line.length()) {
            string after_colon = log_line.substr(colon_pos + 1);
            size_t user_word = after_colon.find("user");
            if (user_word != string::npos) {
                size_t start = user_word + 4;
                while (start < after_colon.length() && after_colon[start] == ' ') start++;
                
                size_t end = after_colon.find_first_of(" \n)", start);
                if (end == string::npos) end = after_colon.length();
                
                string user = after_colon.substr(start, end - start);
                if (!user.empty() && !isTimestampOrInvalidUsername(user)) {
                    return user;
                }
            }
        }
    }
    vector<regex> patterns = {
        regex("user\\s*=\\s*([^\\s;]+)"),
        regex("USER\\s*=\\s*([^\\s;]+)"),
        regex("\\b(\\w+)\\s+from\\s+[0-9]"), 
        regex("\\[(\\w+)\\]"), 
    };
    
    for (const auto& pattern : patterns) {
        smatch match;
        if (regex_search(log_line, match, pattern) && match.size() > 1) {
            string user = match[1].str();
            if (!user.empty() && user != "msg" && user != "type" && 
                !isTimestampOrInvalidUsername(user)) {
                bool is_all_digits = true;
                for (char c : user) {
                    if (!isdigit(c)) {
                        is_all_digits = false;
                        break;
                    }
                }
                if (!is_all_digits || user.length() < 3) { 
                    return user;
                } else {
                    try {
                        long num = stol(user);
                        if (num > 100000) { 
                            cout << "[EXTRACT_SYSLOG_USER] Skipping large number (PID?): " << user << endl;
                        } else if (num < 1000) {                            
                            return "uid_" + user;
                        } else {
                            struct passwd* pw = getpwuid(num);
                            if (pw != nullptr && pw->pw_name != nullptr) {
                                string username = pw->pw_name;
                                if (!username.empty()) {
                                    return username;
                                }
                            }
                            return "uid_" + user;
                        }
                    } catch (...) {
                    }
                }
            }
        }
    }
    return "unknown";
}

void EventProcessor::processBashHistoryDetails(const string& log_line,
                                               SecurityEvent& event,
                                               const string& username) {
    if (log_line.empty()) {
        return;
    }
    if (event.user.empty() || event.user == "unknown") {
        if (!username.empty() && username != "unknown" && 
            !isTimestampOrInvalidUsername(username)) {
            event.user = username;
        } else {
            event.user = "bash_user";
        }
    }

    if (event.event_type.empty()) {
        event.event_type = "shell_command";
    }

    if (event.severity.empty()) {
        event.severity = determineSeverity("shell_command", log_line);
    }

    if (event.process.empty() || event.process == "unknown") {
        event.process = "bash";
    }

    if (event.command.empty()) {
        event.command = log_line;
    }
}

bool EventProcessor::shouldExclude(const string& log_line) {
    for (size_t i = 0; i < exclude_patterns.size(); i++) {
        if (log_line.find(exclude_patterns[i]) != string::npos) {
            return true;
        }
    }
    regex timestamp_only_regex1("^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}\\.\\d+[+-]\\d{2}:\\d{2}$");
    regex timestamp_only_regex2("^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}\\.\\d+$");
    if (regex_match(log_line, timestamp_only_regex1) || regex_match(log_line, timestamp_only_regex2)) {
        return true;
    }
    if (log_line.length() < 20) {
        return true;
    }
    bool has_content = false;
    for (char c : log_line) {
        if (isalpha(c) || isdigit(c)) {
            has_content = true;
            break;
        }
    }
    if (!has_content) {
        return true;
    }
    return false;
}

string EventProcessor::determineEventType(const string& source, const string& log_line) {
    regex timestamp_only_regex("^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}\\.\\d+[+-]\\d{2}:\\d{2}$");
    regex timestamp_only_regex2("^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}\\.\\d+$");
    if (regex_match(log_line, timestamp_only_regex) || regex_match(log_line, timestamp_only_regex2)) {
        return "timestamp_only"; 
    }
    string line_lower = log_line;
    transform(line_lower.begin(), line_lower.end(), line_lower.begin(), ::tolower);
    if (source == "syslog" || source == "auth" || source == "auditd") {
        if (line_lower.find("failed password") != string::npos ||
            line_lower.find("authentication failure") != string::npos ||
            line_lower.find("failed publickey") != string::npos) {
            return "failed_login";
        }
        if (line_lower.find("accepted password") != string::npos ||
            line_lower.find("accepted publickey") != string::npos ||
            line_lower.find("authentication success") != string::npos) {
            return "successful_login";
        }

        if (line_lower.find("invalid user") != string::npos) {
            return "invalid_user";
        }
        if (line_lower.find("session opened") != string::npos ||
            line_lower.find("session started") != string::npos) {
            return "session_opened";
        }

        if (line_lower.find("session closed") != string::npos) {
            return "session_closed";
        }
        if (line_lower.find("sshd") != string::npos) {
            if (line_lower.find("accepted") != string::npos) {
                return "ssh_login_success";
            } else if (line_lower.find("failed") != string::npos) {
                return "ssh_login_failed";
            } else {
                return "ssh_event";
            }
        }
        if (line_lower.find("sudo:") != string::npos) {
            return "sudo_command";
        }
        if (line_lower.find("pam_") != string::npos) {
            if (line_lower.find("failure") != string::npos) {
                return "pam_auth_failure";
            } else if (line_lower.find("success") != string::npos) {
                return "pam_auth_success";
            }
        }
    }
    if (source == "auditd") {
        size_t type_pos = log_line.find("type=");
        if (type_pos != string::npos) {
            size_t space_pos = log_line.find(" ", type_pos);
            if (space_pos != string::npos) {
                string audit_type = log_line.substr(type_pos + 5, space_pos - (type_pos + 5));
                return audit_type;
            }
        }
        if (log_line.find("USER_LOGIN") != string::npos) {
            return "USER_LOGIN";
        }
        const char* audit_types[] = {"USER_CMD", "SYSCALL", "EXECVE", "PROCTITLE", "PATH", "AVC"};
        for (const char* type : audit_types) {
            if (log_line.find(type) != string::npos) {
                return type;
            }
        }

        return "audit_event";
    }
    else if (source.find("bash_history") != string::npos) {
        return "shell_command";
    }
    return "system_event";
}

string EventProcessor::determineSeverity(const string& event_type, const string& log_line) {
    if (event_type == "failed_login" ||
        event_type == "ssh_login_failed" ||
        event_type == "pam_auth_failure" ||
        event_type == "auth_failure" ||
        event_type == "invalid_user" ||
        event_type == "brute_force") {
        return "high";
    }
    if (event_type == "successful_login" ||
        event_type == "ssh_login_success" ||
        event_type == "pam_auth_success" ||
        event_type == "USER_LOGIN" ||
        event_type == "session_opened" ||
        event_type == "session_closed") {
        return "medium";
    }
    if (event_type == "failed_login" ||
        event_type == "auth_failure" ||
        event_type == "invalid_user" ||
        event_type == "brute_force") {
        return "high";
    }
    if (event_type == "SYSCALL" ||
        event_type == "EXECVE" ||
        event_type == "PROCTITLE" ||
        event_type == "USER_ACCT" ||
        event_type == "USER_CMD" ||
        event_type == "USER_LOGIN") {
        return "medium";
    }
    if (event_type == "AVC") {
        return "medium";
    }
    if (event_type == "sudo_command" ||
        event_type == "user_login" ||
        event_type == "command_execution" ||
        event_type == "system_call" ||
        event_type == "ssh_event" ||
        event_type == "session_opened" ||
        event_type == "session_closed") {
        return "medium";
    }
    if (event_type == "shell_command") {
        string line_lower = log_line;
        transform(line_lower.begin(), line_lower.end(), line_lower.begin(), ::tolower);
        if (line_lower.find("sudo") != string::npos ||
            line_lower.find("rm -rf") != string::npos ||
            line_lower.find("chmod 777") != string::npos ||
            line_lower.find("/etc/shadow") != string::npos ||
            line_lower.find("passwd") != string::npos) {
            return "medium";
        }
        return "low";
    }
    return "low";
}

bool EventProcessor::isTimestampOrInvalidUsername(const string& str) {
    if (str.empty() || str == "unknown") {
        return false;
    }
    bool all_digits = !str.empty();
    for (char c : str) {
        if (!isdigit(c)) {
            all_digits = false;
            break;
        }
    }
    if (all_digits) {
        try {
            long uid = stol(str);
            if (uid >= 0 && uid < 100000) {
                return false; 
            }
        } catch (...) {
        }
    }
    regex timestamp_patterns[] = {
        regex(R"(\d{4}-\d{2}-\d{2}[T ]?\d{2}:\d{2}:\d{2})"),  
        regex(R"(\d{4}-\d{2}-\d{2}[T ]?\d{2}:\d{2})"),        
        regex(R"(\d{4}-\d{2}-\d{2}[T ]?\d{2})"),            
        regex(R"(\d{4}-\d{2}-\d{2})"),                    
        regex(R"(\d{2}:\d{2}:\d{2})"),                 
        regex(R"(\d{10,})"),                              
        regex(R"(\d+\.\d+)")                              
    };
    for (const auto& pattern : timestamp_patterns) {
        if (regex_match(str, pattern)) {
            return true;
        }
    }
    if (str.find('-') != string::npos && 
        (str.find(':') != string::npos || str.find('T') != string::npos) &&
        str.length() >= 8) {
        if (str.length() >= 4 && isdigit(str[0]) && isdigit(str[1]) && 
            isdigit(str[2]) && isdigit(str[3])) {
            return true;
        }
    }
    if (all_digits && str.length() > 8) {
        try {
            long long timestamp = stoll(str);
            if (timestamp > 1000000000 && timestamp < 5000000000) {
                return true;
            }
        } catch (...) {
        }
    }
    return false;
}

string EventProcessor::validateAndFixUsername(const string& username, const string& log_line) {
    if (username.empty() || username == "unknown") {
        return username;
    }
    if (username.find('/') != string::npos) {
        size_t last_slash = username.find_last_of('/');
        if (last_slash != string::npos && last_slash + 1 < username.length()) {
            string filename = username.substr(last_slash + 1);
            if (filename.find('.') == string::npos && filename.length() > 1) {
                return "unknown";
            }
        }
        return "unknown";
    }
    if (isTimestampOrInvalidUsername(username)) {
        string new_user = extractUser(log_line);
        if (!new_user.empty() && new_user != "unknown" && 
            !isTimestampOrInvalidUsername(new_user)) {
            return new_user;
        }
        return "unknown";
    }
    if (username.find(' ') != string::npos) {
        string cleaned = username;
        size_t pos = 0;
        while ((pos = cleaned.find(' ', pos)) != string::npos) {
            cleaned.replace(pos, 1, "_");
            pos += 1;
        }
        return cleaned;
    }
    for (char c : username) {
        if (!isalnum(c) && c != '_' && c != '-' && c != '.' && c != '@') {
            string cleaned;
            for (char ch : username) {
                if (isalnum(ch) || ch == '_' || ch == '-' || ch == '.' || ch == '@') {
                    cleaned += ch;
                }
            }
            if (!cleaned.empty()) {
                return cleaned;
            }
            return "unknown";
        }
    }
    
    return username; 
}

string EventProcessor::extractUser(const string& log_line) {
    regex timestamp_only_regex("^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}\\.\\d+[+-]\\d{2}:\\d{2}$");
    if (regex_match(log_line, timestamp_only_regex)) {
        return "unknown";
    }
    if (log_line.find("type=PROCTITLE") != string::npos) {
        regex numeric_uid_regex("\\b(?:auid|uid)=([0-9]+)");
        smatch match;
        if (regex_search(log_line, match, numeric_uid_regex) && match.size() > 1) {
            string uid_str = match[1].str();
            try {
                long uid = stol(uid_str);
                if (uid == 0) {
                    return "root";
                } else if (uid < 1000) {
                    return "uid_" + uid_str;
                } else if (uid < 100000) {
                    struct passwd* pw = getpwuid(uid);
                    if (pw != nullptr && pw->pw_name != nullptr) {
                        string username = pw->pw_name;
                        if (!username.empty()) {
                            return username;
                        }
                    }
                    return "uid_" + uid_str;
                } else {
                    return "unknown";
                }
            } catch (...) {
                return "uid_" + uid_str;
            }
        } else {
            regex pid_regex("\\bpid=([0-9]+)");
            if (regex_search(log_line, match, pid_regex) && match.size() > 1) {
                string pid_str = match[1].str();
                regex ses_regex("\\bses=([0-9]+)");
                if (regex_search(log_line, match, ses_regex) && match.size() > 1) {
                    string ses_str = match[1].str();
                    return "session_" + ses_str;
                }
                return "pid_" + pid_str;
            }
        }
        return "unknown"; 
    }
    regex auditd_uid_named_regex("\\b(?:AUID|UID|FSUID)=\"([^\"]+)\"");
    smatch match;
    if (regex_search(log_line, match, auditd_uid_named_regex) && match.size() > 1) {
        string user = match[1].str();
        if (user.find('/') != string::npos) {
            cout << "[EXTRACT_USER] Ignoring path-like user: " << user << endl;
        } else if (user == "Ilyinykh" || user == "user") {
            return user;
        }
        if (user == "root") {
            return "root";
        }
        if (user == "unset" || user == "(unknown)" || user == "-1") {
        } else if (!isTimestampOrInvalidUsername(user)) {
            return user;
        }
    }
    regex full_uid_regex("\\b(?:AUID|UID|FSUID|OUID)=\"([^\"]+)\"");
    if (regex_search(log_line, match, full_uid_regex) && match.size() > 1) {
        string user = match[1].str();
        if (!user.empty() && user != "root" && user != "unset" && user != "(unknown)" &&
            !isTimestampOrInvalidUsername(user)) {
            return user;
        }
    }
    regex auditd_user_regex("\\b(?:auid|uid|user)=(\\S+)");
    if (regex_search(log_line, match, auditd_user_regex) && match.size() > 1) {
        string user = match[1].str();
        if (user == "0") {
            return "root";
        }
        if (user != "unset" && user != "-1" && user != "(unknown)") {
            bool is_number = !user.empty();
            for (char c : user) {
                if (!isdigit(c)) {
                    is_number = false;
                    break;
                }
            }
            if (is_number) {
                try {
                    long uid = stol(user);
                    if (uid == 0) {
                        return "root";
                    } else if (uid < 1000) {
                        return "uid_" + user;
                    } else if (uid < 100000) {
                        struct passwd* pw = getpwuid(uid);
                        if (pw != nullptr && pw->pw_name != nullptr) {
                            string username = pw->pw_name;
                            if (!username.empty()) {
                                return username;
                            }
                        }
                        return "uid_" + user;
                    } else {
                        return "unknown";
                    }
                } catch (...) {
                    return "uid_" + user;
                }
            } else if (!isTimestampOrInvalidUsername(user)) {
                return user;
            }
        }
    }
    if (log_line.find("firefox") != string::npos || 
        log_line.find("gnome-shell") != string::npos ||
        log_line.find("chrome") != string::npos) {
        size_t uid_pos = log_line.find("UID=\"");
        if (uid_pos != string::npos) {
            size_t start = uid_pos + 5;
            size_t end = log_line.find('"', start);
            if (end != string::npos) {
                string user = log_line.substr(start, end - start);
                if (!user.empty() && user != "unset" && user != "(unknown)" &&
                    !isTimestampOrInvalidUsername(user)) {
                    return user;
                }
            }
        }
        size_t auid_pos = log_line.find("AUID=\"");
        if (auid_pos != string::npos) {
            size_t start = auid_pos + 6;
            size_t end = log_line.find('"', start);
            if (end != string::npos) {
                string user = log_line.substr(start, end - start);
                if (!user.empty() && user != "unset" && user != "(unknown)" &&
                    !isTimestampOrInvalidUsername(user)) {
                    return user;
                }
            }
        }
        size_t last_quoted = log_line.rfind('"');
        if (last_quoted != string::npos && last_quoted > 10) {
            size_t second_last_quote = log_line.rfind('"', last_quoted - 1);
            if (second_last_quote != string::npos) {
                string potential_user = log_line.substr(second_last_quote + 1, 
                                                       last_quoted - second_last_quote - 1);
                if (!potential_user.empty() && potential_user.length() < 50 &&
                    potential_user != "root" && potential_user != "unset" &&
                    !isTimestampOrInvalidUsername(potential_user)) {
                    return potential_user;
                }
            }
        }
    }
    if (log_line.find("Failed password for ") != string::npos) {
        size_t start = log_line.find("Failed password for ") + 20;
        size_t end = log_line.find(" from ", start);
        if (end != string::npos) {
            string user = log_line.substr(start, end - start);
            if (!isTimestampOrInvalidUsername(user)) {
                return user;
            }
        }
    }
    if (log_line.find("Accepted password for ") != string::npos) {
        size_t start = log_line.find("Accepted password for ") + 22;
        size_t end = log_line.find(" ", start);
        if (end == string::npos) end = log_line.length();
        string user = log_line.substr(start, end - start);
        if (!isTimestampOrInvalidUsername(user)) {
            return user;
        }
    }
    if (log_line.find("Invalid user ") != string::npos) {
        size_t start = log_line.find("Invalid user ") + 13;
        size_t end = log_line.find(" ", start);
        if (end == string::npos) end = log_line.length();
        string potential_user = log_line.substr(start, end - start);
        if (!potential_user.empty() && !isTimestampOrInvalidUsername(potential_user)) {
            return potential_user;
        }
    }
    if (log_line.find("sudo:") != string::npos) {
        size_t user_pos = log_line.find("USER=");
        if (user_pos != string::npos) {
            size_t start = user_pos + 5;
            size_t end = log_line.find(" ", start);
            if (end == string::npos) end = log_line.find(";", start);
            if (end == string::npos) end = log_line.length();

            string user = log_line.substr(start, end - start);
            if (!isTimestampOrInvalidUsername(user)) {
                return user;
            }
        }

        if (log_line.find("session opened for user ") != string::npos) {
            size_t start = log_line.find("session opened for user ") + 24;
            size_t end = log_line.find(" ", start);
            if (end == string::npos) end = log_line.length();

            string user = log_line.substr(start, end - start);
            if (!isTimestampOrInvalidUsername(user)) {
                return user;
            }
        }
    }
    size_t user_eq_pos = log_line.find("user=");
    if (user_eq_pos != string::npos) {
        size_t start = user_eq_pos + 5;
        size_t end = log_line.find(" ", start);
        if (end == string::npos) end = log_line.length();

        string user = log_line.substr(start, end - start);
        if (!user.empty() && user != " " && user != "\n" && 
            !isTimestampOrInvalidUsername(user)) {
            return user;
        }
    }
    return "unknown";
}

string EventProcessor::extractProcess(const string& log_line) {
    regex auditd_exe_regex("\\bexe=\"([^\"]+)\"");
    smatch match;
    if (regex_search(log_line, match, auditd_exe_regex) && match.size() > 1) {
        string exe = match[1].str();
        size_t last_slash = exe.find_last_of('/');
        if (last_slash != string::npos) {
            string process = exe.substr(last_slash + 1);
            return process;
        }
        return exe;
    }
    regex syslog_process_regex("^(\\S+?)\\[\\d+\\]:");
    if (regex_search(log_line, match, syslog_process_regex) && match.size() > 1) {
        string process = match[1].str();
        return process;
    }
    if (log_line.find("COMMAND=") != string::npos) {
        size_t start = log_line.find("COMMAND=") + 8;
        string rest = log_line.substr(start);
        if (!rest.empty() && rest[0] == '"') {
            size_t end_quote = rest.find('"', 1);
            if (end_quote != string::npos) {
                string command = rest.substr(1, end_quote - 1);
                size_t space_pos = command.find(' ');
                if (space_pos != string::npos) {
                    command = command.substr(0, space_pos);
                }
                size_t slash_pos = command.find_last_of('/');
                if (slash_pos != string::npos) {
                    command = command.substr(slash_pos + 1);
                }
                return command;
            }
        }
    }
    if (log_line.find("sshd") != string::npos) {
        return "sshd";
    }
    if (log_line.find("sudo") != string::npos) {
        return "sudo";
    }
    if (log_line.find("login") != string::npos) {
        return "login";
    }
    if (log_line.find("bash") != string::npos || log_line.find(".bash_history") != string::npos) {
        return "bash";
    }
    size_t first_space = log_line.find(' ');
    if (first_space != string::npos && first_space > 0 && first_space < 50) {
        string potential_process = log_line.substr(0, first_space);
        if (!potential_process.empty() &&
            potential_process.find('[') == string::npos &&
            potential_process.find(':') == string::npos &&
            !isTimestampOrInvalidUsername(potential_process)) {
            return potential_process;
        }
    }
    return "unknown";
}

string EventProcessor::extractCommand(const string& log_line) {
    regex auditd_cmd_regex("\\bcmd=\"([^\"]+)\"");
    smatch match;
    if (regex_search(log_line, match, auditd_cmd_regex) && match.size() > 1) {
        return match[1].str();
    }
    if (log_line.find("/.bash_history") != string::npos) {
        return log_line;
    }
    if (log_line.find("COMMAND=") != string::npos) {
        size_t start = log_line.find("COMMAND=") + 8;
        size_t end = log_line.find(" ", start);
        if (end == string::npos) end = log_line.length();
        return log_line.substr(start, end - start);
    }
    return "";
}

string EventProcessor::extractAuditdField(const string& log_line, const string& field) {
    string pattern = "\\b" + field + "=([^\\s\"]+|\"[^\"]+\")";
    regex field_regex(pattern);
    smatch match;

    if (regex_search(log_line, match, field_regex) && match.size() > 1) {
        string value = match[1].str();
        if (value.length() >= 2) {
            if (value[0] == '"' && value[value.length()-1] == '"') {
                value = value.substr(1, value.length() - 2);
            }
            if (value[0] == '\'' && value[value.length()-1] == '\'') {
                value = value.substr(1, value.length() - 2);
            }
        }
        size_t pos = 0;
        while ((pos = value.find("\\\"", pos)) != string::npos) {
            value.replace(pos, 2, "\"");
            pos += 1;
        }
        
        return value;
    }

    return "";
}

string EventProcessor::extractTimestampFromLog(const string& source, const string& log_line) {
    if (source == "syslog" || source == "auth") {
        regex syslog_timestamp("^(\\w{3}\\s+\\d{1,2}\\s+\\d{2}:\\d{2}:\\d{2})");
        smatch match;
        if (regex_search(log_line, match, syslog_timestamp) && match.size() > 1) {
            string syslog_time = match[1].str();
            string iso_time = normalizeTimestamp(syslog_time);
            return iso_time;
        }
        regex iso_timestamp("(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2})");
        if (regex_search(log_line, match, iso_timestamp) && match.size() > 1) {
            string iso_time = match[1].str() + "Z";
            return iso_time;
        }
    }
    if (source == "auditd") {
        regex audit_timestamp("msg=audit\\((\\d+\\.\\d+):");
        smatch match;
        if (regex_search(log_line, match, audit_timestamp) && match.size() > 1) {
            string epoch_str = match[1].str();
            try {
                double epoch = stod(epoch_str);
                time_t t = static_cast<time_t>(epoch);
                struct tm* gm_time = gmtime(&t);
                char buffer[100];
                strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%SZ", gm_time);
                string iso_time = string(buffer);
                return iso_time;
            } catch (const exception& e) {
                cout << "[EXTRACT_TIMESTAMP] Failed to parse epoch: " << e.what() << endl;
            }
        }
        regex daemon_timestamp("msg=audit\\((\\d+\\.\\d+):\\d+\\)");
        if (regex_search(log_line, match, daemon_timestamp) && match.size() > 1) {
            string epoch_str = match[1].str();
            try {
                double epoch = stod(epoch_str);
                time_t t = static_cast<time_t>(epoch);
                struct tm* gm_time = gmtime(&t);
                char buffer[100];
                strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%SZ", gm_time);
                string iso_time = string(buffer);
                return iso_time;
            } catch (const exception& e) {
                cout << "[EXTRACT_TIMESTAMP] Failed to parse daemon epoch: " << e.what() << endl;
            }
        }
    }
    
    vector<regex> iso_patterns = {
        regex("(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}\\.\\d+[+-]\\d{2}:\\d{2})"),  
        regex("(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}\\.\\d+Z)"),  
        regex("(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z)"), 
        regex("(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2})"),  
        regex("(\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2})")   
    };
    
    for (const auto& pattern : iso_patterns) {
        smatch match;
        if (regex_search(log_line, match, pattern) && match.size() > 1) {
            string timestamp = match[1].str();
            if (timestamp.find('Z') == string::npos && 
                timestamp.find('+') == string::npos && 
                timestamp.find('-', 10) == string::npos) {
                if (timestamp.find('T') != string::npos || timestamp.find(' ') != string::npos) {
                    timestamp += "Z";
                }
            }
            return timestamp;
        }
    }
    return "";
}

string EventProcessor::normalizeTimestamp(const string& timestamp) {
    if (timestamp.empty()) {
        time_t now = time(nullptr);
        struct tm* gm_time = gmtime(&now);
        char buffer[100];
        strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%SZ", gm_time);
        return string(buffer);
    }
    if (timestamp.length() >= 20 && timestamp[4] == '-' && timestamp[7] == '-' &&
        timestamp[10] == 'T' && timestamp[13] == ':' && timestamp[16] == ':' &&
        timestamp[19] == 'Z') {
        return timestamp;
    }
    if (timestamp.length() >= 25 && timestamp.find('+') != string::npos) {
        size_t plus_pos = timestamp.find('+');
        if (plus_pos != string::npos && plus_pos > 19) {
            string datetime_part = timestamp.substr(0, plus_pos);
            size_t dot_pos = datetime_part.find('.');
            if (dot_pos != string::npos) {
                datetime_part = datetime_part.substr(0, dot_pos);
            }
            return datetime_part + "Z";
        }
    }
    if (timestamp.length() >= 19 && timestamp[4] == '-' && timestamp[7] == '-' &&
        timestamp[10] == 'T' && timestamp[13] == ':' && timestamp[16] == ':') {
        return timestamp + "Z";
    }
    if (timestamp.find('.') != string::npos) {
        try {
            double epoch = stod(timestamp);
            time_t t = static_cast<time_t>(epoch);
            struct tm* gm_time = gmtime(&t);
            char buffer[100];
            strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%SZ", gm_time);
            return string(buffer);
        } catch (...) {
        }
    }
    if (!timestamp.empty() && isdigit(timestamp[0])) {
        try {
            time_t t = static_cast<time_t>(stoll(timestamp));
            struct tm* gm_time = gmtime(&t);
            char buffer[100];
            strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%SZ", gm_time);
            return string(buffer);
        } catch (...) {
        }
    }
    struct tm tm_time = {};
    if (strptime(timestamp.c_str(), "%b %d %H:%M:%S", &tm_time)) {
        time_t now = time(nullptr);
        struct tm* current_tm = localtime(&now);

        tm_time.tm_year = current_tm->tm_year;
        tm_time.tm_mon = current_tm->tm_mon;
        tm_time.tm_isdst = -1;

        time_t event_time = mktime(&tm_time);
        if (event_time > now) {
            tm_time.tm_year = current_tm->tm_year - 1;
            event_time = mktime(&tm_time);
        }

        struct tm* gm_time = gmtime(&event_time);
        char buffer[100];
        strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%SZ", gm_time);
        return string(buffer);
    }

    time_t now = time(nullptr);
    struct tm* gm_time = gmtime(&now);
    char buffer[100];
    strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%SZ", gm_time);
    return string(buffer);
}

string EventProcessor::decodeProctitle(const string& proctitle) {
    bool is_hex = true;
    for (size_t i = 0; i < proctitle.length(); i++) {
        char c = proctitle[i];
        if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f'))) {
            is_hex = false;
            break;
        }
    }
    
    if (is_hex && proctitle.length() >= 2) {
        string decoded;
        for (size_t i = 0; i < proctitle.length(); i += 2) {
            if (i + 1 < proctitle.length()) {
                string hex_byte = proctitle.substr(i, 2);
                try {
                    int byte_value = stoi(hex_byte, nullptr, 16);
                    if (byte_value > 0 && byte_value < 128) { 
                        decoded += static_cast<char>(byte_value);
                    } else if (byte_value == 0) {
                        decoded += ' '; 
                    }
                } catch (...) {
                    return proctitle;
                }
            }
        }
        if (!decoded.empty()) {
            return decoded;
        }
    }
    return proctitle;
}

string EventProcessor::extractExecveCommand(const string& log_line) {
    vector<string> args;
    regex arg_regex("\\ba(\\d+)=\"([^\"]+)\"");
    smatch match;
    string search_line = log_line;
    map<int, string> arg_map;
    
    while (regex_search(search_line, match, arg_regex)) {
        int arg_num = stoi(match[1].str());
        string arg_value = match[2].str();
        arg_map[arg_num] = arg_value;
        search_line = match.suffix().str();
    }
    if (!arg_map.empty()) {
        string command;
        for (const auto& pair : arg_map) {
            if (!command.empty()) {
                command += " ";
            }
            command += pair.second;
        }
        return command;
    }
    regex arg_regex2("\\ba0=([^\\s\"]+)");
    if (regex_search(log_line, match, arg_regex2) && match.size() > 1) {
        string arg0 = match[1].str();
        if (arg0.length() >= 2 && arg0[0] == '"' && arg0[arg0.length()-1] == '"') {
            arg0 = arg0.substr(1, arg0.length() - 2);
        }
        return arg0;
    }
    return "";
}