#ifndef EVENT_PROCESSOR_H
#define EVENT_PROCESSOR_H

#include "HashMap.h"
#include "vector.h"
#include <string>

struct SecurityEvent;
string generateEventId(const SecurityEvent& event);
class EventProcessor {
private:
    Vector<string> exclude_patterns;
    void processAuditdDetails(const string& log_line, SecurityEvent& event);
    void processSyslogDetails(const string& log_line, SecurityEvent& event);
    void processBashHistoryDetails(const string& log_line,
                                   SecurityEvent& event,
                                   const string& username);

public:
    EventProcessor(const Vector<string>& filters);

    SecurityEvent processLogLine(const string& source,
                               const string& log_line,
                               const string& agent_id);

    SecurityEvent processEvent(SecurityEvent& base_event,
                              const string& log_line,
                              const string& agent_id);

    SecurityEvent processAuditdLog(const string& log_line, const string& agent_id);
    SecurityEvent processSyslog(const string& log_line, const string& agent_id);
    SecurityEvent processBashHistory(const string& log_line, const string& agent_id,
                                   const string& username);
    string normalizeTimestamp(const string& timestamp);
    void testParsing();
    void validateEvent(const SecurityEvent& event, const string& context = "");

    private:
    bool shouldExclude(const string& log_line);
    string determineEventType(const string& source, const string& log_line);
    string determineSeverity(const string& event_type, const string& log_line);
    string extractUser(const string& log_line);
    string extractProcess(const string& log_line);
    string extractCommand(const string& log_line);
    string extractAuditdField(const string& log_line, const string& field);
    string extractSyslogUser(const string& log_line);
    string validateAndFixUsername(const string& username, const string& log_line);
    string extractTimestampFromLog(const string& source, const string& log_line);
    bool isTimestampOrInvalidUsername(const string& str);
    string decodeProctitle(const string& proctitle);
    string extractExecveCommand(const string& log_line);
};

#endif