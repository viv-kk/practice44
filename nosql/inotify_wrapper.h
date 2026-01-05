#ifndef INOTIFY_WRAPPER_H
#define INOTIFY_WRAPPER_H

#include <string>
#include <cstdint>
#include <unordered_map>  
#include "vector.h"
#include <sys/inotify.h>

class InotifyWrapper {
private:
    int inotify_fd;
    unordered_map<int, string> watch_descriptors;
    unordered_map<string, int> path_to_wd;
    
public:
    InotifyWrapper();
    ~InotifyWrapper();
    
    bool addWatch(const string& path, uint32_t mask);
    bool removeWatch(const string& path);
    Vector<pair<string, uint32_t>> readEvents(int timeout_ms = -1);
    int getFileDescriptor() const { return inotify_fd; }
    
    static const uint32_t DEFAULT_MASK = IN_MODIFY | IN_DELETE_SELF | IN_MOVE_SELF | IN_CREATE;
    
private:
    static const int EVENT_SIZE = sizeof(struct inotify_event);
    static const int BUF_LEN = 1024 * (EVENT_SIZE + 16);
};

#endif 