/**
 * Exam Integrity Client - Network Blocker
 *
 * This client blocks ALL network traffic using iptables (Linux) during
 * evaluations. StudentID is sent to the server for tracking.
 *
 * Supported Platforms: Linux, Windows, macOS
 */

#include <iostream>
#include <string>
#include <thread>
#include <atomic>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <chrono>

#ifdef _WIN32
    #define WIN32_LEAN_AND_MEAN
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <windows.h>
    #include <iphlpapi.h>
    #pragma comment(lib, "ws2_32.lib")
    #pragma comment(lib, "iphlpapi.lib")
#elif defined(__linux__)
    #include <fcntl.h>
    #include <unistd.h>
    #include <sys/ioctl.h>
    #include <linux/if.h>
    #include <linux/if_tun.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <sys/socket.h>
    #include <poll.h>
#elif defined(__APPLE__)
    #include <cstring>
    #include <fcntl.h>
    #include <unistd.h>
    #include <sys/ioctl.h>
    #include <sys/socket.h>
    #include <sys/sockio.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <net/if.h>
    #include <net/if_utun.h>
    #include <net/route.h>
    #include <poll.h>
#endif

// ============================================================================
// Configuration
// ============================================================================

struct ClientConfig {
    std::string server_host = "127.0.0.1";
    int server_port = 8888;
    std::string student_id;
    std::atomic<bool> running{true};
};

// Global atomic flag for graceful shutdown
static std::atomic<bool> g_shutdown_requested{false};
static std::atomic<int> g_signal_received{0};

// ============================================================================
// Signal Handler for Graceful Shutdown
// ============================================================================

void signal_handler(int signum) {
    g_signal_received.store(signum);
    g_shutdown_requested.store(true);
}

// ============================================================================
// Platform-Specific Network Blocker
// ============================================================================

#ifdef _WIN32
// Windows: Using netsh to block traffic

class NetworkBlockerWin {
private:
    bool rules_added = false;

public:
    bool initialize() {
        // Initialize Winsock
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            std::cerr << "[ERROR] WSAStartup failed\n";
            return false;
        }
        std::cout << "[*] Winsock initialized\n";
        return true;
    }

    bool block_all_traffic() {
        std::cout << "[*] Blocking all network traffic on Windows...\n";
        std::cout << "[!] Note: Requires administrator privileges.\n";

        // Block all outbound traffic except loopback using netsh
        system("netsh advfirewall firewall add rule name=\"ExamBlockOut\" dir=out action=block enable=yes 2>nul");
        system("netsh advfirewall firewall add rule name=\"ExamBlockIn\" dir=in action=block enable=yes 2>nul");

        // Allow loopback
        system("netsh advfirewall firewall add rule name=\"ExamAllowLoopback\" dir=out action=allow enable=yes localip=127.0.0.1 remoteip=127.0.0.1 2>nul");

        rules_added = true;
        std::cout << "[*] Firewall rules applied - all external traffic blocked\n";
        return true;
    }

    void restore_traffic() {
        std::cout << "[*] Restoring network firewall rules...\n";

        // Delete our rules
        system("netsh advfirewall firewall delete rule name=\"ExamBlockOut\" 2>nul");
        system("netsh advfirewall firewall delete rule name=\"ExamBlockIn\" 2>nul");
        system("netsh advfirewall firewall delete rule name=\"ExamAllowLoopback\" 2>nul");

        WSACleanup();
    }

    void cleanup() {
        restore_traffic();
    }
};

#elif defined(__linux__)
// Linux: Using iptables to DROP all packets (most reliable method)

class NetworkBlockerLinux {
private:
    bool rules_added = false;
    std::string server_ip;
    int server_port;

public:
    void set_server_info(const std::string& ip, int port) {
        server_ip = ip;
        server_port = port;
    }

    bool initialize() {
        return true;
    }

    bool block_all_traffic() {
        std::cout << "[*] Blocking all network traffic on Linux using iptables...\n";
        std::cout << "[!] Note: Requires ROOT privileges.\n";

        // Backup current iptables rules
        system("iptables-save > /tmp/exam_iptables_backup 2>/dev/null");

        // FLUSH all existing rules first - critical for proper ordering
        system("iptables -F 2>/dev/null");
        system("iptables -X 2>/dev/null");  // Delete custom chains
        system("iptables -t nat -F 2>/dev/null");
        system("iptables -t nat -X 2>/dev/null");
        system("iptables -t mangle -F 2>/dev/null");
        system("iptables -t mangle -X 2>/dev/null");

        // Set default policies to DROP (most secure - drops anything not explicitly allowed)
        system("iptables -P INPUT DROP 2>/dev/null");
        system("iptables -P OUTPUT DROP 2>/dev/null");
        system("iptables -P FORWARD DROP 2>/dev/null");

        // Allow loopback interface (must come before DROP rules)
        system("iptables -A INPUT -i lo -j ACCEPT 2>/dev/null");
        system("iptables -A OUTPUT -o lo -j ACCEPT 2>/dev/null");

        // Allow established/related connections (for the server connection)
        system("iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null");
        system("iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null");

        // Allow connection to our exam server
        std::string cmd = "iptables -A OUTPUT -d " + server_ip +
                          " -p tcp --dport " + std::to_string(server_port) +
                          " -j ACCEPT 2>/dev/null";
        system(cmd.c_str());

        rules_added = true;
        std::cout << "[*] iptables rules applied - ALL network traffic BLOCKED\n";
        std::cout << "[*] Only loopback and exam server connection allowed\n";
        return true;
    }

    void restore_traffic() {
        std::cout << "[*] Restoring network firewall rules...\n";

        // Restore from backup
        if (rules_added) {
            system("iptables -F 2>/dev/null");  // Flush all rules
            system("iptables -X 2>/dev/null");  // Delete custom chains

            // Restore backup if exists
            system("if [ -f /tmp/exam_iptables_backup ]; then iptables-restore < /tmp/exam_iptables_backup 2>/dev/null; fi");
        }

        rules_added = false;
    }

    void cleanup() {
        restore_traffic();
    }
};

#elif defined(__APPLE__)
// macOS: Using pf (packet filter) firewall

class NetworkBlockerMac {
private:
    bool pf_enabled = false;
    std::string server_ip;
    int server_port;

public:
    void set_server_info(const std::string& ip, int port) {
        server_ip = ip;
        server_port = port;
    }

    bool initialize() {
        return true;
    }

    bool block_all_traffic() {
        std::cout << "[*] Blocking all network traffic on macOS using pf...\n";
        std::cout << "[!] Note: Requires ROOT privileges.\n";

        // Backup current pf rules
        system("pfctl -sr > /tmp/exam_pf_backup 2>/dev/null");

        // Create pf rules to block all traffic
        const char* pf_rules =
            "block all\n"
            "pass in on lo0\n"
            "pass out on lo0\n";

        // Write rules to temp file
        FILE* f = fopen("/tmp/exam_pf_rules", "w");
        if (f) {
            fprintf(f, "%s", pf_rules);
            fclose(f);
        }

        // Enable pf with our rules
        system("pfctl -ef /tmp/exam_pf_rules 2>/dev/null");

        pf_enabled = true;
        std::cout << "[*] pf firewall enabled - ALL network traffic BLOCKED\n";
        return true;
    }

    void restore_traffic() {
        std::cout << "[*] Restoring network firewall rules...\n";

        if (pf_enabled) {
            // Disable pf
            system("pfctl -df 2>/dev/null");

            // Restore backup if exists
            system("if [ -f /tmp/exam_pf_backup ]; then pfctl -f /tmp/exam_pf_backup 2>/dev/null; fi");
        }

        pf_enabled = false;
    }

    void cleanup() {
        restore_traffic();
    }
};

#endif

// ============================================================================
// Network Communication with Server
// ============================================================================

class ServerConnection {
private:
    ClientConfig& config;

#ifdef _WIN32
    SOCKET sock = INVALID_SOCKET;
#else
    int sock = -1;
#endif

public:
    ServerConnection(ClientConfig& cfg) : config(cfg) {}

    bool connect_to_server() {
        std::cout << "[*] Connecting to server at " << config.server_host
                  << ":" << config.server_port << "...\n";

#ifdef _WIN32
        sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET) {
            std::cerr << "[ERROR] Socket creation failed\n";
            return false;
        }

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(config.server_port);
        inet_pton(AF_INET, config.server_host.c_str(), &addr.sin_addr);

        if (connect(sock, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
            std::cerr << "[ERROR] Connection failed: " << WSAGetLastError() << "\n";
            closesocket(sock);
            return false;
        }
#else
        sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) {
            std::cerr << "[ERROR] Socket creation failed\n";
            return false;
        }

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(config.server_port);
        inet_pton(AF_INET, config.server_host.c_str(), &addr.sin_addr);

        if (connect(sock, (sockaddr*)&addr, sizeof(addr)) < 0) {
            std::cerr << "[ERROR] Connection failed: " << strerror(errno) << "\n";
            close(sock);
            return false;
        }
#endif

        std::cout << "[+] Connected to server\n";
        return true;
    }

    bool send_student_id(const std::string& id) {
        std::string msg = "STUDENT_ID:" + id + "\n";

#ifdef _WIN32
        int result = send(sock, msg.c_str(), msg.length(), 0);
        if (result == SOCKET_ERROR) {
            std::cerr << "[ERROR] Send failed: " << WSAGetLastError() << "\n";
            return false;
        }
#else
        ssize_t result = write(sock, msg.c_str(), msg.length());
        if (result < 0) {
            std::cerr << "[ERROR] Send failed: " << strerror(errno) << "\n";
            return false;
        }
#endif

        std::cout << "[+] StudentID sent to server: " << id << "\n";
        return true;
    }

    bool listen_for_commands() {
        std::cout << "[*] Listening for server commands...\n";
        char buffer[1024];

        while (!g_shutdown_requested.load() && config.running.load()) {
            // Use poll with timeout so signals can interrupt
#ifdef _WIN32
            // Windows: use select with timeout
            fd_set read_fds;
            FD_ZERO(&read_fds);
            FD_SET(sock, &read_fds);

            struct timeval timeout;
            timeout.tv_sec = 1;  // 1 second timeout
            timeout.tv_usec = 0;

            int result = select(0, &read_fds, nullptr, nullptr, &timeout);
            if (result == SOCKET_ERROR) {
                if (g_shutdown_requested.load()) break;
                std::cerr << "[ERROR] Select failed: " << WSAGetLastError() << "\n";
                return false;
            }
            if (result == 0) {
                // Timeout - check shutdown flag and continue
                continue;
            }
            if (FD_ISSET(sock, &read_fds)) {
                int n = recv(sock, buffer, sizeof(buffer) - 1, 0);
                if (n == SOCKET_ERROR) {
                    std::cerr << "[ERROR] Recv failed: " << WSAGetLastError() << "\n";
                    return false;
                }
                if (n == 0) {
                    std::cout << "[!] Server disconnected\n";
                    return false;
                }

                buffer[n] = '\0';
                std::string cmd(buffer);

                // Trim newline
                while (!cmd.empty() && (cmd.back() == '\n' || cmd.back() == '\r')) {
                    cmd.pop_back();
                }

                std::cout << "[*] Received command: " << cmd << "\n";

                if (cmd == "STOP" || cmd == "TERMINATE" || cmd == "EXIT") {
                    std::cout << "[!] Server requested stop. Shutting down...\n";
                    config.running.store(false);
                    g_shutdown_requested.store(true);
                    return true;
                }
            }
#else
            // Unix: use poll with timeout
            struct pollfd pfd;
            pfd.fd = sock;
            pfd.events = POLLIN;

            int result = poll(&pfd, 1, 1000);  // 1 second timeout

            if (result < 0) {
                if (errno == EINTR) {
                    // Interrupted by signal - check flag
                    if (g_shutdown_requested.load()) break;
                    continue;
                }
                std::cerr << "[ERROR] Poll failed: " << strerror(errno) << "\n";
                return false;
            }
            if (result == 0) {
                // Timeout - check shutdown flag and continue
                continue;
            }
            if (pfd.revents & POLLIN) {
                ssize_t n = read(sock, buffer, sizeof(buffer) - 1);
                if (n < 0) {
                    if (errno == EINTR) {
                        if (g_shutdown_requested.load()) break;
                        continue;
                    }
                    std::cerr << "[ERROR] Read failed: " << strerror(errno) << "\n";
                    return false;
                }
                if (n == 0) {
                    std::cout << "[!] Server disconnected\n";
                    return false;
                }

                buffer[n] = '\0';
                std::string cmd(buffer);

                // Trim newline
                while (!cmd.empty() && (cmd.back() == '\n' || cmd.back() == '\r')) {
                    cmd.pop_back();
                }

                std::cout << "[*] Received command: " << cmd << "\n";

                if (cmd == "STOP" || cmd == "TERMINATE" || cmd == "EXIT") {
                    std::cout << "[!] Server requested stop. Shutting down...\n";
                    config.running.store(false);
                    g_shutdown_requested.store(true);
                    return true;
                }
            }
#endif
        }

        return true;
    }

    void close_connection() {
#ifdef _WIN32
        if (sock != INVALID_SOCKET) {
            closesocket(sock);
            sock = INVALID_SOCKET;
        }
#else
        if (sock >= 0) {
            close(sock);
            sock = -1;
        }
#endif
    }
};

// ============================================================================
// User Input: Get StudentID
// ============================================================================

std::string get_student_id() {
    std::string id;

    std::cout << "\n";
    std::cout << "============================================================\n";
    std::cout << "           EXAM INTEGRITY CLIENT - NETWORK BLOCKER          \n";
    std::cout << "============================================================\n";
    std::cout << "\n";
    std::cout << "[!] WARNING: This client will BLOCK all network traffic\n";
    std::cout << "    during your evaluation. No internet access will be\n";
    std::cout << "    available until the exam is complete.\n";
    std::cout << "\n";
    std::cout << "    Running this program requires ROOT/Administrator.\n";
    std::cout << "\n";
    std::cout << "------------------------------------------------------------\n";
    std::cout << "\n";

    std::cout << "Enter your Student ID: ";
    std::getline(std::cin, id);

    if (id.empty()) {
        std::cerr << "[ERROR] Student ID cannot be empty.\n";
        return "";
    }

    std::cout << "\n";
    std::cout << "[?] You entered: " << id << "\n";
    std::cout << "[?] Proceed with network blocking? (yes/no): ";

    std::string confirm;
    std::getline(std::cin, confirm);

    if (confirm != "yes" && confirm != "y") {
        std::cout << "[!] Aborted by user.\n";
        return "";
    }

    return id;
}

// ============================================================================
// Check if network is actually blocked (Linux only)
// ============================================================================

#ifdef __linux__
void verify_network_blocked() {
    std::cout << "[*] Verifying network is blocked...\n";

    // Try to ping external host (should fail)
    int result = system("ping -c 1 -W 1 8.8.8.8 > /dev/null 2>&1");
    if (result != 0) {
        std::cout << "[+] Network is BLOCKED (ping to 8.8.8.8 failed)\n";
    } else {
        std::cout << "[!] WARNING: Network may not be fully blocked (ping succeeded)\n";
    }
}
#endif

// ============================================================================
// Main Entry Point
// ============================================================================

int main(int argc, char* argv[]) {
    // Setup signal handlers
    struct sigaction sa;
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);

#ifdef _WIN32
    signal(SIGBREAK, signal_handler);
#endif

    std::cout << "[*] Exam Integrity Client starting...\n";

    // Get StudentID from user
    std::string student_id = get_student_id();
    if (student_id.empty()) {
        return 1;
    }

    // Initialize configuration
    ClientConfig config;
    config.student_id = student_id;

    // Allow server override via command line
    if (argc >= 2) {
        config.server_host = argv[1];
    }
    if (argc >= 3) {
        config.server_port = std::atoi(argv[2]);
    }

    // Initialize platform-specific network blocker
    bool blocker_init = false;

#ifdef _WIN32
    NetworkBlockerWin blocker;
    blocker.set_server_info(config.server_host, config.server_port);
    blocker_init = blocker.initialize();
#elif defined(__linux__)
    NetworkBlockerLinux blocker;
    blocker.set_server_info(config.server_host, config.server_port);
    blocker_init = blocker.initialize();
#elif defined(__APPLE__)
    NetworkBlockerMac blocker;
    blocker.set_server_info(config.server_host, config.server_port);
    blocker_init = blocker.initialize();
#endif

    if (!blocker_init) {
        std::cerr << "[ERROR] Failed to initialize network blocker.\n";
        std::cerr << "[!] Make sure to run this program as ROOT/Administrator.\n";
        return 1;
    }

    // Block all network traffic
    if (!blocker.block_all_traffic()) {
        std::cerr << "[ERROR] Failed to block network traffic.\n";
        return 1;
    }

#ifdef __linux__
    // Verify network is actually blocked
    verify_network_blocked();
#endif

    // Connect to server
    ServerConnection server(config);
    if (!server.connect_to_server()) {
        std::cerr << "[ERROR] Failed to connect to server.\n";
        std::cerr << "[!] Check if server is running at " << config.server_host
                  << ":" << config.server_port << "\n";
        blocker.cleanup();
        return 1;
    }

    // Send StudentID to server
    if (!server.send_student_id(config.student_id)) {
        std::cerr << "[ERROR] Failed to send StudentID.\n";
        server.close_connection();
        blocker.cleanup();
        return 1;
    }

    std::cout << "\n";
    std::cout << "============================================================\n";
    std::cout << "  EXAM MODE ACTIVE - Network traffic is BLOCKED\n";
    std::cout << "  Student ID: " << config.student_id << "\n";
    std::cout << "  Press Ctrl+C to stop (or wait for server STOP command)\n";
    std::cout << "============================================================\n";
    std::cout << "\n";

    // Listen for server commands (with interruptible polling)
    server.listen_for_commands();

    // Cleanup
    std::cout << "[*] Cleaning up...\n";

    server.close_connection();
    blocker.cleanup();

    std::cout << "[+] Client stopped. Network should be restored.\n";
    std::cout << "[!] If network is not working, please run:\n";
    std::cout << "    Linux:  iptables -F && iptables -X\n";
    std::cout << "    macOS:  pfctl -df\n";
    std::cout << "    Windows: netsh advfirewall reset\n";

    return 0;
}
