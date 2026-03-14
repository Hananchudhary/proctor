/**
 * Exam Integrity Server - Network Blocker Controller
 *
 * This server manages connections from student clients, tracks their
 * StudentIDs, and can send STOP commands to terminate their network
 * blocking sessions.
 *
 * Features:
 *   - Accept multiple client connections
 *   - Track StudentID and connection status
 *   - Interactive dashboard to view/stop students
 *   - Send STOP command to specific or all clients
 *
 * Supported Platforms: Linux, Windows, macOS
 */

#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <thread>
#include <mutex>
#include <atomic>
#include <sstream>
#include <algorithm>
#include <csignal>
#include <iomanip>
#include <iomanip>

#ifdef _WIN32
    #define WIN32_LEAN_AND_MEAN
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <windows.h>
    #pragma comment(lib, "ws2_32.lib")
#else
    #include <cstring>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    #include <fcntl.h>
    #include <errno.h>
    #include <sys/select.h>
#endif

// ============================================================================
// Configuration
// ============================================================================

struct ServerConfig {
    int port = 8888;
    int max_clients = 100;
    std::atomic<bool> running{true};
};

// ============================================================================
// Client Connection Info
// ============================================================================

struct ClientInfo {
    int client_id;
    std::string student_id;
    std::string ip_address;
    int port;
#ifdef _WIN32
    SOCKET socket;
#else
    int socket;
#endif
    bool is_active;
    std::chrono::steady_clock::time_point connected_at;

    ClientInfo()
        : client_id(0), is_active(false), socket(0) {}
};

// ============================================================================
// Global State
// ============================================================================

static std::map<int, ClientInfo> g_clients;
static std::mutex g_clients_mutex;
static std::atomic<int> g_next_client_id{1};
static ServerConfig g_config;

// ============================================================================
// Signal Handler
// ============================================================================

void signal_handler(int signum) {
    std::cout << "\n[!] Signal " << signum << " received. Shutting down server...\n";
    g_config.running.store(false);
}

// ============================================================================
// Platform-Specific Socket Helpers
// ============================================================================

#ifdef _WIN32
    typedef SOCKET socket_t;
    #define INVALID_SOCKET_HANDLE INVALID_SOCKET
    #define CLOSE_SOCKET(s) closesocket(s)
    #define SOCKET_ERROR_CODE WSAGetLastError()
#else
    typedef int socket_t;
    #define INVALID_SOCKET_HANDLE -1
    #define CLOSE_SOCKET(s) close(s)
    #define SOCKET_ERROR_CODE errno
#endif

// ============================================================================
// Server Class
// ============================================================================

class ExamServer {
private:
    socket_t server_socket = INVALID_SOCKET_HANDLE;
    ServerConfig& config;

public:
    ExamServer(ServerConfig& cfg) : config(cfg) {}

    bool initialize() {
        std::cout << "[*] Initializing Exam Integrity Server...\n";

#ifdef _WIN32
        // Initialize Winsock
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            std::cerr << "[ERROR] WSAStartup failed: " << WSAGetLastError() << "\n";
            return false;
        }
        std::cout << "[*] Winsock initialized\n";
#endif

        // Create socket
        server_socket = socket(AF_INET, SOCK_STREAM, 0);
        if (server_socket == INVALID_SOCKET_HANDLE) {
            std::cerr << "[ERROR] Socket creation failed\n";
            return false;
        }

        // Set socket options (reuse address)
        int opt = 1;
        setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR,
                   reinterpret_cast<const char*>(&opt), sizeof(opt));

        // Bind to address
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(config.port);

        if (bind(server_socket, (sockaddr*)&addr, sizeof(addr)) < 0) {
            std::cerr << "[ERROR] Bind failed on port " << config.port << "\n";
            return false;
        }

        // Listen for connections
        if (listen(server_socket, config.max_clients) < 0) {
            std::cerr << "[ERROR] Listen failed\n";
            return false;
        }

        std::cout << "[+] Server listening on port " << config.port << "\n";
        return true;
    }

    void accept_clients() {
        std::cout << "[*] Waiting for client connections...\n";

        // Set non-blocking for all platforms
#ifdef _WIN32
        u_long mode = 1;
        ioctlsocket(server_socket, FIONBIO, &mode);
#else
        int flags = fcntl(server_socket, F_GETFL, 0);
        fcntl(server_socket, F_SETFL, flags | O_NONBLOCK);
#endif

        while (config.running.load()) {
            sockaddr_in client_addr{};
            socklen_t client_len = sizeof(client_addr);

#ifdef _WIN32
            fd_set read_fds;
            FD_ZERO(&read_fds);
            FD_SET(server_socket, &read_fds);

            struct timeval timeout;
            timeout.tv_sec = 1;
            timeout.tv_usec = 0;

            int select_result = select(0, &read_fds, nullptr, nullptr, &timeout);
            if (select_result > 0 && FD_ISSET(server_socket, &read_fds)) {
#endif

            socket_t client_socket = accept(server_socket, (sockaddr*)&client_addr, &client_len);

            if (client_socket == INVALID_SOCKET_HANDLE) {
#ifdef _WIN32
                if (!config.running.load()) break;
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                continue;
#else
                if (errno == EWOULDBLOCK || errno == EAGAIN) {
                    if (!config.running.load()) break;
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                    continue;
                }
                std::cerr << "[ERROR] Accept failed: " << strerror(errno) << "\n";
                continue;
#endif
            }

            // Get client info
            char client_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
            int client_port = ntohs(client_addr.sin_port);

            std::cout << "[+] New connection from " << client_ip << ":" << client_port << "\n";

            // Create client info
            int client_id = g_next_client_id.fetch_add(1);
            ClientInfo info;
            info.client_id = client_id;
            info.socket = client_socket;
            info.ip_address = client_ip;
            info.port = client_port;
            info.is_active = true;
            info.connected_at = std::chrono::steady_clock::now();

            // Store in map
            {
                std::lock_guard<std::mutex> lock(g_clients_mutex);
                g_clients[client_id] = info;
            }

            // Start client handler thread
            std::thread(&ExamServer::handle_client, this, client_id).detach();

#ifdef _WIN32
            }
#endif
        }
    }

    void handle_client(int client_id) {
        ClientInfo* info = nullptr;
        {
            std::lock_guard<std::mutex> lock(g_clients_mutex);
            auto it = g_clients.find(client_id);
            if (it == g_clients.end()) {
                return;
            }
            info = &it->second;
        }

        char buffer[1024];
        bool got_student_id = false;

        while (config.running.load() && info->is_active) {
            int n = recv(info->socket, buffer, sizeof(buffer) - 1, 0);

            if (n <= 0) {
                std::cout << "[!] Client " << client_id << " disconnected\n";
                break;
            }

            buffer[n] = '\0';
            std::string msg(buffer);

            // Trim trailing whitespace
            while (!msg.empty() && (msg.back() == '\n' || msg.back() == '\r' || msg.back() == ' ')) {
                msg.pop_back();
            }

            std::cout << "[Client " << client_id << "] Received: " << msg << "\n";

            // Parse message
            if (msg.rfind("STUDENT_ID:", 0) == 0) {
                std::string student_id = msg.substr(11);
                info->student_id = student_id;
                got_student_id = true;

                std::cout << "[Client " << client_id << "] StudentID: " << student_id << "\n";

                // Update client info in map
                {
                    std::lock_guard<std::mutex> lock(g_clients_mutex);
                    g_clients[client_id] = *info;
                }
            }
        }

        // Mark as inactive
        info->is_active = false;
        CLOSE_SOCKET(info->socket);

        std::cout << "[!] Client " << client_id << " (" << info->student_id << ") disconnected\n";
    }

    bool send_stop_command(int client_id) {
        std::lock_guard<std::mutex> lock(g_clients_mutex);
        auto it = g_clients.find(client_id);
        if (it == g_clients.end() || !it->second.is_active) {
            std::cerr << "[ERROR] Client " << client_id << " not found or inactive\n";
            return false;
        }

        const char* stop_msg = "STOP\n";
        int result = send(it->second.socket, stop_msg, strlen(stop_msg), 0);

        if (result < 0) {
            std::cerr << "[ERROR] Failed to send STOP to client " << client_id << "\n";
            return false;
        }

        std::cout << "[+] STOP command sent to client " << client_id
                  << " (Student: " << it->second.student_id << ")\n";
        return true;
    }

    bool send_stop_all() {
        std::lock_guard<std::mutex> lock(g_clients_mutex);
        int count = 0;

        for (auto& [id, info] : g_clients) {
            if (info.is_active) {
                const char* stop_msg = "STOP\n";
                int result = send(info.socket, stop_msg, strlen(stop_msg), 0);
                if (result >= 0) {
                    std::cout << "[+] STOP sent to client " << id
                              << " (Student: " << info.student_id << ")\n";
                    count++;
                }
            }
        }

        std::cout << "[+] STOP command sent to " << count << " active clients\n";
        return count > 0;
    }

    void show_dashboard() {
        std::lock_guard<std::mutex> lock(g_clients_mutex);

        std::cout << "\n";
        std::cout << "============================================================\n";
        std::cout << "                  EXAM INTEGRITY SERVER                     \n";
        std::cout << "                      Student Dashboard                     \n";
        std::cout << "============================================================\n";
        std::cout << "\n";

        if (g_clients.empty()) {
            std::cout << "  No clients connected.\n";
        } else {
            std::cout << "  ID  | Student ID        | IP Address       | Port  | Status\n";
            std::cout << "------|-------------------|------------------|-------|-------\n";

            for (const auto& [id, info] : g_clients) {
                std::cout << "  " << std::setw(4) << id << " | "
                          << std::setw(17) << info.student_id << " | "
                          << std::setw(16) << info.ip_address << " | "
                          << std::setw(5) << info.port << " | "
                          << (info.is_active ? "ACTIVE" : "DISCONNECTED") << "\n";
            }
        }

        std::cout << "\n";
        std::cout << "  Total clients: " << g_clients.size() << "\n";
        std::cout << "  Active clients: ";
        int active = 0;
        for (const auto& [id, info] : g_clients) {
            if (info.is_active) active++;
        }
        std::cout << active << "\n";
        std::cout << "============================================================\n";
        std::cout << "\n";
    }

    void cleanup() {
        std::cout << "[*] Cleaning up server...\n";

        // Close all client sockets
        {
            std::lock_guard<std::mutex> lock(g_clients_mutex);
            for (auto& [id, info] : g_clients) {
                if (info.socket != INVALID_SOCKET_HANDLE) {
                    CLOSE_SOCKET(info.socket);
                }
            }
            g_clients.clear();
        }

        if (server_socket != INVALID_SOCKET_HANDLE) {
            CLOSE_SOCKET(server_socket);
            server_socket = INVALID_SOCKET_HANDLE;
        }

#ifdef _WIN32
        WSACleanup();
#endif

        std::cout << "[+] Server stopped.\n";
    }
};

// ============================================================================
// Interactive Command Loop
// ============================================================================

void print_help() {
    std::cout << "\n";
    std::cout << "Available Commands:\n";
    std::cout << "  dashboard     - Show all connected students\n";
    std::cout << "  stop <id>     - Stop specific client by ID\n";
    std::cout << "  stopall       - Stop all active clients\n";
    std::cout << "  list          - Alias for dashboard\n";
    std::cout << "  help          - Show this help\n";
    std::cout << "  quit          - Shutdown server and exit\n";
    std::cout << "\n";
}

void interactive_loop(ExamServer& server) {
    std::cout << "\n";
    std::cout << "[*] Entering interactive command mode.\n";
    std::cout << "[*] Type 'help' for available commands.\n";
    std::cout << "\n";

    std::string line;
    while (g_config.running.load()) {
        std::cout << "server> ";
        std::getline(std::cin, line);

        // Parse command
        std::istringstream iss(line);
        std::string cmd;
        iss >> cmd;

        if (cmd.empty()) continue;

        // Convert to lowercase
        std::transform(cmd.begin(), cmd.end(), cmd.begin(), ::tolower);

        if (cmd == "dashboard" || cmd == "list") {
            server.show_dashboard();
        }
        else if (cmd == "stop") {
            int client_id;
            if (iss >> client_id) {
                server.send_stop_command(client_id);
            } else {
                std::cerr << "[ERROR] Usage: stop <client_id>\n";
            }
        }
        else if (cmd == "stopall") {
            server.send_stop_all();
        }
        else if (cmd == "help") {
            print_help();
        }
        else if (cmd == "quit" || cmd == "exit") {
            std::cout << "[*] Shutting down...\n";
            g_config.running.store(false);
            break;
        }
        else {
            std::cerr << "[ERROR] Unknown command: " << cmd << "\n";
            std::cerr << "      Type 'help' for available commands.\n";
        }
    }
}

// ============================================================================
// Main Entry Point
// ============================================================================

int main(int argc, char* argv[]) {
    // Setup signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

#ifdef _WIN32
    signal(SIGBREAK, signal_handler);
#endif

    // Parse command line args
    int port = 8888;
    if (argc >= 2) {
        port = std::atoi(argv[1]);
    }

    g_config.port = port;

    std::cout << "\n";
    std::cout << "============================================================\n";
    std::cout << "           EXAM INTEGRITY SERVER - NETWORK BLOCKER          \n";
    std::cout << "============================================================\n";
    std::cout << "\n";
    std::cout << "[*] Server port: " << port << "\n";
    std::cout << "[*] Max clients: " << g_config.max_clients << "\n";
    std::cout << "\n";

    // Initialize server
    ExamServer server(g_config);
    if (!server.initialize()) {
        std::cerr << "[ERROR] Failed to initialize server.\n";
        std::cerr << "[!] Check if port " << port << " is already in use.\n";
        return 1;
    }

    // Start client acceptor thread
    std::thread acceptor_thread([&server]() {
        server.accept_clients();
    });

    // Run interactive command loop
    interactive_loop(server);

    // Wait for acceptor thread
    g_config.running.store(false);
    if (acceptor_thread.joinable()) {
        acceptor_thread.join();
    }

    // Cleanup
    server.cleanup();

    return 0;
}
