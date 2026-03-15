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

static std::atomic<bool> g_shutdown_requested{false};
static std::atomic<int>  g_signal_received{0};

// ============================================================================
// Signal Handler
// ============================================================================

void signal_handler(int signum) {
    g_signal_received.store(signum);
    g_shutdown_requested.store(true);
}

// ============================================================================
// Platform-Specific Network Blocker
// ============================================================================

#ifdef _WIN32

class NetworkBlockerWin {
private:
    bool rules_added = false;
public:
    void set_server_info(const std::string&, int) {}

    bool initialize() {
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

        system("netsh advfirewall firewall add rule name=\"ExamBlockOut\" dir=out action=block enable=yes 2>nul");
        system("netsh advfirewall firewall add rule name=\"ExamBlockIn\"  dir=in  action=block enable=yes 2>nul");
        system("netsh advfirewall firewall add rule name=\"ExamAllowLoopback\" dir=out action=allow enable=yes localip=127.0.0.1 remoteip=127.0.0.1 2>nul");

        rules_added = true;
        std::cout << "[*] Firewall rules applied - all external traffic blocked\n";
        return true;
    }

    void restore_traffic() {
        std::cout << "[*] Restoring network firewall rules...\n";
        system("netsh advfirewall firewall delete rule name=\"ExamBlockOut\"      2>nul");
        system("netsh advfirewall firewall delete rule name=\"ExamBlockIn\"       2>nul");
        system("netsh advfirewall firewall delete rule name=\"ExamAllowLoopback\" 2>nul");
        WSACleanup();
    }

    void cleanup() { restore_traffic(); }
};

#elif defined(__linux__)

// ============================================================================
// Linux Network Blocker — nftables-first with iptables fallback
//
// WHY THE PREVIOUS VERSION STILL ALLOWED PING:
//
// Modern Linux distros (Ubuntu 20.04+, Debian 10+, Fedora 32+) use nftables
// as the real kernel firewall. The `iptables` command is just a compatibility
// shim (iptables-nft) that inserts rules into a special nftables table called
// "ip filter". However:
//
//   1. ufw / firewalld / the distro's own nftables rules live in SEPARATE
//      nftables tables (e.g. "inet firewalld", "inet ufw") that run at a
//      HIGHER or EQUAL priority and can independently allow traffic.
//
//   2. nftables processes all matching tables in order of priority. If ANY
//      table accepts the packet, it's accepted — even if your iptables DROP
//      rules exist in a different table.
//
//   3. Result: your iptables DROP rules are in the "ip filter" table but ufw's
//      ACCEPT for ICMP is in the "ip ufw-before" table. The ping gets accepted
//      before it ever reaches your DROP rule.
//
// THE FIX — three-layer approach:
//
//   Layer 1: Disable ufw and stop firewalld so their tables are gone entirely.
//   Layer 2: Write a native nftables ruleset with a high-priority table that
//            drops everything except loopback + the exam server TCP connection.
//            Using nftables directly (not the iptables shim) ensures our rules
//            are in the SAME namespace as any remaining system rules and
//            priority gives us first say.
//   Layer 3: Also set iptables default policies to DROP as a belt-and-suspenders
//            measure for kernels where nftables isn't available.
//
// The nftables ruleset uses priority 0 (filter level) with a base chain that
// explicitly drops all traffic, then whitelists only what we need. ICMP is
// never whitelisted so it simply hits the drop policy.
// ============================================================================

// Helper: run a command and return its exit code
static int run_cmd(const char* cmd) {
    return system(cmd);
}

// Helper: run a command built from a string
static int run_cmd(const std::string& cmd) {
    return system(cmd.c_str());
}

// Helper: check if a program exists in PATH
static bool program_exists(const char* name) {
    std::string check = std::string("command -v ") + name + " > /dev/null 2>&1";
    return system(check.c_str()) == 0;
}

class NetworkBlockerLinux {
private:
    bool  rules_added    = false;
    bool  used_nftables  = false;
    bool  ufw_was_active = false;
    bool  firewalld_was_active = false;
    std::string server_ip;
    int   server_port    = 8888;

    // -----------------------------------------------------------------------
    // Write and load a native nftables ruleset
    // -----------------------------------------------------------------------
    bool apply_nftables() {
        // Build the ruleset as a here-doc written to a temp file
        // Priority -100 puts us BEFORE the default filter chains (priority 0)
        // so we run first regardless of what ufw/firewalld left behind.
        std::string ruleset =
            "#!/usr/sbin/nft -f\n"
            "\n"
            "# Exam integrity blocker — generated ruleset\n"
            "# Flush any previous exam table first\n"
            "table inet exam_blocker\n"
            "delete table inet exam_blocker\n"
            "\n"
            "table inet exam_blocker {\n"
            "\n"
            "    # INPUT chain — drop everything except loopback + exam server reply\n"
            "    chain input {\n"
            "        type filter hook input priority -100; policy drop;\n"
            "\n"
            "        # Always allow loopback\n"
            "        iif lo accept\n"
            "\n"
            "        # Drop ALL ICMP and ICMPv6 explicitly (belt-and-suspenders)\n"
            "        ip  protocol icmp   drop\n"
            "        ip6 nexthdr  icmpv6 drop\n"
            "\n"
            "        # Allow established TCP replies from the exam server only\n"
            "        ip saddr " + server_ip + " tcp sport " + std::to_string(server_port) +
            " ct state established accept\n"
            "\n"
            "        # Drop everything else\n"
            "        drop\n"
            "    }\n"
            "\n"
            "    # OUTPUT chain — drop everything except loopback + exam server\n"
            "    chain output {\n"
            "        type filter hook output priority -100; policy drop;\n"
            "\n"
            "        # Always allow loopback\n"
            "        oif lo accept\n"
            "\n"
            "        # Drop ALL ICMP and ICMPv6 explicitly\n"
            "        ip  protocol icmp   drop\n"
            "        ip6 nexthdr  icmpv6 drop\n"
            "\n"
            "        # Allow new + established TCP to exam server only\n"
            "        ip daddr " + server_ip + " tcp dport " + std::to_string(server_port) +
            " ct state new,established accept\n"
            "\n"
            "        # Drop everything else\n"
            "        drop\n"
            "    }\n"
            "\n"
            "    # FORWARD chain — drop all forwarded traffic\n"
            "    chain forward {\n"
            "        type filter hook forward priority -100; policy drop;\n"
            "    }\n"
            "}\n";

        // Write ruleset to temp file
        FILE* f = fopen("/tmp/exam_nft_rules.nft", "w");
        if (!f) {
            std::cerr << "[ERROR] Could not write nftables ruleset to /tmp\n";
            return false;
        }
        fputs(ruleset.c_str(), f);
        fclose(f);

        // Load it
        int rc = run_cmd("nft -f /tmp/exam_nft_rules.nft 2>/dev/null");
        if (rc != 0) {
            std::cerr << "[WARN] nft -f failed (rc=" << rc << "), falling back to iptables\n";
            return false;
        }

        std::cout << "[+] nftables exam_blocker table loaded (priority -100)\n";
        return true;
    }

    // -----------------------------------------------------------------------
    // Fallback: legacy iptables rules
    // -----------------------------------------------------------------------
    void apply_iptables() {
        std::cout << "[*] Applying iptables rules as fallback...\n";

        // Backup
        run_cmd("iptables-save  > /tmp/exam_iptables_backup  2>/dev/null");
        run_cmd("ip6tables-save > /tmp/exam_ip6tables_backup 2>/dev/null");

        // Flush filter table completely
        run_cmd("iptables  -t filter -F 2>/dev/null");
        run_cmd("iptables  -t filter -X 2>/dev/null");
        run_cmd("ip6tables -t filter -F 2>/dev/null");
        run_cmd("ip6tables -t filter -X 2>/dev/null");

        // Also flush nat/mangle so no sneaky redirects survive
        run_cmd("iptables  -t nat    -F 2>/dev/null");
        run_cmd("iptables  -t mangle -F 2>/dev/null");

        // Default DROP
        run_cmd("iptables  -P INPUT   DROP 2>/dev/null");
        run_cmd("iptables  -P OUTPUT  DROP 2>/dev/null");
        run_cmd("iptables  -P FORWARD DROP 2>/dev/null");
        run_cmd("ip6tables -P INPUT   DROP 2>/dev/null");
        run_cmd("ip6tables -P OUTPUT  DROP 2>/dev/null");
        run_cmd("ip6tables -P FORWARD DROP 2>/dev/null");

        // Allow loopback
        run_cmd("iptables  -A INPUT  -i lo -j ACCEPT 2>/dev/null");
        run_cmd("iptables  -A OUTPUT -o lo -j ACCEPT 2>/dev/null");

        // Explicit ICMP DROP (before any ESTABLISHED rule)
        run_cmd("iptables  -A INPUT  -p icmp -j DROP 2>/dev/null");
        run_cmd("iptables  -A OUTPUT -p icmp -j DROP 2>/dev/null");
        run_cmd("ip6tables -A INPUT  -p icmpv6 -j DROP 2>/dev/null");
        run_cmd("ip6tables -A OUTPUT -p icmpv6 -j DROP 2>/dev/null");

        // Allow exam server TCP only — no blanket ESTABLISHED/RELATED
        run_cmd(("iptables -A OUTPUT -d " + server_ip +
                 " -p tcp --dport " + std::to_string(server_port) +
                 " -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT 2>/dev/null").c_str());
        run_cmd(("iptables -A INPUT  -s " + server_ip +
                 " -p tcp --sport " + std::to_string(server_port) +
                 " -m conntrack --ctstate ESTABLISHED     -j ACCEPT 2>/dev/null").c_str());

        std::cout << "[+] iptables fallback rules applied\n";
    }

public:
    void set_server_info(const std::string& ip, int port) {
        server_ip   = ip;
        server_port = port;
    }

    bool initialize() { return true; }

    bool block_all_traffic() {
        std::cout << "[*] Blocking all network traffic on Linux...\n";
        std::cout << "[!] Note: Requires ROOT privileges.\n";

        // ---------------------------------------------------------------
        // Layer 1: Disable ufw / firewalld so their nftables tables vanish.
        // Without this, their rules can accept ICMP before ours run.
        // ---------------------------------------------------------------
        if (program_exists("ufw")) {
            int rc = run_cmd("ufw status 2>/dev/null | grep -q 'Status: active'");
            ufw_was_active = (rc == 0);
            if (ufw_was_active) {
                std::cout << "[*] Disabling ufw (will restore on exit)...\n";
                run_cmd("ufw disable 2>/dev/null");
            }
        }

        if (program_exists("firewall-cmd")) {
            int rc = run_cmd("firewall-cmd --state 2>/dev/null | grep -q 'running'");
            firewalld_was_active = (rc == 0);
            if (firewalld_was_active) {
                std::cout << "[*] Stopping firewalld (will restore on exit)...\n";
                run_cmd("systemctl stop firewalld 2>/dev/null");
            }
        }

        // Flush any leftover nftables tables from ufw/firewalld that didn't
        // clean up after themselves
        run_cmd("nft flush ruleset 2>/dev/null");

        // ---------------------------------------------------------------
        // Layer 2: Apply nftables ruleset (preferred)
        // ---------------------------------------------------------------
        if (program_exists("nft")) {
            // Backup existing nftables ruleset
            run_cmd("nft list ruleset > /tmp/exam_nft_backup 2>/dev/null");
            used_nftables = apply_nftables();
        }

        // ---------------------------------------------------------------
        // Layer 3: Also apply iptables rules (belt-and-suspenders, and
        // required on kernels without nftables)
        // ---------------------------------------------------------------
        apply_iptables();

        rules_added = true;

        std::cout << "[*] Firewall rules applied:\n";
        std::cout << "    - ufw disabled:          " << (ufw_was_active       ? "yes" : "no/was-off") << "\n";
        std::cout << "    - firewalld stopped:     " << (firewalld_was_active ? "yes" : "no/was-off") << "\n";
        std::cout << "    - nftables table loaded: " << (used_nftables        ? "yes" : "no/unavailable") << "\n";
        std::cout << "    - iptables DROP rules:   yes\n";
        std::cout << "    - ICMP (ping):           BLOCKED\n";
        std::cout << "    - Exam server TCP:       ALLOWED\n";
        return true;
    }

    void restore_traffic() {
        if (!rules_added) return;
        std::cout << "[*] Restoring network configuration...\n";

        // Remove our nftables table
        if (used_nftables) {
            run_cmd("nft delete table inet exam_blocker 2>/dev/null");
            // Restore nftables backup if it had content
            run_cmd("if [ -s /tmp/exam_nft_backup ]; then "
                    "nft -f /tmp/exam_nft_backup 2>/dev/null; fi");
        }

        // Restore iptables
        run_cmd("iptables  -F 2>/dev/null");
        run_cmd("iptables  -X 2>/dev/null");
        run_cmd("ip6tables -F 2>/dev/null");
        run_cmd("ip6tables -X 2>/dev/null");
        run_cmd("iptables  -P INPUT   ACCEPT 2>/dev/null");
        run_cmd("iptables  -P OUTPUT  ACCEPT 2>/dev/null");
        run_cmd("iptables  -P FORWARD ACCEPT 2>/dev/null");
        run_cmd("ip6tables -P INPUT   ACCEPT 2>/dev/null");
        run_cmd("ip6tables -P OUTPUT  ACCEPT 2>/dev/null");
        run_cmd("ip6tables -P FORWARD ACCEPT 2>/dev/null");
        run_cmd("if [ -f /tmp/exam_iptables_backup ];  then "
                "iptables-restore  < /tmp/exam_iptables_backup  2>/dev/null; fi");
        run_cmd("if [ -f /tmp/exam_ip6tables_backup ]; then "
                "ip6tables-restore < /tmp/exam_ip6tables_backup 2>/dev/null; fi");

        // Re-enable ufw / firewalld if they were running before
        if (ufw_was_active) {
            std::cout << "[*] Re-enabling ufw...\n";
            run_cmd("ufw enable 2>/dev/null");
        }
        if (firewalld_was_active) {
            std::cout << "[*] Restarting firewalld...\n";
            run_cmd("systemctl start firewalld 2>/dev/null");
        }

        rules_added = false;
        std::cout << "[+] Network configuration restored.\n";
    }

    void cleanup() { restore_traffic(); }
};

#elif defined(__APPLE__)

class NetworkBlockerMac {
private:
    bool pf_enabled = false;
    std::string server_ip;
    int server_port = 8888;

public:
    void set_server_info(const std::string& ip, int port) {
        server_ip = ip;
        server_port = port;
    }

    bool initialize() { return true; }

    bool block_all_traffic() {
        std::cout << "[*] Blocking all network traffic on macOS using pf...\n";
        std::cout << "[!] Note: Requires ROOT privileges.\n";

        // Backup current pf rules
        system("pfctl -sr > /tmp/exam_pf_backup 2>/dev/null");

        // FIX #3 (macOS): explicitly block ICMP and only allow TCP to server
        std::string pf_rules =
            "block all\n"
            "block in  quick proto icmp\n"
            "block out quick proto icmp\n"
            "pass in  on lo0\n"
            "pass out on lo0\n"
            "pass out proto tcp to "   + server_ip + " port " + std::to_string(server_port) + " keep state\n";

        FILE* f = fopen("/tmp/exam_pf_rules", "w");
        if (f) {
            fputs(pf_rules.c_str(), f);
            fclose(f);
        }

        system("pfctl -ef /tmp/exam_pf_rules 2>/dev/null");

        pf_enabled = true;
        std::cout << "[*] pf firewall enabled - ALL network traffic BLOCKED (incl. ICMP)\n";
        return true;
    }

    void restore_traffic() {
        std::cout << "[*] Restoring network firewall rules...\n";

        if (pf_enabled) {
            system("pfctl -df 2>/dev/null");
            system("if [ -f /tmp/exam_pf_backup ]; then "
                   "pfctl -f /tmp/exam_pf_backup 2>/dev/null; fi");
        }

        pf_enabled = false;
    }

    void cleanup() { restore_traffic(); }
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
        int result = send(sock, msg.c_str(), (int)msg.length(), 0);
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

#ifdef _WIN32
            fd_set read_fds;
            FD_ZERO(&read_fds);
            FD_SET(sock, &read_fds);

            struct timeval timeout;
            timeout.tv_sec = 1;
            timeout.tv_usec = 0;

            int result = select(0, &read_fds, nullptr, nullptr, &timeout);
            if (result == SOCKET_ERROR) {
                if (g_shutdown_requested.load()) break;
                std::cerr << "[ERROR] Select failed: " << WSAGetLastError() << "\n";
                return false;
            }
            if (result == 0) continue;

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
                while (!cmd.empty() && (cmd.back() == '\n' || cmd.back() == '\r'))
                    cmd.pop_back();

                std::cout << "[*] Received command: " << cmd << "\n";

                if (cmd == "STOP" || cmd == "TERMINATE" || cmd == "EXIT") {
                    std::cout << "[!] Server requested stop. Shutting down...\n";
                    config.running.store(false);
                    g_shutdown_requested.store(true);
                    return true;
                }
            }
#else
            struct pollfd pfd;
            pfd.fd = sock;
            pfd.events = POLLIN;

            int result = poll(&pfd, 1, 1000);

            if (result < 0) {
                if (errno == EINTR) {
                    if (g_shutdown_requested.load()) break;
                    continue;
                }
                std::cerr << "[ERROR] Poll failed: " << strerror(errno) << "\n";
                return false;
            }
            if (result == 0) continue;

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
                while (!cmd.empty() && (cmd.back() == '\n' || cmd.back() == '\r'))
                    cmd.pop_back();

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
        if (sock != INVALID_SOCKET) { closesocket(sock); sock = INVALID_SOCKET; }
#else
        if (sock >= 0) { close(sock); sock = -1; }
#endif
    }
};

// ============================================================================
// User Input: Get StudentID
// ============================================================================

std::string get_student_id() {
    std::cout << "\n";
    std::cout << "============================================================\n";
    std::cout << "           EXAM INTEGRITY CLIENT - NETWORK BLOCKER          \n";
    std::cout << "============================================================\n\n";
    std::cout << "[!] WARNING: This client will BLOCK all network traffic\n";
    std::cout << "    during your evaluation. No internet access will be\n";
    std::cout << "    available until the exam is complete.\n\n";
    std::cout << "    Running this program requires ROOT/Administrator.\n\n";
    std::cout << "------------------------------------------------------------\n\n";

    std::cout << "Enter your Student ID: ";
    std::string id;
    std::getline(std::cin, id);

    if (id.empty()) {
        std::cerr << "[ERROR] Student ID cannot be empty.\n";
        return "";
    }

    std::cout << "\n[?] You entered: " << id << "\n";
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
// Verify network is blocked (Linux only)
// ============================================================================

#ifdef __linux__
void verify_network_blocked() {
    std::cout << "\n[*] Verifying network is blocked...\n";

    // Show active nftables tables so the user can see what's loaded
    std::cout << "[*] Active nftables tables:\n";
    system("nft list tables 2>/dev/null || echo '    (nft not available)'");

    // Show iptables default policies
    std::cout << "[*] iptables default policies:\n";
    system("iptables -L -n | grep 'Chain ' 2>/dev/null");

    // Test 1: ICMP ping (must fail)
    std::cout << "[*] Test 1 - ICMP ping to 8.8.8.8 (should FAIL): ";
    fflush(stdout);
    int ping_result = system("ping -c 1 -W 1 8.8.8.8 > /dev/null 2>&1");
    if (ping_result != 0) {
        std::cout << "[PASS] ping failed as expected\n";
    } else {
        std::cout << "[FAIL] ping succeeded - check if ufw/firewalld is still active\n";
        system("ufw status 2>/dev/null");
        system("firewall-cmd --state 2>/dev/null");
    }

    // Test 2: TCP to external host (must fail)
    std::cout << "[*] Test 2 - TCP to 8.8.8.8:53 (should FAIL): ";
    fflush(stdout);
    int tcp_result = system("timeout 2 bash -c 'echo > /dev/tcp/8.8.8.8/53' > /dev/null 2>&1");
    if (tcp_result != 0) {
        std::cout << "[PASS] TCP blocked as expected\n";
    } else {
        std::cout << "[FAIL] TCP connection succeeded - traffic not fully blocked\n";
    }

    std::cout << "\n";
}
#endif

// ============================================================================
// Main Entry Point
// ============================================================================

int main(int argc, char* argv[]) {
#ifdef _WIN32
    signal(SIGINT,  signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGBREAK, signal_handler);
#else
    struct sigaction sa;
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT,  &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);
#endif

    std::cout << "[*] Exam Integrity Client starting...\n";

    std::string student_id = get_student_id();
    if (student_id.empty()) return 1;

    ClientConfig config;
    config.student_id = student_id;

    if (argc >= 2) config.server_host = argv[1];
    if (argc >= 3) config.server_port = std::atoi(argv[2]);

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

    if (!blocker.block_all_traffic()) {
        std::cerr << "[ERROR] Failed to block network traffic.\n";
        return 1;
    }

#ifdef __linux__
    verify_network_blocked();
#endif

    ServerConnection server(config);
    if (!server.connect_to_server()) {
        std::cerr << "[ERROR] Failed to connect to server.\n";
        std::cerr << "[!] Check if server is running at " << config.server_host
                  << ":" << config.server_port << "\n";
        blocker.cleanup();
        return 1;
    }

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
    std::cout << "============================================================\n\n";

    server.listen_for_commands();

    std::cout << "[*] Cleaning up...\n";
    server.close_connection();
    blocker.cleanup();

    std::cout << "[+] Client stopped. Network should be restored.\n";
    std::cout << "[!] If network is not working, please run:\n";
    std::cout << "    Linux:   iptables -F && iptables -P INPUT ACCEPT && iptables -P OUTPUT ACCEPT\n";
    std::cout << "    macOS:   pfctl -df\n";
    std::cout << "    Windows: netsh advfirewall reset\n";

    return 0;
}