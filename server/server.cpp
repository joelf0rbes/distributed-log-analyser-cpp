// server.cpp
//
// Server for the distributed log file analysis application.
//
// Accepts connections from multiple clients concurrently (one thread per
// connection), receives normalized log entries for each file a client
// sends, filters them by date range, counts log levels per client IP, and
// sends each client a summary of what was received.
//
// Build:
//   g++ server.cpp -o server -pthread -std=c++17
//
// Usage:
//   ./server <port>
 
#include <arpa/inet.h>
#include <atomic>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <mutex>
#include <netinet/in.h>
#include <sstream>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <vector>
 
// ============================================================================
// Shared state
// ============================================================================
 
// Tracks how many times each IP address has connected, across the server's
// entire lifetime. Kept global/shared (unlike the per-connection stats
// below), since it's meant to persist across separate connections.
std::map<std::string, int> userLogAttempts;
std::mutex userLogMutex;

// Assigns each connection a unique, ever-increasing number, so that files
// from different connections never collide on disk even if they share the
// same client IP address (e.g. the same client reconnecting).
std::atomic<long long> connectionCounter{0};

// ============================================================================
// Networking helpers
// ============================================================================

// Reads a single '\n'-terminated line from the socket. Bytes read past the
// end of the line are kept in `connBuffer` for the next call, so nothing
// received from the client is ever lost — this buffer must be shared across
// every recvLine() call made for the same connection (see handleClient).
bool recvLine(int socket, std::string& connBuffer, std::string& outLine) {
    size_t searchFrom = 0;
    size_t newlinePos;
 
    while ((newlinePos = connBuffer.find('\n', searchFrom)) == std::string::npos) {
        searchFrom = connBuffer.size();  // Don't re-scan bytes we've already checked.
 
        char temp[65536];
        int bytesRead = recv(socket, temp, sizeof(temp), 0);
        if (bytesRead <= 0) {
            return false;  // Connection closed or an error occurred.
        }
        connBuffer.append(temp, bytesRead);
    }
 
    outLine = connBuffer.substr(0, newlinePos);
    connBuffer.erase(0, newlinePos + 1);
    return true;
}

// Logs a message to the console. Protected by its own mutex since multiple
// client threads may log concurrently.
void logMessage(const std::string& level, const std::string& message) {
    static std::mutex coutMutex;
    std::lock_guard<std::mutex> lock(coutMutex);
    std::cout << "[" << level << "] " << message << std::endl;
}

// ============================================================================
// Log entry parsing
// ============================================================================

// Splits a normalized log line ("timestamp|level|message|ip") into its four
// fields. Returns false if the line doesn't have exactly four parts.
bool parseLogEntry(const std::string& line, std::string& timestamp, std::string& level,
                    std::string& message, std::string& ip) {
    std::vector<std::string> parts;
    std::stringstream ss(line);
    std::string part;
 
    while (std::getline(ss, part, '|')) {
        parts.push_back(part);
    }
 
    if (parts.size() != 4) {
        return false;
    }
 
    timestamp = parts[0];
    level = parts[1];
    message = parts[2];
    ip = parts[3];
    return true;
}

// ============================================================================
// File receiving
// ============================================================================

// Receives one file's worth of normalized log entries from a client,
// filters them by date range, saves matching entries to disk, and updates
// this connection's stat maps. Reads until an "END_OF_FILE" marker line is
// received.
void receiveFile(int clientSocket, std::string& connBuffer, const std::string& fileName,
    const std::string& startDate, const std::string& endDate,
    const std::string& clientIPAddress, const std::string& outputDir,
    std::map<std::string, int>& logLevelCounts,
    std::map<std::string, int>& ipLogEntryCounts,
    std::map<std::string, std::map<std::string, int>>& userLogLevelCounts,
    size_t& totalBytesReceived) {
    // Strip any directory components from the client-supplied filename, so a
    // malicious or buggy client can't write outside our intended folder.
    std::string safeFileName = std::filesystem::path(fileName).filename().string();
    if (safeFileName.empty()) {
        logMessage("ERROR", "Rejected invalid filename from client.");
        return;
    }
 
    std::filesystem::create_directories(outputDir);
    std::string outputPath = outputDir + "/" + safeFileName;
    std::ofstream outFile(outputPath, std::ios::binary);
    if (!outFile) {
        logMessage("ERROR", "Failed to open file for writing: " + fileName);
        return;
    }
 
    logMessage("INFO", "Receiving file: " + fileName);
 
    std::string line;
    while (recvLine(clientSocket, connBuffer, line)) {
        if (line == "END_OF_FILE") {
            return;
        }
 
        std::string timestamp, level, message, ip;
        if (!parseLogEntry(line, timestamp, level, message, ip)) {
            continue;  // Skip malformed lines instead of miscounting.
        }
 
        if (timestamp.size() < 10) {
            continue;
        }
 
        std::string date = timestamp.substr(0, 10);
        if (date < startDate || date > endDate) {
            continue;  // Outside the requested date range.
        }
 
        outFile << line << '\n';
        totalBytesReceived += line.size() + 1;
 
        if (level.empty()) {
            continue;
        }
 
        logMessage(level, line);
        logLevelCounts[level]++;
        ipLogEntryCounts[clientIPAddress]++;
        userLogLevelCounts[clientIPAddress][level]++;
    }

    // If the loop above exits without returning, the connection dropped
    // before an END_OF_FILE marker ever arrived.
    logMessage("ERROR", "Connection closed before END_OF_FILE marker for: " + fileName);
}

// ============================================================================
// Client connection handling
// ============================================================================

// Handles one client connection end-to-end: reads the date range, receives
// every file the client sends, builds a summary of what was received, and
// sends that summary back before closing the connection. Runs on its own
// thread per connection (see main()).
void handleClient(int clientSocket, std::string clientIPAddress) {
    std::string connBuffer;
    std::string startDate, endDate;

    // Unique output folder for this connection's saved files.
    long long connectionId = ++connectionCounter;
    std::string outputDir = "received_logs/" + clientIPAddress + "_" + std::to_string(connectionId);

    // Per-connection stats, scoped to this client's session only — reset
    // for every new connection rather than shared across all clients.
    std::map<std::string, int> logLevelCounts;
    std::map<std::string, int> ipLogEntryCounts;
    std::map<std::string, std::map<std::string, int>> userLogLevelCounts;
    if (!recvLine(clientSocket, connBuffer, startDate) ||
        !recvLine(clientSocket, connBuffer, endDate)) {
        logMessage("ERROR", "Connection lost before metadata complete.");
        close(clientSocket);
        return;
    }

        {
            std::lock_guard<std::mutex> lock(userLogMutex);
            userLogAttempts[clientIPAddress]++;
            logMessage("INFO", "Client connected from IP: " + clientIPAddress);
            logMessage("INFO", "Log attempts by this user: " + std::to_string(userLogAttempts[clientIPAddress]));
        }

    // --- Transfer metrics ---
    size_t totalFilesReceived = 0;
    size_t totalBytesReceived = 0;
    auto transferStart = std::chrono::steady_clock::now();

    // Receive files from the client until it signals it's done.
    std::string fileName;
    while (recvLine(clientSocket, connBuffer, fileName)) {
        if (fileName == "END_OF_FOLDER") {
            break;
        }
        if (fileName.empty()) {
            continue;
        }

        receiveFile(clientSocket, connBuffer, fileName, startDate, endDate, clientIPAddress, outputDir,
            logLevelCounts, ipLogEntryCounts, userLogLevelCounts, totalBytesReceived);
        totalFilesReceived++;
    }

    auto transferEnd = std::chrono::steady_clock::now();
    double totalTransferSeconds = std::chrono::duration<double>(transferEnd - transferStart).count();

    // --- Compute derived metrics ---

    // Total log entries actually counted, across all levels.
    size_t totalEntriesCounted = 0;
    for (const auto& pair : logLevelCounts) {
        totalEntriesCounted += pair.second;
    }

    // Safe lookup that doesn't insert a 0 entry into the map if the level
    // was never seen (unlike operator[]).
    auto getLevelCount = [&logLevelCounts](const std::string& lvl) -> int {
        auto it = logLevelCounts.find(lvl);
        return it != logLevelCounts.end() ? it->second : 0;
    };

    double avgTransferTimePerFile = totalFilesReceived > 0
        ? totalTransferSeconds / totalFilesReceived : 0.0;
    double avgFileSizeKB = totalFilesReceived > 0
        ? (totalBytesReceived / 1024.0) / totalFilesReceived : 0.0;
    double transferSpeedMBps = totalTransferSeconds > 0
        ? (totalBytesReceived / (1024.0 * 1024.0)) / totalTransferSeconds : 0.0;
    double errorPercentage = totalEntriesCounted > 0
        ? (getLevelCount("ERROR") * 100.0) / totalEntriesCounted : 0.0;
    double warningPercentage = totalEntriesCounted > 0
        ? (getLevelCount("WARN") * 100.0) / totalEntriesCounted : 0.0;

    // --- Build the summary ---

    std::ostringstream metrics;
    metrics << std::fixed << std::setprecision(2);
    metrics << "Transfer Metrics:\n";
    metrics << "Total Files Received: " << totalFilesReceived << "\n";
    metrics << "Total Transfer Time: " << totalTransferSeconds << " s\n";
    metrics << "Average Transfer Time per File: " << avgTransferTimePerFile << " s\n";
    metrics << "Average Log File Size: " << avgFileSizeKB << " KB\n";
    metrics << "Average Transfer Speed: " << transferSpeedMBps << " MB/s\n";
    metrics << "Error Rate: " << errorPercentage << "%\n";
    metrics << "Warning Rate: " << warningPercentage << "%\n";

    std::string summary = "Summary:\n\n" + metrics.str();

    summary += "\nLog Levels:\n";
    for (const auto& pair : logLevelCounts) {
        summary += pair.first + ": " + std::to_string(pair.second) + "\n";
    }

    summary += "\nLog Attempts by IP:\n";
    for (const auto& pair : ipLogEntryCounts) {
        summary += pair.first + ": " + std::to_string(pair.second) + " entries\n";
    }

    summary += "\nLog Attempts by IP and Level:\n";
    for (const auto& user : userLogLevelCounts) {
        summary += user.first + ":\n";
        for (const auto& level : user.second) {
            summary += "  " + level.first + ": " + std::to_string(level.second) + "\n";
        }
    }

    summary += "END_OF_SUMMARY\n";

    // --- Send the summary ---

    // send() isn't guaranteed to write the whole buffer in one call for
    // larger payloads, so loop until everything has actually gone out.
    size_t totalSent = 0;
    while (totalSent < summary.size()) {
        ssize_t sent = send(clientSocket, summary.c_str() + totalSent, summary.size() - totalSent, 0);
        if (sent <= 0) {
            logMessage("ERROR", "Failed to send summary to " + clientIPAddress);
            break;
        }
        totalSent += sent;
    }

    close(clientSocket);
    logMessage("INFO", "Closed connection with " + clientIPAddress);
}

// ============================================================================
// main
// ============================================================================

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <port>\n";
        return 1;
    }
    
    int port = std::stoi(argv[1]);

    int serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket < 0) {
        std::cerr << "Socket creation failed.\n";
        return 1;
    }

    // Allow immediate re-binding to this port after the server restarts,
    // rather than waiting out the OS's default TIME_WAIT period.
    int reuse = 1;
    setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    sockaddr_in serverAddr{};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);
    serverAddr.sin_addr.s_addr = INADDR_ANY; // Accept connections on any network interface.

    if (bind(serverSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        std::cerr << "Bind failed.\n";
        close(serverSocket);
        return 1;
    }

    if (listen(serverSocket, 5) < 0) {
        std::cerr << "Listen failed.\n";
        close(serverSocket);
        return 1;
    }

    logMessage("INFO", "Server is listening on port " + std::to_string(port) + "...");

    while (true) {
        sockaddr_in clientAddr{};
        socklen_t clientSize = sizeof(clientAddr);
        int clientSocket = accept(serverSocket, (sockaddr*)&clientAddr, &clientSize);
        if (clientSocket < 0) {
            std::cerr << "Client accept failed.\n";        
            continue;
        }

        char clientIP[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &clientAddr.sin_addr, clientIP, INET_ADDRSTRLEN);
        std::string clientIPAddress(clientIP);      

        logMessage("INFO", "Connection accepted from " + clientIPAddress);

        // Handle each client on its own detached thread so the accept loop
        // is never blocked waiting on one client's transfer to finish.
        std::thread(handleClient, clientSocket, clientIPAddress).detach();    
    }

    close(serverSocket);
    return 0;
}