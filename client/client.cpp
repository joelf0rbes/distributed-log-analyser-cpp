// client.cpp
//
// Client for the distributed log file analysis application.
//
// Connects to the log analysis server, recursively finds all .json/.xml/.txt
// log files under a given folder, parses each one into a normalized format,
// and streams the parsed entries to the server for processing. Once all
// files have been sent, it receives and displays a summary from the server.
//
// Build:
//   g++ client.cpp -o client -ltinyxml2 -std=c++17
//
// Usage:
//   ./client <server_ip> <port> <start_date> <end_date> <folder_path>
//
// Example:
//   ./client 127.0.0.1 54000 2024-01-01 2024-12-31 ./logs/client#1
 
#include <algorithm>
#include <arpa/inet.h>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <netinet/in.h>
#include <regex>
#include <sstream>
#include <string>
#include <sys/socket.h>
#include <tinyxml2.h>
#include <unistd.h>
#include <vector>
 
#include "json.hpp"

using json = nlohmann::json;
using tinyxml2::XMLDocument;
using tinyxml2::XMLElement;
using tinyxml2::XML_SUCCESS;

// ============================================================================
// Networking helpers
// ============================================================================

// Sends raw data over a socket. Returns false if the underlying send() call
// fails; does not guarantee the entire buffer was sent in one call for very
// large payloads (not currently needed on the client side, since individual
// log entries are small).
bool safeSend(int socket, const std::string& data) {
    return send(socket, data.c_str(), data.size(), 0) != -1;
}

// Sends one normalized log entry to the server, in the wire format the
// server expects: "timestamp|level|message|ip\n". This is the single place
// that defines that format, so all three parsers below build entries the
// same way.
void sendLogEntry(int socket, const std::string& timestamp, const std::string& level,
    const std::string& message, const std::string& ip) {
std::string line = timestamp + "|" + level + "|" + message + "|" + ip + "\n";
safeSend(socket, line);
}

// ============================================================================
// Input validation
// ============================================================================

// Checks that a date string is in YYYY-MM-DD format.
bool isValidDate(const std::string& date) {
    std::regex pattern(R"(\d{4}-\d{2}-\d{2})");
    return std::regex_match(date, pattern);
}

// Returns a filename's extension in lowercase, including the leading dot
// (e.g. "log.JSON" -> ".json"). Returns an empty string if there is no
// extension.
std::string getFileExtension(const std::string& filename) {
    size_t dotPos = filename.find_last_of('.');
    if (dotPos != std::string::npos && dotPos != 0 && dotPos < filename.size() - 1) {
        std::string ext = filename.substr(dotPos);
        std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
        return ext;
    }
    return "";
}

// ============================================================================
// Format-specific log parsers
//
// Each parser reads one log file in its native format, extracts the fields
// we care about (timestamp, level, message, ip), and sends one normalized
// entry per log record to the server via sendLogEntry(). Malformed or
// incomplete entries are skipped rather than sent, so a single bad record
// doesn't corrupt the whole transfer.
// ============================================================================

// Parses a pipe-delimited plain text log file.
// Expected line format:
//   2024-09-30 22:51:48 | INFO | CPU utilization high | UserID: 2421 | IP: 84.126.98.62
void parseTxtLog(const std::string& filePath, int clientSocket) {
    std::ifstream file(filePath);
    if (!file) {
        std::cerr << "Failed to open file: " << filePath << std::endl;
        return;
    }

    std::string line;
    while (std::getline(file, line)) {
        std::vector<std::string> parts;
        std::stringstream ss(line);
        std::string part;
        while (std::getline(ss, part, '|')) {
            // trim leading/trailing spaces
            size_t start = part.find_first_not_of(' ');
            size_t end = part.find_last_not_of(' ');
            if (start != std::string::npos) {
                part = part.substr(start, end - start + 1);
            }
            parts.push_back(part);
        }

        if (parts.size() < 5) continue;  // Malformed line — doesn't have all expected fields.

        std::string timestamp = parts[0];
        std::string level = parts[1];
        std::string message = parts[2];
        std::string ip = parts[4].substr(parts[4].find(':') + 2);  // strip "IP: " prefix

        sendLogEntry(clientSocket, timestamp, level, message, ip);
    }

    file.close();
}


// Parses an XML log file.
// Expected structure:
//   <logs>
//     <log>
//       <timestamp>...</timestamp>
//       <log_level>...</log_level>
//       <message>...</message>
//       <ip_address>...</ip_address>
//     </log>
//     ...
//   </logs>
void parseXmlLog(const std::string& filePath, int clientSocket){
    XMLDocument doc;
    if (doc.LoadFile(filePath.c_str()) != XML_SUCCESS) {
        std::cerr << "Failed to open XML file: " << filePath << std::endl;
        return;
    }

    XMLElement* root = doc.FirstChildElement("logs");
    if (root == nullptr) {
        std::cerr << "Invalid XML format: " << filePath << std::endl;
        return;
    } 

    for (auto* entry = root->FirstChildElement("log");
    entry; entry = entry->NextSiblingElement("log")) {

        // Reads the text content of a named child element, or "" if it's
        // missing or empty. Declared once per entry since it captures `entry`.
        auto getText = [entry](const char* tagName) -> std::string {
            XMLElement* child = entry->FirstChildElement(tagName);
            if (child == nullptr || child->GetText() == nullptr) return "";
            return child->GetText();
        };

        std::string timestamp = getText("timestamp");
        std::string level = getText("log_level");
        std::string message = getText("message");
        std::string ip = getText("ip_address");

        if (timestamp.empty()) continue;  // skip malformed entries

        sendLogEntry(clientSocket, timestamp, level, message, ip);
    }
}

// Parses a JSON log file.
// Expected structure: a top-level array of log objects, e.g.
//   [
//     { "timestamp": "...", "log_level": "...", "message": "...", "ip_address": "..." },
//     ...
//   ]
void parseJsonLog(const std::string& filePath, int clientSocket) {
    std::ifstream file(filePath);
    if  (!file.is_open()) {
        std::cerr << "Failed to open JSON file: " << filePath << std::endl;
        return;
    }

    json logData;
    try {
        file >> logData;
    } catch (const json::parse_error& e) {
        std::cerr << "Failed to parse JSON file: " << filePath << " (" << e.what() << ")" << std::endl;
        return;
    }

    if (!logData.is_array()) {
        std::cerr << "Expected a JSON array of log entries in: " << filePath << std::endl;
        return;
    }

    for (auto& entry : logData) {
        std::string timestamp = entry.value("timestamp", "");
        std::string level = entry.value("log_level", "");
        std::string message = entry.value("message", "");
        std::string ip = entry.value("ip_address", "");

        if (timestamp.empty()) continue;  // skip malformed entries

        sendLogEntry(clientSocket, timestamp, level, message, ip);
    }

    file.close();
}

// Dispatches to the correct parser based on file extension.
void parseLogFile(const std::string& filePath, const std::string& fileType, int clientSocket) {
    if (fileType == ".json") {
        parseJsonLog(filePath, clientSocket);
    } else if (fileType == ".xml") {
        parseXmlLog(filePath, clientSocket);
    } else if (fileType == ".txt") {
        parseTxtLog(filePath, clientSocket);
    } else {
        std::cerr << "Unsupported file type: " << fileType << std::endl;
    }
}

// ============================================================================
// File discovery and transmission
// ============================================================================

// Recursively finds all .json/.xml/.txt files under `dir` and appends them
// to `logFiles`.
void findLogFiles(const std::filesystem::path& dir, std::vector<std::filesystem::path>& logFiles) {
    try {
        for (const auto& entry : std::filesystem::recursive_directory_iterator(dir)) {
            if (entry.is_regular_file()) {
                std::string ext = entry.path().extension().string();
                std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);

                if (ext == ".json" || ext == ".txt" || ext == ".xml") {
                    logFiles.push_back(entry.path());
                }
            }
        }
    } catch (const std::filesystem::filesystem_error& e) {
        std::cerr << "Error reading directory: " << e.what() << std::endl;
    }
}

// Sends one log file to the server: announces the filename, parses the file
// and streams its normalized entries, then sends an end-of-file marker.
void sendFile(int clientSocket, const std::string& filePath) {
    std::string fileName = std::filesystem::path(filePath).filename().string();
    std::string fileType = getFileExtension(filePath);

    // Tell the server what file is coming
    safeSend(clientSocket, fileName + "\n");

    // Parse the file (json/xml/txt) and stream normalized entries to the server
    parseLogFile(filePath, fileType, clientSocket);

    // Send the end-of-file marker
    safeSend(clientSocket, "END_OF_FILE\n");

    std::cout << "Sent file: " << fileName << std::endl;
}

// ============================================================================
// main
// ============================================================================

int main(int argc, char* argv[]) {
    if (argc != 6) {
        std::cerr << "Usage: " << argv[0] << " <server_ip> <port> <start_date> <end_date> <folder_path>\n";
        return 1;    
    }
    
    std::string serverIP = argv[1];
    int port = std::stoi(argv[2]);
    std::string startDate = argv[3];
    std::string endDate = argv[4];
    std::string folderPath = argv[5];

    if (!isValidDate(startDate) || !isValidDate(endDate)) {
        std::cerr << "Invalid date format.\n";
        return 1;
    }    

    std::vector<std::filesystem::path> logFiles;
    findLogFiles(folderPath, logFiles);

    if (logFiles.empty()) {
        std::cerr << "No log files found in the specified directory!" << std::endl;
        return 1;
    }

    // --- Connect to the server ---
    int clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (clientSocket < 0) {
        std::cerr << "Socket creation failed.\n";
        return 1;
    }

    sockaddr_in serverAddr{};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);
    inet_pton(AF_INET, serverIP.c_str(), &serverAddr.sin_addr);

    if (connect(clientSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        std::cerr << "Connection to server failed.\n";
        close(clientSocket);
        return 1;
    }

    // --- Send metadata, then every log file ---

    if (!safeSend(clientSocket, startDate + "\n") ||
        !safeSend(clientSocket, endDate + "\n")) {
        std::cerr << "Failed to send initial metadata to server.\n";
        close(clientSocket);
        return 1;
    }

    for (const auto& filePath : logFiles) {
        sendFile(clientSocket, filePath.string());
    }

    safeSend(clientSocket, "END_OF_FOLDER\n");

    // --- Receive the summary from the server ---

    char buffer[1024];
    std::string summary;

    while (true) {
        int bytesRecieved = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
        if (bytesRecieved <= 0) break;
        buffer[bytesRecieved] = '\0';
        summary += buffer;
        
        if (summary.find("END_OF_SUMMARY\n") != std::string::npos) break;
    }

    std::cout << "\n=== Server Summary ===\n" << summary << std::endl;

    // --- Offer to save the summary locally ---
    std::cout << "\nDo you want to save the summary to a file? (y/n): ";
    char choice;
    std::cin >> choice;

    if (choice == 'y' || choice == 'Y') {
        std::ofstream outFile("summary.txt");
        if (outFile) {
            outFile << summary;
            std::cout << "Summary saved to summary.txt\n";
        } else {
            std::cerr << "Failed to save summary.\n";
        }

    }

    close(clientSocket);
    return 0;
}