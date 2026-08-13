# C++ Distributed Log Analyser

## Overview

A multithreaded C++ client-server application for aggregating and analyzing log files across multiple clients in JSON, XML, and TXT formats.

As part of my Programming Principles module, this project demonstrates socket programming, concurrent server design, and cross-format data parsing over a custom TCP protocol.</p1>

## Key Features

- **Multi-format log parsing** - the clients parse the log files (JSON, XML, TXT) and normalise them into a consistent format before transmission
- **Concurrent client handling** - the server spawns a dedicated thread per connection, allowing multiple clients to be processed concurrently through multithreading
- **Thread-safe statistics** - per-connection log level counts, per-IP entry counts, and per-IP/level breakdowns, protected against race conditions
- **Date-range filtering** - clients specify a start and end date and log entries within that range are counted only
- **Performance metrics** - total and average transfer time, transfer speed (MB/s), and error/warning rates included in every summary
- **Security-conscious file handling** - filenames are sanitized server-side to prevent path traversal

## Tech Stack

- **Language:** C++17
- **Networking:** POSIX sockets (TCP)
- **Concurrency:** ``std:thread``, ``std::mutex``, ``std::atomic``
- **JSON parsing:** nlohmann/json
- **XML parsing:** tinyxml2
- **Build:** Make, CMake

## How It Works

1. The client recursively scans a stated folder for ``.json``, ``.xml``, and ``.txt`` log files.
2. Each file is parsed according to its original format, and ever log entry is normalised into a single line: ``timestamp|level|message|ip``.
3. Normalised entries are streamed to the server, one file at a time over a TCP connection.
4. The server filters incoming entries by the client-specified date range, and records log level per connection and per client IP. Each client connection is handled on its own thread, so multiple clients can connect at once without blocking each other.
5. Once all the files have sent, the server builds a summary and sends it back to the client.
6. The client displays the summary and offers to save it locally as ``summary.txt``.

## Getting Started

### Prerequisites

- A C++17-capable compiler (e.g.``g++`` or Apple Clang)
- tinyxml2

On macOS, install ``tinyxml2`` via Homebrew:

```bash
brew install tinyxml2
```

On Debian/Ubuntu:

```bash
sudo apt install libtinyxml2-dev
```

``nlohmann::json`` is included directly in this repo as a single header (``client/json.hpp``), therefore no separate installation is needed.

### Build

```bash
cd CMake
make
```

This produces two executables: ``client`` and ``server``.

### Run

Start the server first, specifying a port:

```bash
./server 54000
```

In a separate terminal, build and run the client, pointing it at the server and a folder of log files:

```bash
./client <server_ip> <port> <start_date> <end_date> <folder_path>
```

For example:

```bash
/client 127.0.0.1 54000 2024-01-01 2024-12-31 ../client/logs
```

The client will send every ``.json``, ``.xml``, ``.txt`` file found (recursively) under the given folder, and print a summary once the server responds.
<h2>Sample Output</h2>
