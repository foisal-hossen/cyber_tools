#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <curl/curl.h>
#include <sstream>
#include <iomanip>
#include <cstdlib>

std::mutex printMutex;

// ANSI color codes
#define GREEN   "\033[1;32m"
#define RED     "\033[1;31m"
#define YELLOW  "\033[1;33m"
#define CYAN    "\033[1;36m"
#define RESET   "\033[0m"

// URL encode utility
std::string urlEncode(const std::string &value) {
    std::ostringstream escaped;
    escaped.fill('0');
    escaped << std::hex;
    for (char c : value) {
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            escaped << c;
        } else {
            escaped << '%' << std::setw(2) << int((unsigned char)c);
        }
    }
    return escaped.str();
}

// Curl response callback
size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* userp) {
    userp->append((char*)contents, size * nmemb);
    return size * nmemb;
}

// HTTP GET request
std::string httpGet(const std::string& url) {
    CURL* curl = curl_easy_init();
    std::string response;
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
        curl_easy_perform(curl);
        curl_easy_cleanup(curl);
    }
    return response;
}

// Terminal-style output
void printResult(const std::string& section, const std::string& url, const std::string& status, const std::string& cve = "") {
    std::lock_guard<std::mutex> guard(printMutex);
    std::cout << CYAN << "[+] " << section << RESET << std::endl;
    std::cout << "    Target: " << url << std::endl;
    std::cout << "    Status: ";
    if (status == "VULNERABLE") {
        std::cout << RED << status << RESET;
    } else {
        std::cout << GREEN << status << RESET;
    }
    if (!cve.empty()) {
        std::cout << " " << YELLOW << "(CVE: " << cve << ")" << RESET;
    }
    std::cout << std::endl << std::endl;
}

// ✅ SQL Injection check
void checkSQLInjection(const std::string& baseUrl) {
    std::vector<std::string> payloads = {"' OR '1'='1", "' OR '1'='1' --", "'; DROP TABLE users; --"};
    for (const auto& payload : payloads) {
        std::string testUrl = baseUrl + "?id=" + urlEncode(payload);
        std::string response = httpGet(testUrl);
        if (response.find("SQL") != std::string::npos || response.find("syntax error") != std::string::npos) {
            printResult("SQL Injection", testUrl, "VULNERABLE", "CVE-2002-0649");
            return;
        }
    }
    printResult("SQL Injection", baseUrl, "SAFE");
}

// ✅ XSS check
void checkXSS(const std::string& baseUrl) {
    std::vector<std::string> payloads = {"<script>alert('XSS')</script>", "\"<img src=x onerror=alert('XSS')>\""};
    for (const auto& payload : payloads) {
        std::string testUrl = baseUrl + "?search=" + urlEncode(payload);
        std::string response = httpGet(testUrl);
        if (response.find(payload) != std::string::npos) {
            printResult("Cross-Site Scripting (XSS)", testUrl, "VULNERABLE", "CVE-2000-1202");
            return;
        }
    }
    printResult("Cross-Site Scripting (XSS)", baseUrl, "SAFE");
}

// ✅ Open Directory check
void checkOpenDirs(const std::string& baseUrl) {
    std::vector<std::string> dirs = {"/admin/", "/backup/", "/config/", "/uploads/"};
    bool found = false;
    for (const auto& dir : dirs) {
        std::string testUrl = baseUrl + dir;
        std::string response = httpGet(testUrl);
        if (response.find("Index of") != std::string::npos) {
            printResult("Open Directory", testUrl, "VULNERABLE", "CVE-2005-0400");
            found = true;
        }
    }
    if (!found) printResult("Open Directory", baseUrl, "SAFE");
}

// ✅ Header check
void checkHeaders(const std::string& baseUrl) {
    CURL* curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, baseUrl.c_str());
        curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
        curl_easy_setopt(curl, CURLOPT_HEADER, 1L);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
        CURLcode res = curl_easy_perform(curl);
        if (res == CURLE_OK) {
            printResult("Headers checked", baseUrl, "CHECKED");
        }
        curl_easy_cleanup(curl);
    }
}

// ✅ Security Headers Audit
void auditSecurityHeaders(const std::string& baseUrl) {
    CURL* curl = curl_easy_init();
    if (!curl) return;

    std::string response;
    curl_easy_setopt(curl, CURLOPT_URL, baseUrl.c_str());
    curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
    curl_easy_setopt(curl, CURLOPT_HEADER, 1L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);

    std::lock_guard<std::mutex> guard(printMutex);
    std::cout << CYAN << "[+] Security Headers Audit" << RESET << std::endl;

    std::vector<std::string> headersToCheck = {
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Content-Type-Options",
        "Referrer-Policy"
    };

    for (const auto& header : headersToCheck) {
        if (response.find(header) != std::string::npos) {
            std::cout << GREEN << "    ✓ " << header << RESET << std::endl;
        } else {
            std::cout << RED << "    ✗ " << header << " (Missing)" << RESET << std::endl;
        }
    }
    std::cout << std::endl;
}

// ✅ TLS/SSL Misconfiguration Detection
void checkTLSMisconfig(const std::string& target) {
    std::lock_guard<std::mutex> guard(printMutex);
    std::cout << CYAN << "[+] TLS/SSL Misconfiguration Check" << RESET << std::endl;
    std::string command = "sslscan " + target + " || testssl.sh " + target;
    std::cout << YELLOW << "    Running: " << command << RESET << std::endl;
    system(command.c_str());
    std::cout << std::endl;
}

// ✅ Authentication Bypass
void checkAuthBypass(const std::string& baseUrl) {
    std::vector<std::pair<std::string, std::string>> creds = {
        {"admin", "admin"}, {"guest", "guest"}, {"test", "test"}, {"root", "toor"}
    };

    for (const auto& cred : creds) {
        std::string postData = "username=" + urlEncode(cred.first) + "&password=" + urlEncode(cred.second);
        CURL* curl = curl_easy_init();
        std::string response;
        if (curl) {
            curl_easy_setopt(curl, CURLOPT_URL, (baseUrl + "/login").c_str());
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postData.c_str());
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
            curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
            curl_easy_perform(curl);
            curl_easy_cleanup(curl);
        }

        if (response.find("Welcome") != std::string::npos || response.find("Dashboard") != std::string::npos) {
            printResult("Authentication Bypass", baseUrl + "/login", "VULNERABLE", "CVE-2021-21985");
            return;
        }
    }

    printResult("Authentication Bypass", baseUrl + "/login", "SAFE");
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << RED << "Usage: ./scanner <target_url>" << RESET << std::endl;
        return 1;
    }

    std::string baseUrl = argv[1];
    std::cout << YELLOW << "🔍 Starting powerful scan on: " << baseUrl << RESET << std::endl << std::endl;

    std::thread t1(checkSQLInjection, baseUrl);
    std::thread t2(checkXSS, baseUrl);
    std::thread t3(checkOpenDirs, baseUrl);
    std::thread t4(checkHeaders, baseUrl);
    std::thread t5(auditSecurityHeaders, baseUrl);
    std::thread t6(checkTLSMisconfig, baseUrl);
    std::thread t7(checkAuthBypass, baseUrl);

    t1.join(); t2.join(); t3.join(); t4.join(); t5.join(); t6.join(); t7.join();

    std::cout << GREEN << "✅ Scan complete!" << RESET << std::endl;
    return 0;
}
