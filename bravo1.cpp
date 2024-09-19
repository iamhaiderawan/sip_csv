#include <pcap.h>
#include <iostream>
#include <fstream>
#include <cstring>
#include <string>
#include <sstream>
#include <regex>
#include <vector>

using namespace std;

bool parseSIPHeaders(const u_char *data, int length, ofstream &csvFile, const string &filename) {
    string payload(reinterpret_cast<const char*>(data), length);
    stringstream ss(payload);
    string line;
    string toHeader, fromHeader;

    while (getline(ss, line)) {
        if (line.find("To:") == 0) {
            toHeader = line;
        } else if (line.find("From:") == 0) {
            fromHeader = line;
        }
    }

    regex sipPattern(R"(<sip:(\d+)@([\d\.]+))");
    smatch matches;
    bool headersFound = false;

    if (regex_search(toHeader, matches, sipPattern) && matches.size() == 3) {
        csvFile << filename << "," << "To" << "," << matches[1] << "," << matches[2] << endl;
        headersFound = true;
    }

    if (regex_search(fromHeader, matches, sipPattern) && matches.size() == 3) {
        csvFile << filename << "," << "From" << "," << matches[1] << "," << matches[2] << endl;
        headersFound = true;
    }

    return headersFound;
}

void processPcapFile(const string &filename, ofstream &csvFile) {
    char errbuff[PCAP_ERRBUF_SIZE];
    pcap_t *pcap = pcap_open_offline(filename.c_str(), errbuff);
    if (pcap == nullptr) {
        cerr << "Error opening pcap file " << filename << ": " << errbuff << endl;
        return;
    }

    struct pcap_pkthdr *header;
    const u_char *data;
    bool headerParsed = false;

    while (pcap_next_ex(pcap, &header, &data) >= 0) {
        if (data[12] != 0x08 || data[13] != 0x00) continue; // IPv4

        int ipHeaderLength = ((data[14] & 0x0F) * 4); // IP header length
        int udpHeaderLength = 8; // UDP header length
        const u_char *payload = data + 14 + ipHeaderLength + udpHeaderLength;
        int payloadLength = header->caplen - 14 - ipHeaderLength - udpHeaderLength;

        if (parseSIPHeaders(payload, payloadLength, csvFile, filename)) {
            headerParsed = true;
            break;
        }
    }

    pcap_close(pcap);
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        cerr << "Usage: " << argv[0] << " <output CSV file> <pcap file 1> <pcap file 2> ... <pcap file N>" << endl;
        return 1;
    }

    ofstream csvFile(argv[1]);
    if (!csvFile.is_open()) {
        cerr << "Error opening output CSV file " << argv[1] << endl;
        return 1;
    }

    csvFile << "Filename,Header Type,Number,IP" << endl;

    for (int i = 2; i < argc; ++i) {
        cout << "Processing file: " << argv[i] << endl;
        processPcapFile(argv[i], csvFile);
        cout << endl;
    }

    csvFile.close();
    return 0;
}
