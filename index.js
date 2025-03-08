const dgram = require('dgram'); // For UDP handling
const tls = require('tls'); // For DNS over TLS
const net = require('net');

const LOCAL_UDP_PORT = 533; // Listen for DNS queries
const UPSTREAM_DNS = { host: '1.1.1.1', port: 853 }; // Cloudflare DoT

class SuffixTrie {
    constructor(suffixes) {
        this.root = {};
        for (const suffix of suffixes) {
            this.insert(suffix);
        }
    }

    insert(suffix) {
        let node = this.root;
        for (let i = suffix.length - 1; i >= 0; i--) { // Insert backwards
            let char = suffix[i];
            if (!node[char]) node[char] = {};
            node = node[char];
        }
        node["end"] = true;
    }

    matches(str) {
        let node = this.root;
        for (let i = str.length - 1; i >= 0; i--) { // Check backwards
            let char = str[i];
            if (!node[char]) return false;
            node = node[char];
            if (node["end"]) return true; // Found a match
        }
        return false;
    }
}

const overrideDomains = ['google.com', 'youtube.com'];
const trie = new SuffixTrie(overrideDomains);
const overrideIP = '192.168.1.100';

// Create a UDP server to handle DNS queries
const udpServer = dgram.createSocket('udp4');

udpServer.on('message', (msg, rinfo) => {
    console.log(`Received DNS query from ${rinfo.address}:${rinfo.port}`);

    const query = parseDNSQuery(msg);
    if (!query) return;

    const { id, domain } = query;

    if (trie.matches(domain)) {
        console.log(`Overriding DNS for ${domain} -> ${overrideIP}`);
        const response = buildDNSResponse(id, domain, overrideIP);
        udpServer.send(response, rinfo.port, rinfo.address);
    } else {
        // Establish TLS connection to upstream DoT server
        const tlsSocket = tls.connect(UPSTREAM_DNS, () => {
            console.log("Connected to upstream DoT server");
            // Send the raw DNS query over TLS
            tlsSocket.write(encodeLength(msg));
        });

        tlsSocket.on('data', (data) => {
            // Extract the DNS response and send it back to the original client
            const response = decodeLength(data);
            udpServer.send(response, rinfo.port, rinfo.address, (err) => {
                if (err) console.error("Error sending response:", err);
            });
            tlsSocket.end(); // Close the TLS connection after response
        });

        tlsSocket.on('error', (err) => console.error("TLS error:", err));
    }


});

// Start the UDP server
udpServer.bind(LOCAL_UDP_PORT, () => {
    console.log(`DNS Proxy listening on UDP port ${LOCAL_UDP_PORT}`);
});

// Helper function to encode message length for TLS (DoT requires a 2-byte length prefix)
function encodeLength(data) {
    const length = Buffer.alloc(2);
    length.writeUInt16BE(data.length, 0);
    return Buffer.concat([length, data]);
}

// Helper function to decode TLS response (strip 2-byte length prefix)
function decodeLength(data) {
    return data.slice(2);
}

function parseDNSQuery(msg) {
    let domain = '';
    let offset = 12; // DNS question starts at byte 12

    while (msg[offset] !== 0) {
        let length = msg[offset];
        domain += msg.slice(offset + 1, offset + 1 + length).toString() + '.';
        offset += length + 1;
    }

    return { id: msg.slice(0, 2), domain: domain.slice(0, -1) };
}
// Build a proper DNS response for a given domain
function buildDNSResponse(id, domain, ip) {
    const domainParts = domain.split(".");
    let domainLength = domainParts.reduce((acc, part) => acc + part.length + 1, 1);

    // Buffer size dynamically calculated:
    // Header (12 bytes) + Domain + Type/Class (4 bytes) + Answer section (12 bytes) + IPv4 (4 bytes)
    let response = Buffer.alloc(12 + domainLength + 4 + 12 + 4);

    id.copy(response, 0); // Transaction ID
    response.writeUInt16BE(0x8180, 2); // Response flags: Standard response, no error
    response.writeUInt16BE(1, 4); // Questions count: 1
    response.writeUInt16BE(1, 6); // Answer RRs: 1
    response.writeUInt16BE(0, 8); // Authority RRs: 0
    response.writeUInt16BE(0, 10); // Additional RRs: 0

    let offset = 12;
    for (let part of domainParts) {
        response.writeUInt8(part.length, offset++);
        response.write(part, offset);
        offset += part.length;
    }
    response.writeUInt8(0, offset++); // End of domain
    response.writeUInt16BE(1, offset); // Type: A (IPv4)
    response.writeUInt16BE(1, offset + 2); // Class: IN (Internet)
    offset += 4;

    // Answer section
    response.writeUInt16BE(0xc00c, offset); // Name pointer (compression)
    response.writeUInt16BE(1, offset + 2); // Type A (IPv4)
    response.writeUInt16BE(1, offset + 4); // Class IN
    response.writeUInt32BE(60, offset + 6); // TTL: 60 seconds
    response.writeUInt16BE(4, offset + 10); // Data length: 4 bytes (IPv4)

    // Correct offset for IP address
    let ipOffset = offset + 12;
    ip.split(".").map(Number).forEach((octet, i) => {
        response.writeUInt8(octet, ipOffset + i);
    });

    return response;
}