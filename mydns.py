#!/usr/bin/env python3

import socket
import sys
import random
import struct
import time

# DNS constants
DNS_PORT = 53
DNS_QUERY_TIMEOUT = 5  # seconds
MAX_DNS_MESSAGE_SIZE = 512  # bytes, standard UDP DNS message size

# DNS Header flag fields
QR_QUERY = 0
QR_RESPONSE = 1
OPCODE_STANDARD_QUERY = 0
AA_NOT_AUTH = 0 
TC_NOT_TRUNCATED = 0
RD_NO_RECURSION = 0  # We want iterative resolution
RA_NO_RECURSION_AVAILABLE = 0
Z_RESERVED = 0
RCODE_NO_ERROR = 0

# Resource Record Types
TYPE_A = 1     # Address record
TYPE_NS = 2    # Name server record
TYPE_CNAME = 5 # Canonical name record
TYPE_SOA = 6   # Start of authority record
TYPE_PTR = 12  # Pointer record
TYPE_MX = 15   # Mail exchange record
TYPE_TXT = 16  # Text record
TYPE_AAAA = 28 # IPv6 address record
TYPE_SRV = 33  # Service record

# Resource Record Classes
CLASS_IN = 1   # Internet

def main():
    # Check command line arguments
    if len(sys.argv) != 3:
        print("Usage: python3 mydns.py domain-name root-dns-ip")
        sys.exit(1)
    
    domain_name = sys.argv[1]
    root_dns_ip = sys.argv[2]
    
    # Start the DNS resolution process
    resolve_domain(domain_name, root_dns_ip)

def resolve_domain(domain_name, dns_server_ip):
    """
    Performs iterative DNS resolution for the given domain name.
    """
    # Keep track of the servers we've queried to avoid loops
    queried_servers = set()
    
    while True:
        print("-" * 64)
        print(f"DNS server to query: {dns_server_ip}")
        
        # Send query and get response
        query_message = build_dns_query(domain_name)
        response_data = send_dns_query(query_message, dns_server_ip)
        
        if not response_data:
            print(f"No response received from {dns_server_ip}")
            break
        
        # Parse the response
        parsed_response = parse_dns_response(response_data, domain_name)
        
        if not parsed_response:
            print(f"Failed to parse response from {dns_server_ip}")
            break
        
        # Extract the sections from the parsed response
        (header, question, answers, authority, additional) = parsed_response
        
        # Display the response content
        display_response_content(header, answers, authority, additional)
        
        # Check if we have an answer (A record) for our domain
        if answers and any(answer['type'] == TYPE_A for answer in answers):
            # We found our answer, we can stop
            break
        
        # If no answer, select next server to query from authority and additional sections
        next_server_ip = get_next_server_ip(authority, additional, queried_servers)
        
        if not next_server_ip:
            print("Could not determine next server to query.")
            break
        
        # Add this server to our queried list
        queried_servers.add(dns_server_ip)
        
        # Update the DNS server IP for the next iteration
        dns_server_ip = next_server_ip

def build_dns_query(domain_name):
    """
    Constructs a DNS query message for the given domain name.
    """
    # Generate a random transaction ID
    transaction_id = random.randint(0, 65535)
    
    # Build the header
    flags = (QR_QUERY << 15) | (OPCODE_STANDARD_QUERY << 11) | (AA_NOT_AUTH << 10) | \
            (TC_NOT_TRUNCATED << 9) | (RD_NO_RECURSION << 8) | (RA_NO_RECURSION_AVAILABLE << 7) | \
            (Z_RESERVED << 4) | RCODE_NO_ERROR
    
    qdcount = 1  # We're sending one question
    ancount = 0  # No answers in a query
    nscount = 0  # No authority records in a query
    arcount = 0  # No additional records in a query
    
    header = struct.pack('!HHHHHH', transaction_id, flags, qdcount, ancount, nscount, arcount)
    
    # Build the question section
    question = b''
    
    # Split domain into labels (e.g., "www.example.com" -> ["www", "example", "com"])
    labels = domain_name.split('.')
    
    # Encode each label as length + label
    for label in labels:
        label_bytes = label.encode('ascii')
        question += struct.pack('B', len(label_bytes)) + label_bytes
    
    # Terminate with a zero-length label
    question += b'\x00'
    
    # Add QTYPE and QCLASS
    question += struct.pack('!HH', TYPE_A, CLASS_IN)
    
    # Combine all parts of the message
    return header + question

def send_dns_query(query_message, dns_server_ip):
    """
    Sends a DNS query to the specified DNS server and returns the response.
    """
    try:
        # Create a UDP socket
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            # Set timeout to avoid hanging if no response
            s.settimeout(DNS_QUERY_TIMEOUT)
            
            # Send the query
            s.sendto(query_message, (dns_server_ip, DNS_PORT))
            
            # Receive the response
            response, _ = s.recvfrom(MAX_DNS_MESSAGE_SIZE)
            
            return response
    except socket.timeout:
        print(f"Timeout waiting for response from {dns_server_ip}")
        return None
    except Exception as e:
        print(f"Error communicating with DNS server {dns_server_ip}: {e}")
        return None

def parse_dns_response(response_data, queried_domain):
    """
    Parses a DNS response message.
    """
    try:
        # Parse the header
        header_size = 12
        header_data = response_data[:header_size]
        
        header = {}
        header['id'], flags, header['qdcount'], header['ancount'], header['nscount'], header['arcount'] = struct.unpack('!HHHHHH', header_data)
        
        # Extract flag fields
        header['qr'] = (flags >> 15) & 0x1
        header['opcode'] = (flags >> 11) & 0xF
        header['aa'] = (flags >> 10) & 0x1
        header['tc'] = (flags >> 9) & 0x1
        header['rd'] = (flags >> 8) & 0x1
        header['ra'] = (flags >> 7) & 0x1
        header['z'] = (flags >> 4) & 0x7
        header['rcode'] = flags & 0xF
        
        # Check if the response is an error
        if header['rcode'] != 0:
            print(f"DNS server returned error code: {header['rcode']}")
            return None
        
        # Parse the question section (to skip over it)
        offset = header_size
        question_domains = []
        
        for _ in range(header['qdcount']):
            domain_name, offset = parse_domain_name(response_data, offset)
            question_domains.append(domain_name)
            # Skip qtype and qclass (each 2 bytes)
            offset += 4
        
        # Parse the answer section
        answers = []
        for _ in range(header['ancount']):
            answer, offset = parse_resource_record(response_data, offset)
            answers.append(answer)
        
        # Parse the authority section
        authority = []
        for _ in range(header['nscount']):
            auth, offset = parse_resource_record(response_data, offset)
            authority.append(auth)
        
        # Parse the additional section
        additional = []
        for _ in range(header['arcount']):
            additional_rr, offset = parse_resource_record(response_data, offset)
            additional.append(additional_rr)
        
        return (header, question_domains, answers, authority, additional)
        
    except Exception as e:
        print(f"Error parsing DNS response: {e}")
        return None

def parse_domain_name(message, offset):
    """
    Parses a domain name from a DNS message, handling compression.
    Returns the domain name and the new offset.
    """
    domain_parts = []
    
    # Keep track of the original offset to return to after compression jumps
    original_offset = offset
    jumped = False
    
    # Maximum number of jumps to prevent infinite loops
    max_jumps = 10
    jump_count = 0
    
    while True:
        # Get the length byte
        length = message[offset]
        offset += 1
        
        # Check if we're at the end of the domain name
        if length == 0:
            break
        
        # Check for compression (two highest bits set)
        if (length & 0xC0) == 0xC0:
            # It's a pointer - the lower 14 bits are the offset to jump to
            pointer_offset = ((length & 0x3F) << 8) | message[offset]
            offset += 1
            
            # If this is our first jump, keep track of where to return to
            if not jumped:
                original_offset = offset
                jumped = True
            
            # Update the offset to the pointer location
            offset = pointer_offset
            
            # Prevent infinite loops
            jump_count += 1
            if jump_count >= max_jumps:
                raise Exception("Too many compression jumps in domain name")
            
            continue
        
        # Regular label - extract it
        label = message[offset:offset+length].decode('ascii')
        domain_parts.append(label)
        offset += length
    
    # If we jumped, return to the original location
    if jumped:
        offset = original_offset
    
    return '.'.join(domain_parts), offset

def parse_resource_record(message, offset):
    """
    Parses a resource record from a DNS message.
    Returns the record as a dictionary and the new offset.
    """
    # Parse the domain name
    name, offset = parse_domain_name(message, offset)
    
    # Get type, class, TTL, and data length
    record_type, record_class, ttl, rdlength = struct.unpack('!HHIH', message[offset:offset+10])
    offset += 10
    
    # Create the record dictionary
    record = {
        'name': name,
        'type': record_type,
        'class': record_class,
        'ttl': ttl,
        'rdlength': rdlength
    }
    
    # Parse the RDATA field based on the record type
    rdata_start = offset
    
    if record_type == TYPE_A and record_class == CLASS_IN and rdlength == 4:
        # A record - IPv4 address
        ip_bytes = message[offset:offset+rdlength]
        record['data'] = '.'.join(str(b) for b in ip_bytes)
    elif record_type == TYPE_NS:
        # NS record - nameserver domain name
        ns_name, _ = parse_domain_name(message, offset)
        record['data'] = ns_name
    else:
        # Other record types - just store the raw data
        record['data'] = message[offset:offset+rdlength]
    
    # Move the offset past the RDATA field
    offset = rdata_start + rdlength
    
    return record, offset

def display_response_content(header, answers, authority, additional):
    """
    Displays the content of a DNS response.
    """
    print("Reply received. Content overview:")
    print(f"{len(answers)} Answers.")
    print(f"{len(authority)} Intermediate Name Servers.")
    print(f"{len(additional)} Additional Information Records.")
    
    print("Answers section: ")
    for answer in answers:
        if answer['type'] == TYPE_A:
            print(f"Name : {answer['name']} IP: {answer['data']}")
        else:
            print(f"Name : {answer['name']} Data: {answer['data']}")
    
    print("Authority Section:")
    for auth in authority:
        if auth['type'] == TYPE_NS:
            print(f"Name : {auth['name']} Name Server: {auth['data']}")
        else:
            print(f"Name : {auth['name']} Type: {auth['type']} Data: {auth['data']}")
    
    print("Additional Information Section:")
    for add in additional:
        if add['type'] == TYPE_A:
            print(f"Name : {add['name']} IP : {add['data']}")
        else:
            print(f"Name : {add['name']} Type: {add['type']} Data: {add['data']}")

def get_next_server_ip(authority, additional, queried_servers):
    """
    Selects the next DNS server to query.
    Looks for NS records in the authority section, then finds their IPs in the additional section.
    """
    # Get all name servers from the authority section
    name_servers = []
    for auth in authority:
        if auth['type'] == TYPE_NS:
            name_servers.append(auth['data'])
    
    # If no name servers found
    if not name_servers:
        return None
    
    # Find the IP addresses for the name servers in the additional section
    ns_to_ip = {}
    for add in additional:
        if add['type'] == TYPE_A and add['name'] in name_servers:
            ns_to_ip[add['name']] = add['data']
    
    # If we have IPs for name servers, choose one that we haven't queried yet
    for ns, ip in ns_to_ip.items():
        if ip not in queried_servers:
            print(f"Name : {ns}")
            return ip
    
    # If all servers have been queried, just choose the first one as a fallback
    if ns_to_ip:
        first_ns = next(iter(ns_to_ip))
        print(f"Name : {first_ns} (already queried, but trying again)")
        return ns_to_ip[first_ns]
    
    # If we can't find any IPs for the name servers
    return None

if __name__ == "__main__":
    main()