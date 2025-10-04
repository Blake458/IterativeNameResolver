"""
  NS --> ROOT --> NS
  NS --> TLD  --> NS
  A --> Auth --> A or CNAME or NS
  if CAME or NS run through again
"""

from dnslib import DNSRecord, DNSHeader, DNSBuffer, DNSQuestion, RR, QTYPE, RCODE
from socket import socket, SOCK_DGRAM, AF_INET

"""
There are 13 root servers defined at https://www.iana.org/domains/root/servers
"""


ROOT_SERVER = "199.7.83.42"    # ICANN Root Server
DNS_PORT = 53

class Cache():
  def __init__(self):
    """resolved_names follows format: {domain_name : set(ip_addresses)}"""
    self.resolved_names = {}
    self.length = 0

  def remove(self, N:int):
        i = 0
        delete = None
        if 0 <= N < self.length:
          for name in self.resolved_names.keys():
            if i == N:
              delete = name
            i += 1
          if delete is not None:
            self.resolved_names.pop(delete)
          else:
            print("Error: tried to remove a non-existant cache")
        else:
          print("Error: tried to remove a non-existant cache")

  def clear(self):
    self.resolved_names.clear()
    self.length = 0

  def insert(self, new_name, new_ips: set):
    self.resolved_names.update({new_name : new_ips})
    self.length += 1

  def check(self, domain_name):
    """
    returns: ip address if domain name is cached, otherwise None

    args:
      domain_name - the domain name you want to look up in cache
    """
    if domain_name in self.resolved_names.keys():
      return self.resolved_names[domain_name]
    else:
      return None


def get_dns_record(udp_socket, domain:str, parent_server: str, record_type, depth=0):
  """
  Iterative/recursive resolver helper.
  Returns: list[RR] (answers) on success, None on failure.
  - udp_socket: UDP socket
  - domain: domain to resolve (string)
  - parent_server: IP of server to query
  - record_type: "A" or QTYPE int
  - depth/max_depth: prevent infinite recursion
  """
  if depth > 10:
    print(f"Max recursion depth reached")
    return None
  
  try:
    query = DNSRecord.question(domain, qtype = record_type)
    query.header.rd = 0   # Recursion Desired?  NO
    udp_socket.sendto(query.pack(), (parent_server, DNS_PORT))
    pkt, _ = udp_socket.recvfrom(8192)
    buff = DNSBuffer(pkt)
  except TimeoutError:
    print("Error: Timed out")
    return None
  except Exception as e:
    print(f"Error {e}: Domain Name is unresolvable")
    return None
  
  """
  RFC1035 Section 4.1 Format
  
  The top level format of DNS message is divided into five sections:
  1. Header
  2. Question
  3. Answer
  4. Authority
  5. Additional
  """

  """Parse the header section #1"""
  header = DNSHeader.parse(buff)
  queries = []
  answers = []
  authorities = []
  additionals = []

  if query.header.id != header.id:
    print("ERROR: Unmatched transaction")
    return None
  
  if header.rcode != RCODE.NOERROR:
    print("ERROR: Query failed!")
    return None

  """Parse the question section #2"""
  for _ in range(header.q):
    queries.append(DNSQuestion.parse(buff))
    
  """Parse the answer section #3"""
  for _ in range(header.a):
    answers.append(RR.parse(buff))
      
  """Parse the authority section #4"""
  for _ in range(header.auth):
    authorities.append(RR.parse(buff))
      
  """Parse the additional section #5"""
  for _ in range(header.ar):
    additionals.append(RR.parse(buff))

  if answers != []:
    return answers
  
  if additionals != []:
    for additional in additionals:
      if additional.rdata != parent_server:
        print(f"Additional Server Contacted: {str(additional.rdata)}")
        if additional.rtype == QTYPE.NS:
          ip = str(get_dns_record(udp_socket, str(additional.rdata), ROOT_SERVER, "A", depth + 1)[0].rdata)
          print(f"Authority alias resolved to: {ip}")
        else:
          ip = str(additional.rdata)
        return get_dns_record(udp_socket, domain, ip, "A", depth + 1)

  if authorities != []:
    for authority in authorities:
      if authority.rdata != parent_server:
        print(f"Authority Server Contacted: {str(authority.rdata)}")
        if authority.rtype == QTYPE.NS:
          ip = str(get_dns_record(udp_socket, str(authority.rdata), ROOT_SERVER, "A", depth + 1)[0].rdata)
          print(f"Authority alias resolved to: {ip}")
        else:
          ip = str(authority.rdata)
        return get_dns_record(udp_socket, domain, ip, "A", depth + 1)
      
  return None
  

  
if __name__ == '__main__':
    cache = Cache()
    # Create a UDP socket
    sock = socket(AF_INET, SOCK_DGRAM)
    sock.settimeout(2)
  
    while True:
      domain_name = input("Enter a domain name or .exit > ").strip()

      if not domain_name:
        continue

      # exit
      if domain_name == '.exit':
          break
      
      # list the cache
      elif domain_name == '.list':
        i = 0
        for name, ips in cache.resolved_names.items():
            print(f"{i} - {name}: {ips}")
            i += 1
      
      # clear the cache
      elif domain_name == '.clear':
        cache.clear()

      # remove element from the cache
      elif domain_name.startswith('.remove'):
        split_input = domain_name.split()
        if len(split_input) == 2:
          if split_input[1].isdigit():
            cache.remove(int(split_input[1]))
          else:
            print("Error: .remove only accepts type int")
        else:
          print("Error: .remove requires 1 number as input")

      # try to resolve url
      else:
        query_not_resolved = True
        cached_answer = cache.check(domain_name) # check if its saved in cache
       
        if cached_answer is not None:
          print(f"Answer Retreaved from cache:\n{domain_name}")
          for answer in cached_answer: print(f"{answer}")
          query_not_resolved = False

        while query_not_resolved:
          ips = set()
          answers = get_dns_record(sock, domain_name, ROOT_SERVER, "A")
          if answers is None:
            print(f"DNS: {domain_name} not resolvable")
            break
          elif type(answers[0]) == RR:
            query_not_resolved = False
            print(f"Query Resolved:\n{domain_name}:")
            for answer in answers:
              ips.add(str(answer.rdata))  # turn answers into set of ips
              if answer.rtype == QTYPE.A:
                print(f"IP4 Address:\t{answer.rdata}")
              elif answer.rtype == QTYPE.AAAA:
                print(f"IP6 Address:\t{answer.rdata}")
              elif answer.rtype == QTYPE.CNAME:
                alias = str(answer.rdata).rstrip('.')
                print(f"Alias: {alias}")
                answer = get_dns_record(sock, alias, ROOT_SERVER, "A")
              else:
                print(answer.rdata)

        # if not in cache, insert into cache
        if not cache.check(domain_name):
          try:
            if ips != set():
             cache.insert(domain_name, ips)
          except NameError:
            pass


    sock.close()
