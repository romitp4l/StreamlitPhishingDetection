import datetime
import socket
import ssl
import whois

from datetime import date
from functools import lru_cache
from urllib.parse import urlparse


def url_length(url):
  return len(str(url))

def count_question_url(url):
  return url.count('?')

def count_equal_url(url):
  return url.count('=')

def count_http_url(url):
  result = urlparse(url)
  if result.scheme == 'http':
    return 1
  else:
    return 0

def count_https_url(url):
  result = urlparse(url)
  if result.scheme == 'https':
    return 1
  else:
    return 0
def count_tilde(url):
  return url.count('~')
def count_dot_url(url):
  return url.count('.')

def count_hyphen_url(url):
  return url.count('-')

def count_underline_url(url):
  return url.count('_')

def count_question_url(url):
  return url.count('?')

def count_slash_url(url):
  path = str(urlparse(url).path)
  return path.count('/')

@lru_cache(maxsize=None)

def get_domain_info(url):
    return whois.whois(url)

def age_of_domain(url):
    try:
        res = get_domain_info(url)
        current_date = datetime.combine(date.today(), datetime.min.time())
        creation_date = res.creation_date[0] if isinstance(res.creation_date, list) else res.creation_date
        # Calculate the domain age correctly
        domain_age = (current_date - creation_date).days
        return int(domain_age)
    except:
        return 0

def registration_length(url):
    try:
        res = get_domain_info(url)
        creation_date = res.creation_date[0] if isinstance(res.creation_date, list) else res.creation_date
        expiration_date = res.expiration_date[0] if isinstance(res.expiration_date, list) else res.expiration_date
        registration_length = (expiration_date - creation_date).days
        return int(registration_length)
    except:
        return 0

def verify_ssl_certificate(url, timeout=5):
    hostname = urlparse(url).netloc
    context = ssl.create_default_context()
    try:
        # Resolve the hostname first
        address_info = socket.getaddrinfo(hostname, 443, proto=socket.IPPROTO_TCP)
        address = address_info[0][4]  # Extract the address tuple

        # Create a socket connection with a timeout
        with socket.create_connection(address, timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                ssock.do_handshake()
                cert = ssock.getpeercert()
                return 1
    except Exception as e:
        return 0