import sys
import time
import os
import urllib.request
import socket
from datetime import datetime

MAX_DURATION = float(os.getenv("MAX_DURATION") or 1)
INTERVAL = float(os.getenv("INTERVAL") or 1)


def print_with_timestamp(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    print(f"{timestamp} {message}")


def run(url):
    try:
        with urllib.request.urlopen(url) as response:
            code = response.getcode()
            body = response.read().decode("utf-8")
            print_with_timestamp(f"{code}: {body}")
    except urllib.error.URLError as e:
        print_with_timestamp(f"Request failed: {e.reason}")
    except socket.timeout:
        print_with_timestamp(f"Request timed out after {MAX_DURATION} seconds")
    except Exception as e:
        print_with_timestamp(f"An error occurred: {e}")


# Main request logic
def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <URL>")
        sys.exit(1)

    url = sys.argv[1]

    # Set the socket timeout for the request to enforce a maximum duration
    socket.setdefaulttimeout(MAX_DURATION)

    while True:
        run(url)
        time.sleep(INTERVAL)


if __name__ == "__main__":
    sys.exit(main())
