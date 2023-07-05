import argparse
import socket
import concurrent.futures
import time

def scan(target, port, timeout, output_file):
    # Get IP address of target
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        print(f"Invalid hostname: {target}")
        return

    # Create a TCP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    # Attempt to connect to the port
    result = sock.connect_ex((ip, port))

    # Check if port is open
    if result == 0:
        open_port = f"{ip}:{port} - Open"
        print(open_port)
        with open(output_file, "a") as file:
            file.write(open_port + "\n")

    sock.close()

def threaded_scan(target, start_port, end_port, num_threads, timeout, output_file):
    # Create a thread pool
    with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
        # Submit port scanning tasks to the thread pool
        futures = []
        for port in range(start_port, end_port + 1):
            futures.append(executor.submit(scan, target, port, timeout, output_file))

        # Wait for all tasks to complete
        concurrent.futures.wait(futures)

def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Python Port Scanner")
    parser.add_argument("target_file", help="text file containing target hostnames or IP addresses")
    parser.add_argument("--start-port", type=int, default=1, help="first port to scan (default: 1)")
    parser.add_argument("--end-port", type=int, default=1024, help="last port to scan (default: 1024)")
    parser.add_argument("--num-threads", type=int, default=10, help="number of threads to use (default: 10)")
    parser.add_argument("--timeout", type=float, default=0.5, help="timeout for each connection attempt (default: 0.5)")
    parser.add_argument("--output-file", default="scan_results.txt", help="output file to save the results (default: scan_results.txt)")
    args = parser.parse_args()

    # Read targets from file
    targets = []
    with open(args.target_file, "r") as file:
        targets = [line.strip() for line in file if line.strip()]

    if not targets:
        print("No targets specified.")
        return

    # Perform port scan
    start_time = time.time()
    for target in targets:
        threaded_scan(target, args.start_port, args.end_port, args.num_threads, args.timeout, args.output_file)
    end_time = time.time()

    # Print results
    print(f"\nScan completed in {end_time - start_time:.2f} seconds")
    print(f"Results saved to {args.output_file}")

if __name__ == "__main__":
    main()
