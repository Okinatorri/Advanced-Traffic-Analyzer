import argparse
import sys
from collections import Counter, defaultdict
from datetime import datetime


def parse_args():
    parser = argparse.ArgumentParser(description="Advanced Traffic Analyzer")

    parser.add_argument("logfile", help="Path to access.log file")

    parser.add_argument("--method", help="Filter by HTTP method")
    parser.add_argument("--status", help="Filter by status code or range (e.g. 400-499)")
    parser.add_argument("--start", type=int, help="Start timestamp")
    parser.add_argument("--end", type=int, help="End timestamp")
    parser.add_argument("--top", type=int, default=3, help="Top N IPs (default: 3)")

    return parser.parse_args()


def parse_status_filter(status_filter):
    if not status_filter:
        return None

    if "-" in status_filter:
        try:
            start, end = map(int, status_filter.split("-"))
            return start, end
        except ValueError:
            raise ValueError("Invalid status range format")
    else:
        try:
            code = int(status_filter)
            return code, code
        except ValueError:
            raise ValueError("Invalid status code format")


def parse_line(line, line_number):
    parts = line.strip().split()
    if len(parts) != 6:
        print(f"Warning: invalid format at line {line_number}", file=sys.stderr)
        return None

    try:
        timestamp = int(parts[0])
        ip = parts[1]
        method = parts[2]
        url = parts[3]
        status = int(parts[4])
        size = int(parts[5])
    except ValueError:
        print(f"Warning: invalid data types at line {line_number}", file=sys.stderr)
        return None

    return timestamp, ip, method, url, status, size


def readable_bytes(num):
    for unit in ["B", "KB", "MB", "GB"]:
        if num < 1024:
            return f"{num:.2f} {unit}"
        num /= 1024
    return f"{num:.2f} TB"


def main():
    args = parse_args()

    try:
        status_range = parse_status_filter(args.status)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    total_requests = 0
    unique_ips = set()
    ip_counter = Counter()
    url_counter = Counter()
    method_counter = Counter()

    total_bytes = 0

    success_count = 0
    success_bytes = 0
    client_error_count = 0
    server_error_count = 0

    all_timestamps = []
    recent_ips = set()
    hourly_requests = defaultdict(int)

    try:
        with open(args.logfile, "r") as f:
            for line_number, line in enumerate(f, 1):
                parsed = parse_line(line, line_number)
                if not parsed:
                    continue

                timestamp, ip, method, url, status, size = parsed

                # Filters
                if args.method and method != args.method:
                    continue

                if status_range:
                    if not (status_range[0] <= status <= status_range[1]):
                        continue

                if args.start and timestamp < args.start:
                    continue

                if args.end and timestamp > args.end:
                    continue

                # Statistics
                total_requests += 1
                unique_ips.add(ip)
                ip_counter[ip] += 1
                url_counter[url] += 1
                method_counter[method] += 1
                total_bytes += size

                all_timestamps.append(timestamp)

                if 200 <= status <= 299:
                    success_count += 1
                    success_bytes += size
                elif 400 <= status <= 499:
                    client_error_count += 1
                elif 500 <= status <= 599:
                    server_error_count += 1

    except FileNotFoundError:
        print("Error: log file not found", file=sys.stderr)
        sys.exit(1)
    except PermissionError:
        print("Error: no permission to read log file", file=sys.stderr)
        sys.exit(1)

    if not all_timestamps:
        print("No data after applying filters")
        sys.exit(0)

    latest_timestamp = max(all_timestamps)
    last_24h_start = latest_timestamp - 86400

    try:
        with open(args.logfile, "r") as f:
            for line_number, line in enumerate(f, 1):
                parsed = parse_line(line, line_number)
                if not parsed:
                    continue

                timestamp, ip, _, _, _, _ = parsed

                if timestamp >= last_24h_start:
                    recent_ips.add(ip)
                    hour = datetime.utcfromtimestamp(timestamp).strftime("%Y-%m-%d %H:00")
                    hourly_requests[hour] += 1
    except Exception:
        pass

    print("\nTRAFFIC ANALYSIS REPORT\n")

    print("Filter settings:")
    print(f"- Time range: {args.start or 'all time'} - {args.end or 'all time'}")
    print(f"- Method filter: {args.method or 'all methods'}")
    print(f"- Status filter: {args.status or 'all statuses'}\n")

    print("Basic statistics:")
    print(f"Total requests: {total_requests}")
    print(f"Unique IPs: {len(unique_ips)}")
    print(f"Total data transferred: {total_bytes} ({readable_bytes(total_bytes)})\n")

    print("Request distribution:")
    for method, count in method_counter.items():
        percent = (count / total_requests) * 100
        print(f"- {method}: {percent:.1f}%")

    print("\nPerformance metrics:")
    print(f"- Successful requests (2xx): {success_count}")
    print(f"- Client errors (4xx): {client_error_count}")
    print(f"- Server errors (5xx): {server_error_count}")
    if success_count:
        print(f"- Average response size (2xx): {success_bytes // success_count} bytes")

    print(f"\nTop {args.top} active IPs:")
    for i, (ip, count) in enumerate(ip_counter.most_common(args.top), 1):
        print(f"{i}. {ip}: {count} requests")

    print("\nTop 5 requested URLs:")
    for i, (url, count) in enumerate(url_counter.most_common(5), 1):
        print(f"{i}. {url}: {count}")

    print("\nRecent activity (last 24h):")
    print(f"- Unique IPs: {len(recent_ips)}")
    print("- Requests per hour:")
    for hour, count in sorted(hourly_requests.items()):
        print(f"  {hour}: {count}")


if __name__ == "__main__":
    main()
