#!/usr/bin/env python3
from __future__ import annotations

import argparse
import random
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin

import requests


ROUTES = [
    "/",
    "/dashboard",
    "/api/metrics",
    "/api/refresh",
]


def build_targets(base_url: str, routes: list[str]) -> list[str]:
    base = base_url.rstrip("/") + "/"
    return [urljoin(base, route.lstrip("/")) for route in routes]


def send_one(session: requests.Session, url: str, timeout: float) -> tuple[str, int | None]:
    try:
        resp = session.get(url, timeout=timeout)
        return url, resp.status_code
    except Exception:
        return url, None


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Safe demo traffic generator for a local Flask dashboard"
    )
    parser.add_argument(
        "--url",
        required=True,
        help="Base URL of the hosting machine, e.g. http://10.216.2.117:5000",
    )
    parser.add_argument(
        "--requests",
        type=int,
        default=250,
        help="Total number of requests to send (default: 250)",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=8,
        help="Concurrent workers (default: 8)",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0.05,
        help="Small delay between request rounds in seconds (default: 0.05)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=2.0,
        help="Request timeout in seconds (default: 2.0)",
    )
    parser.add_argument(
        "--round-size",
        type=int,
        default=8,
        help="How many requests to dispatch per round (default: 8)",
    )
    args = parser.parse_args()

    if args.requests <= 0:
        print("Requests must be greater than 0.", file=sys.stderr)
        return 1

    if args.workers < 1:
        print("Workers must be at least 1.", file=sys.stderr)
        return 1

    if args.round_size < 1:
        print("Round size must be at least 1.", file=sys.stderr)
        return 1

    if not args.url.startswith(("http://", "https://")):
        print("URL must start with http:// or https://", file=sys.stderr)
        return 1

    targets = build_targets(args.url, ROUTES)
    session = requests.Session()

    sent = 0
    ok = 0
    failed = 0

    print(f"Target: {args.url}")
    print(f"Total requests: {args.requests}")
    print(f"Workers: {args.workers}")
    print("Starting controlled traffic...\n")

    try:
        while sent < args.requests:
            batch = min(args.round_size, args.requests - sent)
            urls = [random.choice(targets) for _ in range(batch)]

            with ThreadPoolExecutor(max_workers=args.workers) as executor:
                futures = [
                    executor.submit(send_one, session, url, args.timeout)
                    for url in urls
                ]

                for fut in as_completed(futures):
                    _, status = fut.result()
                    sent += 1
                    if status is not None and 200 <= status < 500:
                        ok += 1
                    else:
                        failed += 1

            print(
                f"Sent: {sent}/{args.requests} | "
                f"Success: {ok} | Failed: {failed}",
                end="\r",
                flush=True,
            )
            time.sleep(args.delay)

    except KeyboardInterrupt:
        print("\nStopped by user.")
    finally:
        session.close()

    print("\nDone.")
    print(f"Sent: {sent}")
    print(f"Success: {ok}")
    print(f"Failed: {failed}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
