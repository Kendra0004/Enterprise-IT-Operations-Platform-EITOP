"""CLI entry point: ``python -m eitop_collector`` / ``eitop-collector``.

Commands:
  enroll   — exchange an enrollment token for an endpoint credential
  run      — heartbeat + inventory loop (daemon mode)
  rotate   — replace this endpoint's credential
  collect  — print one inventory payload as JSON (local debug, no upload)
  status   — show endpoint id and credential file state (never the secret)

The enrollment token is NEVER accepted as a command-line argument (argv is
visible in `ps` and shell history): use EITOP_ENROLL_TOKEN, --token-stdin,
or the interactive prompt.
"""

from __future__ import annotations

import argparse
import getpass
import json
import logging
import os
import sys

from eitop_collector import __version__
from eitop_collector.api import CollectorError
from eitop_collector.collect import collect_all
from eitop_collector.config import ConfigError, load_config, redact_url
from eitop_collector.credentials import CredentialError, load_credentials
from eitop_collector.runner import Runner


def _read_enrollment_token(args: argparse.Namespace) -> str:
    if args.token_stdin:
        token = sys.stdin.readline().rstrip("\n")
    else:
        token = os.environ.get("EITOP_ENROLL_TOKEN", "")
        if not token and sys.stdin.isatty():
            token = getpass.getpass("Enrollment token (hidden): ").strip()
    if not token:
        raise SystemExit(
            "No enrollment token. Set EITOP_ENROLL_TOKEN, pipe it with "
            "--token-stdin, or run interactively."
        )
    return token


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="eitop-collector", description="EITOP Linux endpoint collector"
    )
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument(
        "--config", default=None, help="Path to collector.toml"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Debug logging"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    enroll = sub.add_parser("enroll", help="Enroll this host with a token")
    enroll.add_argument(
        "--token-stdin",
        action="store_true",
        help="Read the enrollment token from stdin (recommended for scripts)",
    )

    sub.add_parser("run", help="Run heartbeat + inventory loop")
    sub.add_parser("rotate", help="Rotate the endpoint credential")
    sub.add_parser("collect", help="Print inventory JSON to stdout")
    sub.add_parser("status", help="Show endpoint id (never the credential)")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    try:
        config = load_config(args.config)
    except ConfigError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return 2

    if args.command == "collect":
        print(json.dumps(collect_all(), indent=2, sort_keys=True))
        return 0

    if args.command == "status":
        try:
            stored = load_credentials(config.credential_file)
        except CredentialError as exc:
            print(f"not enrolled: {exc}", file=sys.stderr)
            return 1
        print(f"endpoint_id: {stored.endpoint_id}")
        print(f"credential_file: {config.credential_file} (mode 0600)")
        # Redacted: a server_url may carry basic-auth userinfo (L7).
        print(f"server_url: {redact_url(config.server_url)}")
        return 0

    runner = Runner(config)
    try:
        if args.command == "enroll":
            token = _read_enrollment_token(args)
            endpoint_id, _cred = runner.enroll(token)
            print(f"enrolled endpoint_id={endpoint_id}")
            return 0
        if args.command == "rotate":
            runner.rotate()
            print("credential rotated")
            return 0
        if args.command == "run":
            runner.run_forever()
            return 0
    except CredentialError as exc:
        print(f"credential error: {exc}", file=sys.stderr)
        return 1
    except CollectorError as exc:
        print(f"server error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
