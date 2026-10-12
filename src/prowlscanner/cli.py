from __future__ import annotations

import argparse
import asyncio
import sys

from . import __version__, vrt
from .config import ScanConfig
from .engine import Engine
from .report import render_html, render_json, render_sarif, render_submissions, summary_lines

_BANNER = r"""
  ___  ___  _____        ___  ___ ___ __ _ _ _  ___ ___
 | . \| . \|  _  | _ _ _ | | ||_ -|  _|  _| \ | || -_| _|
 |  _/|   /|_____||_____||   |/ __|___|__||_|\_||___|_|
 |_|  |_|\_\  prowlscanner v{v}  ·  VRT {vrt}
""".strip("\n")

_PERMISSION = (
    "Only scan systems you own or are explicitly authorized to test.\n"
    "prowlscanner sends live, active probes to the target."
)


def _event_printer():
    phase_mark = {"recon": "⟡", "crawl": "→", "scan": "⚑", "report": "✓"}

    def emit(kind: str, message: str) -> None:
        if kind == "phase":
            sys.stderr.write(f"\n\x1b[1;36m[{message.upper()}]\x1b[0m\n")
        elif kind == "finding":
            sys.stderr.write(f"  \x1b[1;31m✗\x1b[0m {message}\n")
        elif kind == "recon":
            sys.stderr.write(f"  \x1b[36m⟡\x1b[0m {message}\n")
        elif kind == "module":
            sys.stderr.write(f"  \x1b[90m⚑ {message}\x1b[0m\n")
        elif kind == "error":
            sys.stderr.write(f"  \x1b[33m! {message}\x1b[0m\n")
        else:
            sys.stderr.write(f"  \x1b[90m{message}\x1b[0m\n")
        sys.stderr.flush()

    return emit


def _split(values: list[str] | None) -> list[str]:
    out: list[str] = []
    for value in values or []:
        out.extend(part.strip() for part in value.split(",") if part.strip())
    return out


def _bands(spec: str | None, include_p5: bool) -> tuple[int, ...]:
    if spec:
        return tuple(int(x) for x in spec.replace(",", " ").split())
    return (1, 2, 3, 4, 5) if include_p5 else (1, 2, 3, 4)


def _build_config(targets: list[str], args: argparse.Namespace) -> tuple[ScanConfig, list[str]]:
    if args.scope_file:
        config = ScanConfig.from_file(args.scope_file)
        seed_urls = [t for t in config.in_scope if "://" in t]
    else:
        config = ScanConfig(in_scope=list(targets))
        seed_urls = [t for t in targets if "://" in t]
    if args.out_of_scope:
        config.out_of_scope += _split(args.out_of_scope)
    if args.not_applicable:
        config.not_applicable += _split(args.not_applicable)
    config.bands = _bands(args.bands, args.include_p5)
    if args.max_urls:
        config.max_urls = args.max_urls
    if args.depth is not None:
        config.max_depth = args.depth
    if args.rate:
        config.rate = args.rate
    if args.insecure:
        config.verify_tls = False
    if args.authorize:
        config.authorized = True
    return config, seed_urls


def _confirm_authorization(config: ScanConfig, interactive: bool) -> bool:
    if config.authorized:
        return True
    if not interactive:
        sys.stderr.write(
            "\nRefusing to scan: authorization not confirmed.\n"
            "Re-run with --authorize to confirm you are permitted to test these targets.\n"
        )
        return False
    sys.stderr.write("\n" + _PERMISSION + "\n")
    answer = input("Type 'yes' to confirm you are authorized to test these targets: ").strip().lower()
    return answer in ("y", "yes")


def _prompt_targets() -> tuple[list[str], list[str], list[str]]:
    sys.stderr.write(_BANNER.format(v=__version__, vrt=vrt.release_date()) + "\n\n")
    raw = input("Target to hunt (domain, *.wildcard, URL, IP, or CIDR): ").strip()
    targets = _split([raw]) if raw else []
    oos = input("Out of scope (comma-separated, optional): ").strip()
    na = input("Not-applicable VRT ids/prefixes (comma-separated, optional): ").strip()
    return targets, _split([oos]), _split([na])


def _run_scan(args: argparse.Namespace) -> int:
    interactive = not args.targets and not args.scope_file
    extra_oos: list[str] = []
    extra_na: list[str] = []
    targets = list(args.targets)
    if interactive:
        targets, extra_oos, extra_na = _prompt_targets()
        if not targets:
            sys.stderr.write("No target provided.\n")
            return 1
    config, seed_urls = _build_config(targets, args)
    config.out_of_scope += extra_oos
    config.not_applicable += extra_na
    if not config.in_scope:
        sys.stderr.write("No in-scope targets.\n")
        return 1
    if not _confirm_authorization(config, interactive):
        return 1

    engine = Engine(config, seed_urls=seed_urls, event=_event_printer())
    report = asyncio.run(engine.run())

    for line in summary_lines(report, color=sys.stderr.isatty()):
        sys.stderr.write(line + "\n")

    if args.json:
        _write(args.json, render_json(report))
    if args.html:
        _write(args.html, render_html(report))
    if args.sarif:
        _write(args.sarif, render_sarif(report))
    if args.submissions:
        _write(args.submissions, render_submissions(report))
    if args.all_reports:
        prefix = args.all_reports
        _write(f"{prefix}.json", render_json(report))
        _write(f"{prefix}.html", render_html(report))
        _write(f"{prefix}.sarif", render_sarif(report))
        _write(f"{prefix}.submissions.txt", render_submissions(report))
    if args.stdout == "json":
        sys.stdout.write(render_json(report) + "\n")

    counts = report.counts
    if counts.get("P1", 0) or counts.get("P2", 0):
        return 2
    return 1 if report.findings else 0


def _write(path: str, content: str) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(content)
    sys.stderr.write(f"  \x1b[32m↳ wrote {path}\x1b[0m\n")


def _run_serve(args: argparse.Namespace) -> int:
    from .web import serve
    return serve(host=args.host, port=args.port, authorize=args.authorize)


def build_scan_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="prowlscanner",
        description="Authorized web vulnerability hunter — live recon, verification-based scanning, P1–P4 findings (VRT).",
        epilog="Run 'prowlscanner serve' to launch the web console.",
    )
    p.add_argument("--version", action="version", version=f"prowlscanner {__version__}")
    p.add_argument("targets", nargs="*", help="domain, *.wildcard, URL, IP, or CIDR (omit to be prompted)")
    p.add_argument("--scope-file", help="JSON scope file")
    p.add_argument("--out-of-scope", action="append", help="exclude host/range (repeatable, comma-ok)")
    p.add_argument("--not-applicable", action="append", help="VRT id/prefix to skip (repeatable, comma-ok)")
    p.add_argument("--bands", help="priority bands, e.g. '1,2,3' (default 1,2,3,4)")
    p.add_argument("--include-p5", action="store_true", help="also report P5 informational")
    p.add_argument("--depth", type=int, help="max crawl depth (default 2)")
    p.add_argument("--max-urls", type=int, help="max pages to crawl")
    p.add_argument("--rate", type=float, help="requests per second")
    p.add_argument("--insecure", action="store_true", help="skip TLS verification")
    p.add_argument("--authorize", action="store_true", help="confirm you are authorized to test the targets")
    p.add_argument("--json", help="write JSON report to path")
    p.add_argument("--html", help="write HTML report to path")
    p.add_argument("--sarif", help="write SARIF report to path")
    p.add_argument("--submissions", help="write submission-ready reports (VRT template) to path")
    p.add_argument("--all-reports", metavar="PREFIX", help="write json+html+sarif+submissions using PREFIX")
    p.add_argument("--stdout", choices=["json"], help="emit report to stdout")
    return p


def build_serve_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="prowlscanner serve", description="Launch the local web console.")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8787)
    p.add_argument("--authorize", action="store_true", help="pre-authorize scans launched from the console")
    return p


def _force_utf8() -> None:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure:
            try:
                reconfigure(encoding="utf-8")
            except (ValueError, OSError):
                pass


def main(argv: list[str] | None = None) -> int:
    _force_utf8()
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "serve":
        return _run_serve(build_serve_parser().parse_args(argv[1:]))
    if argv and argv[0] == "scan":
        argv = argv[1:]
    return _run_scan(build_scan_parser().parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
