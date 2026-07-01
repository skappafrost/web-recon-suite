"""Web Recon Suite — CLI entry point.

Click-based command-line interface for web application security
assessment operations.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import click

from web_recon import __version__


def run_async(coro):
    """Run an async coroutine from a sync Click command."""
    return asyncio.run(coro)


@click.group()
@click.version_option(version=__version__, prog_name="web-recon")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose output.")
@click.pass_context
def main(ctx: click.Context, verbose: bool) -> None:
    """Web Recon Suite — Systematic web application security assessment.

    ⚠️  LEGAL NOTICE: This tool is for authorized security auditing only.
    Unauthorized use against systems you do not own is illegal.
    """
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose


@main.command()
@click.argument("target")
@click.option("--timeout", "-t", default=30, type=int, help="Request timeout in seconds.")
@click.option("--output", "-o", default=None, help="Output file for JSON report.")
@click.option("--markdown", "-m", is_flag=True, help="Also generate Markdown report.")
def scan(target: str, timeout: int, output: str | None, markdown: bool) -> None:
    """Scan a web application for endpoints and vulnerabilities."""
    from web_recon.core.scanner import WebScanner
    from web_recon.modules.report import ReportGenerator

    click.echo(f"🔍 Scanning {target}...")
    scanner = WebScanner(target=target, timeout=timeout)
    result = asyncio.run(scanner.scan())

    click.echo(f"  Endpoints: {len(result.endpoints)}")
    click.echo(f"  Auth endpoints: {len(result.auth_endpoints)}")
    click.echo(f"  Technologies: {', '.join(result.technologies)}")
    click.echo(f"  Missing headers: {len([h for h, v in result.security_headers.items() if v == 'MISSING'])}")
    click.echo(f"  Vulnerabilities: {len(result.vulnerabilities)}")

    gen = ReportGenerator()
    if output:
        gen.generate_json(result, output)
        click.echo(f"  Report saved to {output}")
    if markdown:
        md_path = Path(output).with_suffix(".md") if output else "report.md"
        gen.generate_markdown(result, str(md_path))
        click.echo(f"  Markdown saved to {md_path}")


@main.command("cors")
@click.argument("target")
@click.option("--endpoint", "-e", default="/", help="Endpoint to test.")
def cors_cmd(target: str, endpoint: str) -> None:
    """Test CORS configuration for misconfigurations."""
    from web_recon.modules.cors import CORSAnalyzer

    click.echo(f"🌐 Testing CORS on {target}{endpoint}...")
    analyzer = CORSAnalyzer(target=target, endpoint=endpoint)
    results = asyncio.run(analyzer.analyze())

    for r in results:
        status = "❌ VULNERABLE" if r.allowed else "✓"
        click.echo(f"  {status} {r.origin_tested}: {r.severity}")


@main.command()
@click.argument("target")
@click.option("--username", "-u", required=True, help="Username to test.")
@click.option("--passwords", "-p", required=True, help="Comma-separated passwords.")
@click.option("--delay", "-d", default=0.5, type=float, help="Delay between requests.")
def brute(target: str, username: str, passwords: str, delay: float) -> None:
    """Brute-force test an authentication endpoint."""
    from web_recon.modules.credentials import CredentialTester

    pw_list = [p.strip() for p in passwords.split(",")]
    click.echo(f"🔑 Testing {username} against {target}...")
    tester = CredentialTester(target=target, delay=delay)
    results = asyncio.run(tester.brute_force(username, pw_list))

    for r in results:
        if r.success:
            click.echo(f"  ✅ {r.username}:{r.password} (HTTP {r.status_code})")


@main.command("spray")
@click.argument("target")
@click.option("--password", "-p", required=True, help="Password to spray.")
@click.option("--usernames", "-u", required=True, help="Comma-separated usernames.")
@click.option("--delay", "-d", default=0.5, type=float, help="Delay between requests.")
def spray_cmd(target: str, password: str, usernames: str, delay: float) -> None:
    """Password spray test across multiple usernames."""
    from web_recon.modules.credentials import CredentialTester

    user_list = [u.strip() for u in usernames.split(",")]
    click.echo(f"🎯 Spraying password against {len(user_list)} usernames...")
    tester = CredentialTester(target=target, delay=delay)
    results = asyncio.run(tester.password_spray(user_list, password))

    for r in results:
        if r.success:
            click.echo(f"  ✅ {r.username}:{r.password}")


if __name__ == "__main__":
    main()
