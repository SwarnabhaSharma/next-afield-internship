"""Click CLI for crypto scanner."""

import click
import os
from .scanner import scan_file, scan_directory, scan_code, create_sample_vulnerable_code
from .report import format_report
from .patterns import CWE_MAPPINGS


@click.group()
def main() -> None:
    """Cryptographic Code Scanner - Find crypto mistakes in Python code."""
    pass


@main.command()
@click.argument("file_path", type=click.Path(exists=True))
@click.option("-o", "--output", help="Output file path")
@click.option("-f", "--format", "output_format", type=click.Choice(["text", "json"]), default="text")
def scan_file_cmd(file_path: str, output: str, output_format: str) -> None:
    """Scan a single Python file."""
    result = scan_file(file_path)
    report = format_report([result], output_format, output)

    if not output:
        print(report)
    else:
        click.echo(f"Report written to: {output}")


@main.command()
@click.argument("directory", type=click.Path(exists=True))
@click.option("-o", "--output", help="Output file path")
@click.option("-f", "--format", "output_format", type=click.Choice(["text", "json"]), default="text")
@click.option("--ignore", multiple=True, help="Patterns to ignore")
def scan_dir_cmd(directory: str, output: str, output_format: str, ignore: tuple) -> None:
    """Recursively scan directory for Python files."""
    import glob

    results = []
    for root, dirs, files in os.walk(directory):
        if ignore:
            dirs[:] = [d for d in dirs if not any(ign in d for ign in ignore)]

        for file in files:
            if file.endswith(".py"):
                file_path = os.path.join(root, file)
                result = scan_file(file_path)
                results.append(result)

    report = format_report(results, output_format, output)

    if not output:
        print(report)
    else:
        click.echo(f"Report written to: {output}")


@main.command()
def demo() -> None:
    """Run scanner on sample vulnerable code."""
    from .scanner import demonstrate_scanner
    demonstrate_scanner()


@main.command()
def cwe_list() -> None:
    """List all detectable CWEs."""
    click.echo("Detectable CWE Vulnerabilities:")
    click.echo("=" * 60)

    for cwe_id, info in CWE_MAPPINGS.items():
        click.echo(f"\n{cwe_id}: {info['name']}")
        click.echo(f"  Description: {info['description']}")
        click.echo(f"  Remediation: {info['remediation'][:60]}...")


@main.command()
def sample() -> None:
    """Show sample vulnerable code."""
    sample = create_sample_vulnerable_code()
    print("Sample Vulnerable Code:")
    print("=" * 60)
    print(sample)


if __name__ == "__main__":
    main()