from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from pathlib import Path

import click
from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn

from pipeline.analyse import analyse_domain
from pipeline.capture import capture_domain
from pipeline.dashboard import generate_dashboard
from pipeline.ingest import load_and_normalise
from pipeline.passive_intel import gather_passive_intel
from pipeline.report import generate_domain_report
from pipeline.utils import SCREENSHOTS_DIR, chunked, ensure_runtime_dirs

console = Console()


@click.command()
@click.option("--input-file", default="input/domains.txt")
@click.option("--batch-name", default="batch-001")
@click.option("--max-domains", default=None, type=int)
def main(input_file, batch_name, max_domains):
    asyncio.run(run_pipeline(input_file, batch_name, max_domains))


async def run_pipeline(input_file, batch_name, max_domains):
    ensure_runtime_dirs()
    batch_id = f"{batch_name}-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')}Z"
    console.print(f"[bold blue]Starting batch {batch_id}[/bold blue]")

    # Phase 1: Ingest
    domains = load_and_normalise(input_file, max_domains=max_domains)
    console.print(f"[green]Phase 1 complete: {len(domains)} domains loaded[/green]")
    if not domains:
        generate_dashboard(batch_id=batch_id)
        console.print("[yellow]No valid domains were provided. Empty dashboard generated.[/yellow]")
        return []

    results = []
    batches = list(chunked(domains, 10))
    with Progress(SpinnerColumn(), TextColumn("{task.description}"), BarColumn(), console=console) as progress:
        task = progress.add_task("Analysing domains...", total=len(domains))

        for batch_index, batch in enumerate(batches, start=1):
            console.print(f"[bold]Processing batch {batch_index}/{len(batches)} ({len(batch)} domains)[/bold]")
            for domain_entry in batch:
                domain = domain_entry["domain"]
                url = domain_entry["url"]
                try:
                    # Phase 2: Passive Intel (async, parallel API calls)
                    intel = await gather_passive_intel(domain, url)

                    # Phase 3: Active Capture
                    captures = await capture_domain(domain, url, Path(SCREENSHOTS_DIR))

                    # Phase 4: AI Analysis
                    merged = {**domain_entry, **intel, **captures, "domain": domain, "input_url": url}
                    ai_result = await analyse_domain(merged)

                    # Phase 5: Generate report + evidence ZIP
                    artefacts = generate_domain_report(domain, merged, ai_result, batch_id)
                    results.append(
                        {
                            "domain": domain,
                            "status": "SUCCESS",
                            "report_path": str(artefacts["report_path"]),
                            "json_path": str(artefacts["json_path"]),
                            "zip_path": str(artefacts["zip_path"]),
                            **ai_result,
                        }
                    )
                    console.print(
                        f"  [green]OK[/green] {domain} - "
                        f"{ai_result.get('threat_category', '?')} [{ai_result.get('severity', '?')}]"
                    )
                except Exception as exc:
                    console.print(f"  [red]FAIL[/red] {domain}: {exc}")
                    results.append({"domain": domain, "status": "ERROR", "error": str(exc)})

                progress.advance(task)
                await asyncio.sleep(0.5)  # Respect API rate limits

    # Phase 6: Dashboard
    summary = generate_dashboard(results, batch_id)
    console.print(
        f"[bold green]Batch {batch_id} complete. Dashboard: docs/index.html "
        f"({summary['total_domains']} domains)[/bold green]"
    )
    return results


if __name__ == "__main__":
    main()
