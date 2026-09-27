import json
import os
from pathlib import Path
from jinja2 import Environment, FileSystemLoader
from repoguard.core.models import ReportData


def generate_reports(report_data: ReportData, output_dir: str) -> tuple[str, str]:
    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    json_file = out_path / "findings.json"
    html_file = out_path / "report.html"

    with open(json_file, "w", encoding="utf-8") as f:
        f.write(report_data.model_dump_json(indent=2))

    template_dir = Path(__file__).parent / "templates"
    env = Environment(loader=FileSystemLoader(str(template_dir)), autoescape=True)
    template = env.get_template("report_template.html")

    rendered_html = template.render(
        summary=report_data.summary,
        findings=report_data.findings,
        endpoints=report_data.endpoints,
        top_fixes=report_data.top_fixes,
    )

    with open(html_file, "w", encoding="utf-8") as f:
        f.write(rendered_html)

    return str(json_file), str(html_file)
