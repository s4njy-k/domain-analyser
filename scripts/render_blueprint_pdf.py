from __future__ import annotations

import sys
from pathlib import Path

import markdown
from tempfile import TemporaryDirectory


ROOT_DIR = Path(__file__).resolve().parent.parent
DEFAULT_INPUT = ROOT_DIR / "PROJECT_BLUEPRINT.md"
DEFAULT_OUTPUT = ROOT_DIR / "PROJECT_BLUEPRINT.pdf"


def markdown_to_html(markdown_text: str, title: str) -> str:
    body = markdown.markdown(
        markdown_text,
        extensions=["tables", "fenced_code", "sane_lists", "toc"],
        output_format="html5",
    )
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>{title}</title>
  <style>
    @page {{
      size: A4;
      margin: 16mm 14mm 18mm;
      @top-left {{
        content: "{title}";
        color: #4b5563;
        font-size: 9pt;
      }}
      @bottom-left {{
        content: "AI-Powered Malicious Domain Analyser - Maintained Blueprint";
        color: #64748b;
        font-size: 8pt;
      }}
      @bottom-right {{
        content: "Page " counter(page) " of " counter(pages);
        color: #4b5563;
        font-size: 9pt;
      }}
    }}

    body {{
      font-family: "Segoe UI", Arial, sans-serif;
      color: #12263f;
      line-height: 1.6;
      font-size: 10.5pt;
    }}

    h1, h2, h3, h4 {{
      color: #17365f;
      page-break-after: avoid;
    }}

    h1 {{
      font-size: 24pt;
      margin-bottom: 8px;
      border-bottom: 2px solid #2e6da4;
      padding-bottom: 10px;
    }}

    h2 {{
      font-size: 16pt;
      margin-top: 24px;
      padding-bottom: 4px;
      border-bottom: 1px solid #d7dee8;
    }}

    h3 {{
      font-size: 12.5pt;
      margin-top: 18px;
    }}

    p, li {{
      orphans: 3;
      widows: 3;
    }}

    code {{
      font-family: "SFMono-Regular", Consolas, monospace;
      background: #f1f5f9;
      padding: 0.15em 0.35em;
      border-radius: 4px;
      font-size: 0.92em;
    }}

    pre {{
      background: #0f172a;
      color: #e2e8f0;
      padding: 12px 14px;
      border-radius: 10px;
      overflow: hidden;
      white-space: pre-wrap;
      word-break: break-word;
    }}

    pre code {{
      background: transparent;
      padding: 0;
      color: inherit;
    }}

    table {{
      width: 100%;
      border-collapse: collapse;
      margin: 12px 0 18px;
      font-size: 9.5pt;
    }}

    th, td {{
      border: 1px solid #d7dee8;
      padding: 8px 10px;
      vertical-align: top;
    }}

    th {{
      background: #eef4fb;
      text-align: left;
    }}

    blockquote {{
      margin: 16px 0;
      padding: 10px 14px;
      border-left: 4px solid #2e6da4;
      background: #f8fbff;
      color: #2f4258;
    }}

    ul, ol {{
      padding-left: 22px;
    }}
  </style>
</head>
<body>
{body}
</body>
</html>"""


def render_blueprint_pdf(input_path: Path, output_path: Path) -> None:
    markdown_text = input_path.read_text(encoding="utf-8")
    html = markdown_to_html(markdown_text, "AI-Powered Malicious Domain Analyser Blueprint")
    try:
        from weasyprint import HTML

        HTML(string=html, base_url=str(input_path.parent)).write_pdf(str(output_path))
        return
    except Exception:
        from playwright.sync_api import sync_playwright

        with TemporaryDirectory() as tmpdir:
            html_path = Path(tmpdir) / "blueprint.html"
            html_path.write_text(html, encoding="utf-8")
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch()
                page = browser.new_page(viewport={"width": 1440, "height": 1080})
                page.goto(html_path.as_uri(), wait_until="load")
                page.pdf(
                    path=str(output_path),
                    format="A4",
                    print_background=True,
                    margin={"top": "16mm", "right": "14mm", "bottom": "18mm", "left": "14mm"},
                )
                browser.close()


def main() -> int:
    input_path = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else DEFAULT_INPUT
    output_path = Path(sys.argv[2]).resolve() if len(sys.argv) > 2 else DEFAULT_OUTPUT
    render_blueprint_pdf(input_path, output_path)
    print(output_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
