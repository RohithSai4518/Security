"""
Multi-format report generator supporting JSON, Text, Markdown, and HTML.
"""

import json
import os
import datetime
from typing import Dict, Any, Optional

class ReportGenerator:
    """Exports security assessment data into clean, structured reports."""

    def __init__(self, output_dir: str = "reports"):
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)

    def _generate_filename(self, module_name: str, ext: str) -> str:
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{module_name}_report_{timestamp}.{ext}"
        return os.path.join(self.output_dir, filename)

    def save_json(self, module_name: str, data: Dict[str, Any], filepath: Optional[str] = None) -> str:
        target = filepath or self._generate_filename(module_name, "json")
        with open(target, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)
        return target

    def save_text(self, module_name: str, content: str, filepath: Optional[str] = None) -> str:
        target = filepath or self._generate_filename(module_name, "txt")
        with open(target, "w", encoding="utf-8") as f:
            f.write(content)
        return target

    def save_markdown(self, module_name: str, title: str, summary: Dict[str, Any], sections: Dict[str, Any], filepath: Optional[str] = None) -> str:
        target = filepath or self._generate_filename(module_name, "md")
        lines = [
            f"# {title}",
            f"**Generated:** {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"**Module:** `{module_name}`",
            "",
            "## Executive Summary",
            ""
        ]
        for k, v in summary.items():
            lines.append(f"- **{k.replace('_', ' ').title()}:** {v}")
        
        lines.append("")
        lines.append("## Details & Findings")
        lines.append("")

        for section_title, section_data in sections.items():
            lines.append(f"### {section_title}")
            if isinstance(section_data, list):
                if not section_data:
                    lines.append("*No items recorded.*")
                else:
                    for item in section_data:
                        if isinstance(item, dict):
                            lines.append(f"- " + ", ".join(f"`{k}`: {v}" for k, v in item.items()))
                        else:
                            lines.append(f"- {item}")
            elif isinstance(section_data, dict):
                for k, v in section_data.items():
                    lines.append(f"- **{k}:** `{v}`")
            else:
                lines.append(str(section_data))
            lines.append("")

        with open(target, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        return target

    def save_html(self, module_name: str, title: str, summary: Dict[str, Any], data: Dict[str, Any], filepath: Optional[str] = None) -> str:
        target = filepath or self._generate_filename(module_name, "html")
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        summary_cards = "".join(
            f"""<div class="card">
                <div class="card-title">{k.replace('_', ' ').title()}</div>
                <div class="card-value">{v}</div>
            </div>"""
            for k, v in summary.items()
        )

        formatted_json = json.dumps(data, indent=2, default=str)

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title} - PySecSuite Report</title>
    <style>
        :root {{
            --bg-color: #0f172a;
            --surface-color: #1e293b;
            --surface-border: #334155;
            --text-primary: #f8fafc;
            --text-muted: #94a3b8;
            --accent: #38bdf8;
            --accent-glow: rgba(56, 189, 248, 0.15);
            --success: #4ade80;
            --warning: #facc15;
            --danger: #f87171;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-primary);
            margin: 0;
            padding: 2rem;
            line-height: 1.6;
        }}
        .container {{
            max-width: 1000px;
            margin: 0 auto;
        }}
        header {{
            border-bottom: 1px solid var(--surface-border);
            padding-bottom: 1.5rem;
            margin-bottom: 2rem;
        }}
        h1 {{
            margin: 0 0 0.5rem 0;
            color: var(--accent);
            font-size: 2rem;
        }}
        .meta {{
            color: var(--text-muted);
            font-size: 0.9rem;
        }}
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }}
        .card {{
            background: var(--surface-color);
            border: 1px solid var(--surface-border);
            border-radius: 8px;
            padding: 1.25rem;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
        }}
        .card-title {{
            font-size: 0.85rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--text-muted);
            margin-bottom: 0.5rem;
        }}
        .card-value {{
            font-size: 1.5rem;
            font-weight: 700;
            color: var(--accent);
        }}
        .section {{
            background: var(--surface-color);
            border: 1px solid var(--surface-border);
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 2rem;
        }}
        .section h2 {{
            margin-top: 0;
            color: var(--text-primary);
            font-size: 1.3rem;
            border-bottom: 1px solid var(--surface-border);
            padding-bottom: 0.75rem;
        }}
        pre {{
            background: #090d16;
            border: 1px solid var(--surface-border);
            border-radius: 6px;
            padding: 1rem;
            overflow-x: auto;
            color: #38bdf8;
            font-family: Consolas, Monaco, "Courier New", Courier, monospace;
            font-size: 0.9rem;
        }}
        footer {{
            text-align: center;
            color: var(--text-muted);
            font-size: 0.85rem;
            margin-top: 3rem;
            border-top: 1px solid var(--surface-border);
            padding-top: 1.5rem;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>{title}</h1>
            <div class="meta">Generated by <strong>PySecSuite</strong> on {timestamp}</div>
        </header>
        
        <div class="summary-grid">
            {summary_cards}
        </div>

        <div class="section">
            <h2>Detailed Raw Assessment Findings</h2>
            <pre><code>{formatted_json}</code></pre>
        </div>

        <footer>
            PySecSuite Security Assessment Tool &bull; Pure Python &bull; No External Dependencies
        </footer>
    </div>
</body>
</html>"""
        with open(target, "w", encoding="utf-8") as f:
            f.write(html_content)
        return target
