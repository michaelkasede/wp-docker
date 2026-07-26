import json
import sys
from pathlib import Path


def build_empty_sarif():
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "WPScan", "version": "3.8.25", "rules": []}},
            "results": []
        }]
    }


def convert_wpscan_to_sarif(wpscan_json_path, sarif_output_path):
    output_path = Path(sarif_output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    if not Path(wpscan_json_path).exists():
        output_path.write_text(json.dumps(build_empty_sarif(), indent=2), encoding="utf-8")
        return

    try:
        with open(wpscan_json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except json.JSONDecodeError as exc:
        print(
            f"Warning: could not parse {wpscan_json_path}: {exc}. Writing an empty SARIF file.",
            file=sys.stderr,
        )
        output_path.write_text(json.dumps(build_empty_sarif(), indent=2), encoding="utf-8")
        return

    sarif_run = {
        "tool": {"driver": {"name": "WPScan", "version": "3.8.25", "rules": []}},
        "results": []
    }

    plugins = data.get("plugins", {})
    for plugin_name, plugin_info in plugins.items():
        vulnerabilities = plugin_info.get("vulnerabilities", [])
        for vuln in vulnerabilities:
            rule_id = f"WP-PLUGIN-{plugin_name.upper()}"
            title = vuln.get("title", "Core WordPress Vulnerability Component")

            sarif_run["tool"]["driver"]["rules"].append({
                "id": rule_id, "shortDescription": {"text": title}
            })

            sarif_run["results"].append({
                "ruleId": rule_id,
                "message": {"text": f"Plugin: {plugin_name}. Fix version: {vuln.get('fixed_in', 'Unavailable')}"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": "docker-compose.yml"},
                        "region": {"startLine": 1}
                    }
                }]
            })

    sarif_schema = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [sarif_run]
    }

    output_path.write_text(json.dumps(sarif_schema, indent=2), encoding="utf-8")


if __name__ == "__main__":
    convert_wpscan_to_sarif('wpscan-results.json', 'wpscan-results.sarif')