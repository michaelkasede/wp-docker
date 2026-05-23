import json

def convert_wpscan_to_sarif(wpscan_json_path, sarif_output_path):
    with open(wpscan_json_path, 'r') as f:
        data = json.load(f)
    
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
    
    with open(sarif_output_path, 'w') as f:
        json.dump(sarif_schema, f, indent=2)

if __name__ == "__main__":
    convert_wpscan_to_sarif('wpscan-results.json', 'wpscan-results.sarif')