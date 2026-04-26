import json
import os
from datetime import datetime


class Reporter:
    def __init__(self, input_text, final_text, chain, found_flag, flag_format=None):
        self.input_text = input_text
        self.final_text = final_text
        self.chain = chain
        self.found_flag = found_flag
        self.flag_format = flag_format
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def to_json(self, output_path="reports/result.json"):
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        report = {
            "timestamp": self.timestamp,
            "input": self.input_text,
            "output": self.final_text,
            "chain": self.chain,
            "layers": len(self.chain),
            "flag_found": self.found_flag,
            "flag_format": self.flag_format,
        }
        with open(output_path, "w") as f:
            json.dump(report, f, indent=4)
        print(f"\n[+] JSON report saved to {output_path}")

    def to_html(self, output_path="reports/result.html"):
        os.makedirs(os.path.dirname(output_path), exist_ok=True)

        chain_html = " → ".join(self.chain) if self.chain else "No layers decoded"
        flag_color = "#00ff00" if self.found_flag else "#ffaa00"
        flag_label = "✅ FLAG FOUND" if self.found_flag else "⚠ Possible Plaintext"

        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>CipherX Report</title>
    <style>
        body {{ font-family: monospace; background: #0d0d0d; color: #00ff00; padding: 2rem; }}
        h1 {{ color: #ff4444; }}
        .box {{ background: #1a1a1a; padding: 1rem; border-radius: 6px; margin: 1rem 0; word-break: break-all; }}
        .label {{ color: #888; font-size: 0.85rem; margin-bottom: 4px; }}
        .chain {{ color: #ffaa00; }}
        .flag {{ color: {flag_color}; font-size: 1.3rem; font-weight: bold; }}
        .meta {{ color: #555; font-size: 0.8rem; }}
    </style>
</head>
<body>
    <h1>🔓 CipherX Decode Report</h1>
    <p class="meta">Generated: {self.timestamp}</p>

    <div class="box">
        <div class="label">INPUT</div>
        <div>{self.input_text}</div>
    </div>

    <div class="box">
        <div class="label">DECODE CHAIN ({len(self.chain)} layers)</div>
        <div class="chain">{chain_html}</div>
    </div>

    <div class="box">
        <div class="label">OUTPUT</div>
        <div class="flag">{flag_label}</div>
        <div style="margin-top:8px">{self.final_text}</div>
    </div>
</body>
</html>"""

        with open(output_path, "w") as f:
            f.write(html)
        print(f"[+] HTML report saved to {output_path}")

    def print_summary(self):
        print(f"\n{'='*55}")
        print(f"  CipherX Decode Summary")
        print(f"{'='*55}")
        print(f"  Input    : {self.input_text[:60]}...")
        print(f"  Layers   : {len(self.chain)}")
        print(f"  Chain    : {' → '.join(self.chain) if self.chain else 'None'}")
        print(f"  Output   : {self.final_text}")
        print(f"  Flag     : {'✅ FOUND' if self.found_flag else '❌ Not confirmed'}")
        print(f"{'='*55}\n")
