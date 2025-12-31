import os
import httpx
import argparse
import sys
import threading
from rich.console import Console
from rich.layout import Layout
from rich.panel import Panel
from rich.live import Live
from rich.table import Table
from rich.text import Text
from rich.align import Align
from rich.prompt import Prompt
from datetime import datetime
from time import sleep
import readchar

# Path to .env
ENV_PATH = os.path.join(".gemini", ".env")

# Load PIHOLE_PW from .gemini/.env
def load_env():
    if os.path.exists(ENV_PATH):
        with open(ENV_PATH, "r") as f:
            for line in f:
                if line.startswith("export PIHOLE_PW="):
                    return line.split("=")[1].strip().strip('"')
    return None

def save_env(password):
    lines = []
    found = False
    if os.path.exists(ENV_PATH):
        with open(ENV_PATH, "r") as f:
            for line in f:
                if line.startswith("export PIHOLE_PW="):
                    lines.append(f'export PIHOLE_PW="{password}"\n')
                    found = True
                else:
                    lines.append(line)
    
    if not found:
        lines.append(f'export PIHOLE_PW="{password}"\n')
    
    os.makedirs(os.path.dirname(ENV_PATH), exist_ok=True)
    with open(ENV_PATH, "w") as f:
        f.writelines(lines)

PIHOLE_URL = "http://pi.hole/api"

class PiHoleClient:
    def __init__(self, url, password):
        self.url = url
        self.password = password
        self.sid = None

    def authenticate(self):
        try:
            r = httpx.post(f"{self.url}/auth", json={"password": self.password}, timeout=5)
            if r.status_code == 200:
                data = r.json()
                if data.get("session", {}).get("valid"):
                    self.sid = data["session"]["sid"]
                    return True
        except Exception:
            pass
        return False

    def get_summary(self):
        return self._get_endpoint("stats/summary")

    def get_upstreams(self):
        return self._get_endpoint("stats/upstreams")
    
    def get_padd(self):
        return self._get_endpoint("padd")
    
    def get_history(self):
        return self._get_endpoint("history/summary")
    
    def get_queries(self, limit=20):
        return self._get_endpoint(f"queries?limit={limit}")

    def set_blocking(self, enabled: bool):
        if not self.sid:
            if not self.authenticate():
                return None
        try:
            headers = {"X-FTL-SID": self.sid}
            r = httpx.post(f"{self.url}/dns/blocking", headers=headers, json={"blocking": enabled}, timeout=5)
            return r.json()
        except Exception:
            return None

    def _get_endpoint(self, endpoint):
        if not self.sid:
            if not self.authenticate():
                return None
        
        try:
            headers = {"X-FTL-SID": self.sid}
            r = httpx.get(f"{self.url}/{endpoint}", headers=headers, timeout=5)
            if r.status_code == 200:
                return r.json()
            elif r.status_code == 401:
                if self.authenticate():
                    headers = {"X-FTL-SID": self.sid}
                    r = httpx.get(f"{self.url}/{endpoint}", headers=headers, timeout=5)
                    return r.json()
        except Exception:
            pass
        return None

def make_layout() -> Layout:
    layout = Layout()
    layout.split(
        Layout(name="header", size=4),
        Layout(name="top", size=7),
        Layout(name="chart", ratio=1),
        Layout(name="logs", ratio=1),
        Layout(name="bottom", size=10),
        Layout(name="help", size=1),
    )
    layout["top"].split_row(
        Layout(name="total_queries"),
        Layout(name="queries_blocked"),
        Layout(name="percent_blocked"),
        Layout(name="domains_blocked"),
    )
    layout["bottom"].split_row(
        Layout(name="query_types"),
        Layout(name="upstream_servers"),
    )
    return layout

def render_chart(history_data, width, height):
    if not history_data or "history" not in history_data:
        return Text("No history data", style="dim")
    
    history = history_data["history"]
    if not history:
        return Text("Empty history", style="dim")

    # Determine max value for visible history
    max_val = max((p["total"] for p in history), default=1)
    if max_val == 0: max_val = 1
    
    label_width = len(f"{max_val:,}") + 3
    chart_width = width - label_width
    
    points = history[-chart_width:] if len(history) > chart_width else history
    max_val = max((p["total"] for p in points), default=1)
    if max_val == 0: max_val = 1
    
    blocks = [" ", " ", "▂", "▃", "▄", "▅", "▆", "▇", "█"]
    
    chart_lines = []
    for h in range(height, 0, -1):
        val = int((h / height) * max_val)
        label = f"{val:>{label_width-3}} │ "
        line = Text(label, style="dim")
        
        threshold = (h / height) * max_val
        prev_threshold = ((h-1) / height) * max_val
        
        for p in points:
            total = p["total"]
            blocked = p["blocked"]
            if total >= threshold:
                style = "bright_red" if blocked > 0 else "bright_blue"
                line.append("█", style=style)
            elif total > prev_threshold:
                fraction = (total - prev_threshold) / (threshold - prev_threshold)
                idx = int(fraction * (len(blocks) - 1))
                line.append(blocks[idx], style="bright_blue")
            else:
                line.append(" ")
        chart_lines.append(line)
    
    bottom_line = Text(" " * (label_width-3) + " └" + "─" * chart_width, style="dim")
    chart_lines.append(bottom_line)
    
    return Text("\n").join(chart_lines)

def render_logs(queries_data):
    if not queries_data or "queries" not in queries_data:
        return Text("No query logs", style="dim")
    
    table = Table(expand=True, box=None, show_header=True, header_style="bold cyan")
    table.add_column("Time", width=10)
    table.add_column("Type", width=6)
    table.add_column("Domain", ratio=1)
    table.add_column("Client", ratio=1)
    table.add_column("Status", width=12)

    for q in queries_data["queries"]:
        dt = datetime.fromtimestamp(q["time"]).strftime("%H:%M:%S")
        status = q["status"]
        style = "green" if status in ["CACHE", "FORWARDED"] else "red"
        
        table.add_row(
            dt,
            q["type"],
            q["domain"],
            q["client"]["name"] or q["client"]["ip"],
            Text(status, style=style)
        )
    
    return table

def generate_dashboard(summary, upstreams, padd, history, queries, console_width, message=""):
    layout = make_layout()
    
    now = datetime.now().strftime("%H:%M:%S")
    
    if not summary or not padd:
        layout["chart"].update(Align.center(Panel("Error fetching data or unauthorized", style="red"), vertical="middle"))
        layout["header"].update(Panel(Text(f"Pi-hole Dashboard | Last Update: {now}", justify="center", style="bold white"), style="blue"))
        return layout

    q = summary.get("queries", {})
    total = q.get("total", 0)
    blocked = q.get("blocked", 0)
    percent = q.get("percent_blocked", 0)
    gravity = summary.get("gravity", {}).get("domains_being_blocked", 0)
    clients = summary.get("clients", {}).get("active", 0)
    q_per_min = q.get("frequency", 0) * 60

    blocking_status = padd.get("blocking", "unknown").capitalize()
    status_style = "green" if blocking_status == "Enabled" else "red"
    load = padd.get("system", {}).get("cpu", {}).get("load", {}).get("raw", [0,0,0])
    mem = padd.get("system", {}).get("memory", {}).get("ram", {}).get("%used", 0)

    header_table = Table.grid(expand=True)
    header_table.add_column(justify="left", ratio=1)
    header_table.add_column(justify="center", ratio=1)
    header_table.add_column(justify="right", ratio=1)
    
    status_text = Text.assemble(
        ("Status: ", "white"), (blocking_status, f"bold {status_style}"),
        ("\n", ""),
        (f"{q_per_min:.0f} q/min", "cyan")
    )
    
    sys_info = Text.assemble(
        (f"Load: {load[0]:.2f} / {load[1]:.2f} / {load[2]:.2f}", "white"),
        ("\n", ""),
        (f"Memory usage: {mem:.1f}%", "white")
    )

    header_table.add_row(
        status_text,
        Text("Pi-hole Dashboard", style="bold white", justify="center"),
        sys_info
    )

    layout["header"].update(Panel(header_table, style="blue", subtitle=message if message else None))
    
    layout["total_queries"].update(
        Panel(
            Align.center(Text(f"{total:,}", style="bold white"), vertical="middle"), 
            title="Total Queries", 
            subtitle=f"{clients} active clients",
            style="cyan"
        )
    )
    layout["queries_blocked"].update(
        Panel(Align.center(Text(f"{blocked:,}", style="bold white"), vertical="middle"), title="Queries Blocked", style="red")
    )
    layout["percent_blocked"].update(
        Panel(Align.center(Text(f"{percent:.1f}%", style="bold white"), vertical="middle"), title="Percent Blocked", style="yellow")
    )
    layout["domains_blocked"].update(
        Panel(Align.center(Text(f"{gravity:,}", style="bold white"), vertical="middle"), title="Domains on Adlists", style="green")
    )

    # Query Types Table
    type_table = Table(title="Query Types", expand=True, box=None)
    type_table.add_column("Type", style="cyan")
    type_table.add_column("Count", justify="right", style="magenta")
    
    types = q.get("types", {})
    sorted_types = sorted(types.items(), key=lambda x: x[1], reverse=True)
    for t, count in sorted_types[:6]:
        if count > 0:
            type_table.add_row(t, f"{count:,}")
    layout["query_types"].update(Panel(type_table))

    # Upstream Servers Table
    up_table = Table(title="Upstream Servers", expand=True, box=None)
    up_table.add_column("Server", style="cyan")
    up_table.add_column("Queries", justify="right", style="magenta")
    
    if upstreams and "upstreams" in upstreams:
        sorted_ups = sorted(upstreams["upstreams"], key=lambda x: x["count"], reverse=True)
        for up in sorted_ups[:6]:
            name = up.get("name") or up.get("ip")
            up_table.add_row(name, f"{up['count']:,}")
    layout["upstream_servers"].update(Panel(up_table))

    chart_width = console_width - 4
    chart_height = 8
    layout["chart"].update(Panel(render_chart(history, chart_width, chart_height), title="Total queries over last 24h"))

    layout["logs"].update(Panel(render_logs(queries), title="Recent Queries"))

    layout["help"].update(Text("q: Quit | t: Toggle Blocking | e: Enable | d: Disable | r: Refresh", justify="center", style="dim"))

    return layout

# Shared state for hotkeys
running = True
force_refresh = False
current_message = ""

def key_listener(client):
    global running, force_refresh, current_message
    while running:
        try:
            key = readchar.readkey()
            if key == 'q':
                running = False
            elif key == 't':
                padd = client.get_padd()
                if padd:
                    is_enabled = padd.get("blocking") == "enabled"
                    client.set_blocking(not is_enabled)
                    current_message = f"Blocking {('disabled' if is_enabled else 'enabled')}"
                    force_refresh = True
            elif key == 'e':
                client.set_blocking(True)
                current_message = "Blocking enabled"
                force_refresh = True
            elif key == 'd':
                client.set_blocking(False)
                current_message = "Blocking disabled"
                force_refresh = True
            elif key == 'r':
                force_refresh = True
                current_message = "Refreshing..."
        except Exception:
            pass

def main():
    global running, force_refresh, current_message
    parser = argparse.ArgumentParser(description="Pi-hole TUI")
    parser.add_argument("--iterations", type=int, default=0, help="Number of iterations to run (0 for infinite)")
    parser.add_argument("--refresh", type=float, default=1.0, help="Refresh interval in seconds (default: 1.0)")
    args = parser.parse_args()

    console = Console()
    
    password = load_env()
    client = PiHoleClient(PIHOLE_URL, password)
    
    if not password or not client.authenticate():
        console.print("[yellow]Pi-hole password missing or invalid.[/yellow]")
        password = Prompt.ask("Enter Pi-hole password", password=True)
        client.password = password
        if not client.authenticate():
            console.print("[red]Authentication failed. Exiting.[/red]")
            sys.exit(1)
        save_env(password)
        console.print("[green]Authentication successful! Password saved.[/green]")
        sleep(1)

    console.print("Fetching initial data...")
    summary = client.get_summary()
    upstreams = client.get_upstreams()
    padd = client.get_padd()
    history = client.get_history()
    queries = client.get_queries(limit=15)
    
    if not summary or not padd:
        console.print("[red]Failed to fetch initial data from Pi-hole API. Check connection.[/red]")
        sys.exit(1)

    if args.iterations == 0:
        threading.Thread(target=key_listener, args=(client,), daemon=True).start()

    count = 0
    with Live(generate_dashboard(summary, upstreams, padd, history, queries, console.width), console=console, screen=True, refresh_per_second=4) as live:
        while running:
            if count > 0 or force_refresh:
                summary = client.get_summary()
                upstreams = client.get_upstreams()
                padd = client.get_padd()
                history = client.get_history()
                queries = client.get_queries(limit=15)
                live.update(generate_dashboard(summary, upstreams, padd, history, queries, console.width, current_message))
            
            count += 1
            if args.iterations > 0 and count >= args.iterations:
                break
            
            sleep_time = args.refresh
            for _ in range(int(sleep_time * 10)): 
                if force_refresh or not running:
                    break
                sleep(0.1)
            
            force_refresh = False
            current_message = ""

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass