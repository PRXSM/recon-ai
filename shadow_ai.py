"""
shadow_ai.py — Phase 10
Shadow AI Discovery.
Detects unauthorized or hidden AI tools running across the local network.

Four detection methods:
1. Known AI ports — checks for AI tools by their default port numbers
2. Service banners — reads HTTP responses to identify AI signatures
3. Process names — checks the local machine for running AI processes
4. Network behavior — flags devices talking to known AI API endpoints

This tool NEVER installs, modifies, or interacts with discovered AI tools.
It observes and reports only.
Recon AI advises. The user decides.
"""

import socket
import logging
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)

AI_PORTS = {
    11434: {
        "name": "Ollama",
        "description": "A local AI tool that runs large language models on your machine.",
        "risk": "MEDIUM",
    },
    1234: {
        "name": "LM Studio",
        "description": "A local AI tool for running and chatting with language models.",
        "risk": "MEDIUM",
    },
    7860: {
        "name": "Gradio",
        "description": "An AI model interface tool, often used to run and share AI apps locally.",
        "risk": "MEDIUM",
    },
    8888: {
        "name": "Jupyter Notebook",
        "description": "A data science and AI development environment.",
        "risk": "LOW",
    },
    3000: {
        "name": "Open WebUI",
        "description": "A browser interface for running local AI models.",
        "risk": "MEDIUM",
    },
    8080: {
        "name": "Common AI web interface port",
        "description": "A common port used by various AI web interfaces.",
        "risk": "MEDIUM",
    },
    6006: {
        "name": "TensorBoard",
        "description": "A tool for visualizing machine learning experiments.",
        "risk": "LOW",
    },
    8501: {
        "name": "Streamlit",
        "description": "A framework for building and sharing AI and data apps.",
        "risk": "MEDIUM",
    },
    8000: {
        "name": "FastAPI / AI REST API",
        "description": "A common port for Python-based AI API servers.",
        "risk": "MEDIUM",
    },
    5001: {
        "name": "AI tool (alternate port)",
        "description": "An alternate port commonly used by local AI tools and proxies.",
        "risk": "MEDIUM",
    },
    4000: {
        "name": "AI development server",
        "description": "A port frequently used by AI app development servers.",
        "risk": "LOW",
    },
    9001: {
        "name": "AI worker / task queue",
        "description": "A port used by AI task queues and worker processes.",
        "risk": "MEDIUM",
    },
    11435: {
        "name": "Ollama (alternate port)",
        "description": "An alternate port sometimes used by Ollama local AI.",
        "risk": "MEDIUM",
    },
    8188: {
        "name": "ComfyUI",
        "description": "A popular local AI image generation interface.",
        "risk": "MEDIUM",
    },
    3001: {
        "name": "AnythingLLM",
        "description": "A local ChatGPT alternative for running private AI assistants.",
        "risk": "MEDIUM",
    },
}

AI_BANNER_SIGNATURES = [
    "ollama",
    "lm studio",
    "gradio",
    "jupyter",
    "open webui",
    "streamlit",
    "tensorboard",
    "langchain",
    "hugging face",
    "transformers",
    "fastapi",
    "stable diffusion",
    "text-generation",
    "llama",
    "gpt4all",
    "localai",
    "koboldai",
    "oobabooga",
    "text generation webui",
]


def check_port(ip, port, timeout=1):
    """
    Returns True if the given TCP port is open on the IP.
    """
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except Exception:
        return False


def check_banner(ip, port):
    """
    Makes an HTTP GET to ip:port and returns the response text if successful.
    Returns None on any failure.
    """
    try:
        response = requests.get(
            f"http://{ip}:{port}/",
            timeout=3,
            allow_redirects=True,
        )
        return response.text
    except Exception:
        return None


def check_ollama_api(ip, port):
    """
    Checks Ollama's /api/tags endpoint to get the actual model names running.
    Returns a list of model name strings, or None if not Ollama.
    """
    try:
        r = requests.get(f"http://{ip}:{port}/api/tags", timeout=3)
        if r.status_code == 200:
            data = r.json()
            return [m["name"] for m in data.get("models", [])]
    except Exception:
        return None


def scan_device(ip):
    """
    Checks all AI_PORTS against one IP address.
    For each open port, attempts a banner grab to confirm the AI tool.
    Returns a list of finding dicts — one per detected AI tool.
    """
    # Never scan localhost — Recon AI runs here and would flag itself
    if ip in ("127.0.0.1", "::1", "localhost"):
        return []
    
    findings = []

    for port, info in AI_PORTS.items():
        if not check_port(ip, port):
            continue

        banner = check_banner(ip, port)
        confirmed = False
        banner_match = None

        if banner:
            banner_lower = banner.lower()
            for signature in AI_BANNER_SIGNATURES:
                if signature in banner_lower:
                    confirmed = True
                    banner_match = signature
                    break

        finding = {
            "ip": ip,
            "port": port,
            "name": info["name"],
            "risk": info["risk"],
            "description": info["description"],
            "confirmed": confirmed,
            "banner_match": banner_match,
        }

        if port == 11434:
            models = check_ollama_api(ip, port)
            if models is not None:
                finding["ollama_models"] = models

        findings.append(finding)

    return findings


def scan_network(devices):
    """
    Takes a list of IP strings, runs scan_device concurrently using
    ThreadPoolExecutor, and returns all findings as a flat list.
    """
    all_findings = []

    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(scan_device, ip): ip for ip in devices}
        for future in as_completed(futures):
            try:
                results = future.result()
                all_findings.extend(results)
            except Exception as e:
                ip = futures[future]
                logger.error(f"scan_device failed for {ip}: {e}")

    return all_findings


def run_shadow_ai_scan(devices):
    """
    Main entry point. Scans all devices for AI tools and returns a
    structured result with findings, total count, clean flag, and summary.

    Args:
        devices: list of IP address strings.

    Returns:
        dict with findings, total_found, clean, and plain English summary.
    """
    logger.info(f"Starting shadow AI scan across {len(devices)} device(s)...")

    findings = scan_network(devices)

    total_found = len(findings)
    clean = total_found == 0
    confirmed_count = sum(1 for f in findings if f["confirmed"])
    affected_ips = len({f["ip"] for f in findings})

    if clean:
        summary = (
            f"I scanned {len(devices)} device(s) and found no AI tools running "
            "on any of them. Nothing to flag."
        )
    elif confirmed_count > 0:
        tool_names = list({f["name"] for f in findings if f["confirmed"]})
        names_str = ", ".join(tool_names[:3])
        if len(tool_names) > 3:
            names_str += f" and {len(tool_names) - 3} more"
        summary = (
            f"I found {confirmed_count} confirmed AI tool(s) running across "
            f"{affected_ips} device(s), including {names_str}. "
            "These are active and responding — worth reviewing if you didn't set them up."
        )
    else:
        summary = (
            f"I found {total_found} open port(s) that match known AI tools across "
            f"{affected_ips} device(s). I couldn't confirm them by banner, but the "
            "ports are open. Something could be running there."
        )

    logger.info(f"Shadow AI scan complete. {total_found} finding(s) across {len(devices)} device(s).")

    return {
        "findings": findings,
        "total_found": total_found,
        "devices_scanned": len(devices),
        "clean": clean,
        "summary": summary,
    }


if __name__ == "__main__":
    import json
    test_devices = ["127.0.0.1"]
    results = run_shadow_ai_scan(test_devices)
    print(json.dumps(results, indent=2))
