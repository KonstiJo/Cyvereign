"""
cli.py
======
Command-Line Interface for Cyvereign.

Usage examples:

  # Ask the AI a question
  python cli.py ask "What is SSRF and how do I prevent it?"

  # Scan a project folder for vulnerabilities
  python cli.py scan ./my_project

  # Scan a single file
  python cli.py scan ./app.py

  # Look up a CVE
  python cli.py cve CVE-2021-44228

  # Analyse a log file
  python cli.py logs /var/log/nginx/access.log

  # Generate secure code
  python cli.py generate "JWT authentication in Python"

  # Build / refresh the RAG knowledge base
  python cli.py build-kb
"""

import sys
import click
from rich.console import Console

console = Console()


# ---------------------------------------------------------------------------
# CLI entry-point
# ---------------------------------------------------------------------------

@click.group()
@click.version_option("0.1.0", prog_name="Cyvereign")
def cli() -> None:
    """
    🔒 Cyvereign – Local Cyber-Security AI System

    Powered by Ollama + ChromaDB + HuggingFace Embeddings
    """


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

@cli.command()
@click.argument("question")
@click.option("--no-rag", is_flag=True, default=False, help="Disable RAG context enrichment")
@click.option("--model", default=None, help="Override the Ollama model name")
def ask(question: str, no_rag: bool, model: str | None) -> None:
    """
    Ask the AI a cyber-security question.

    QUESTION  The question or code snippet to analyse (use quotes).

    \b
    Examples:
      python cli.py ask "Explain SQL injection with a Python example"
      python cli.py ask "Is this code safe: os.system(user_input)"
    """
    agent = _create_agent(use_rag=not no_rag, model=model)
    agent.ask(question)


@cli.command()
@click.argument("path")
@click.option("--model", default=None, help="Override the Ollama model name")
def scan(path: str, model: str | None) -> None:
    """
    Scan a file or directory for security vulnerabilities.

    PATH  Path to the source file or project directory.

    \b
    Examples:
      python cli.py scan ./app.py
      python cli.py scan ./my_project
    """
    agent = _create_agent(model=model)
    agent.scan(path)


@cli.command()
@click.argument("cve_id")
@click.option("--model", default=None, help="Override the Ollama model name")
def cve(cve_id: str, model: str | None) -> None:
    """
    Look up a CVE by ID and get an AI-powered explanation.

    CVE_ID  CVE identifier (e.g. CVE-2021-44228).

    \b
    Examples:
      python cli.py cve CVE-2021-44228
      python cli.py cve CVE-2014-0160
    """
    agent = _create_agent(model=model)
    agent.cve(cve_id)


@cli.command()
@click.argument("log_path")
@click.option("--model", default=None, help="Override the Ollama model name")
def logs(log_path: str, model: str | None) -> None:
    """
    Analyse a log file for suspicious / malicious activity.

    LOG_PATH  Path to the log file.

    \b
    Examples:
      python cli.py logs /var/log/nginx/access.log
      python cli.py logs ./server.log
    """
    agent = _create_agent(model=model)
    agent.logs(log_path)


@cli.command()
@click.argument("description")
@click.option("--language", "-l", default="python", show_default=True, help="Target language")
@click.option("--model", default=None, help="Override the Ollama model name")
def generate(description: str, language: str, model: str | None) -> None:
    """
    Generate a secure code snippet from a description.

    DESCRIPTION  What the code should do (use quotes for multi-word descriptions).

    \b
    Examples:
      python cli.py generate "JWT authentication middleware"
      python cli.py generate "Secure file upload handler" --language python
      python cli.py generate "SQL query builder" --language go
    """
    agent = _create_agent(model=model)
    agent.generate_secure_code(description, language=language)


@cli.command("build-kb")
@click.option("--model", default=None, help="Override the Ollama model name")
def build_kb(model: str | None) -> None:
    """
    Build or refresh the RAG knowledge base from the datasets/ folders.

    Run this once after adding new documents to:
      datasets/cve/, datasets/owasp/, datasets/pentest/, datasets/security_research/

    \b
    Example:
      python cli.py build-kb
    """
    agent = _create_agent(model=model)
    agent.build_knowledge_base()


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _create_agent(use_rag: bool = True, model: str | None = None):
    """Import and instantiate the agent (deferred so --help works without deps)."""
    try:
        from agent.cybersec_agent import CybersecAgent
        return CybersecAgent(model=model, use_rag=use_rag)
    except ImportError as exc:
        console.print(
            f"[red]Failed to import Cyvereign modules: {exc}\n"
            "Make sure you have installed the requirements:\n"
            "  pip install -r requirements.txt[/red]"
        )
        sys.exit(1)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    cli()
