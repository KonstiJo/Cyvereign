"""
agent/cybersec_agent.py
=======================
The main Cyvereign agent that orchestrates all components:

  LLM (Ollama) ──► SecureCodeGenerator
       │
       ├── RAG (ChromaDB) ──► VectorStore / Embeddings
       │
       └── Tools:
             ├── CodeAnalyzer   – static vulnerability scanning
             ├── CVELookup      – NVD CVE database queries
             ├── LogAnalyzer    – server log inspection
             └── SecureCodeGenerator – LLM-powered secure coding

Public interface matches the problem statement:
    cybersec_ai = CybersecAgent()
    cybersec_ai.ask("Analysiere diesen Code")
    cybersec_ai.scan("project_folder")
"""

from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel

from models.llm_interface import LLMInterface
from rag.vector_store import VectorStore
from tools.code_analyzer import CodeAnalyzer
from tools.cve_lookup import CVELookup
from tools.log_analyzer import LogAnalyzer
from tools.secure_code_generator import SecureCodeGenerator

console = Console()

# System prompt for the agent – drives all LLM interactions
_AGENT_SYSTEM_PROMPT = """\
You are Cyvereign, an expert AI assistant specialising in cyber security and
secure software development.

Your expertise covers:
- Python, C, C++, Go, JavaScript/TypeScript
- Code vulnerability analysis (OWASP Top 10, CWE database)
- Secure coding practices and design patterns
- Penetration testing techniques and tools
- CVE research and advisory interpretation
- Red-team / blue-team concepts

When analysing code:
1. Identify ALL security issues with their CWE/OWASP reference
2. Rate severity: Critical / High / Medium / Low
3. Provide concrete, working fixes

Always be concise, accurate, and educational.
"""


class CybersecAgent:
    """
    Top-level Cyvereign agent.

    Usage:
        agent = CybersecAgent()

        # Ask a question (with optional RAG context)
        agent.ask("What is a buffer overflow?")

        # Analyse a code snippet
        agent.ask("Is this code safe?  ```python\\neval(user_input)\\n```")

        # Scan an entire project folder for vulnerabilities
        agent.scan("./my_project")

        # Look up a CVE
        agent.cve("CVE-2021-44228")

        # Analyse a log file
        agent.logs("/var/log/nginx/access.log")
    """

    def __init__(
        self,
        model: Optional[str] = None,
        use_rag: bool = True,
        verbose: bool = True,
    ):
        """
        Parameters
        ----------
        model:    Override the default Ollama model name.
        use_rag:  Enable RAG (requires a built vector store). Set False to skip.
        verbose:  Print rich-formatted output to the terminal.
        """
        self.verbose = verbose

        # Core LLM
        self.llm = LLMInterface(model=model) if model else LLMInterface()

        # RAG knowledge store (lazy – only used when available)
        self.rag: Optional[VectorStore] = VectorStore() if use_rag else None

        # Cyber security tools
        self.code_analyzer = CodeAnalyzer()
        self.cve_lookup = CVELookup()
        self.log_analyzer = LogAnalyzer()
        self.code_gen = SecureCodeGenerator(llm=self.llm)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def ask(self, question: str) -> str:
        """
        Ask the AI a cyber-security question, optionally enriched with RAG context.

        Parameters
        ----------
        question: Free-text question or code snippet to analyse.

        Returns
        -------
        The LLM's answer as a string.
        """
        prompt = self._build_rag_prompt(question)
        self._print_header(f"[bold cyan]Question[/bold cyan]", question)

        response = self.llm.ask(prompt, system_prompt=_AGENT_SYSTEM_PROMPT)

        if self.verbose:
            console.print(Panel(Markdown(response), title="Cyvereign", border_style="green"))

        return response

    def scan(self, path: str) -> str:
        """
        Scan a file or directory for security vulnerabilities using static analysis.
        Results are enriched with LLM explanations.

        Parameters
        ----------
        path: Path to the file or directory to scan.

        Returns
        -------
        A formatted scan report as a string.
        """
        p = Path(path)
        if not p.exists():
            msg = f"Path not found: {path}"
            console.print(f"[red]{msg}[/red]")
            return msg

        self._print_header("[bold yellow]Scanning[/bold yellow]", str(p))

        # Run static analysis
        if p.is_file():
            results = [self.code_analyzer.scan_file(str(p))]
        else:
            results = self.code_analyzer.scan_directory(str(p))

        # Build a report
        report_lines = []
        for result in results:
            report_lines.append(result.summary())
            for vuln in result.vulnerabilities:
                report_lines.append(
                    f"  Line {vuln.line_number:>4} | [{vuln.severity:6}] "
                    f"{vuln.category} ({vuln.cwe})\n"
                    f"           → {vuln.line_content[:80]}"
                )

        report = "\n".join(report_lines) if report_lines else "✅ No files found to scan."

        if self.verbose:
            console.print(Panel(report, title="Static Analysis Report", border_style="yellow"))

        # If vulnerabilities were found, ask the LLM for a summary + advice
        total_vulns = sum(len(r.vulnerabilities) for r in results)
        if total_vulns > 0:
            vuln_summary = "\n".join(
                f"- {v.category} (line {v.line_number}): {v.line_content[:60]}"
                for r in results
                for v in r.vulnerabilities
            )
            llm_prompt = (
                f"I scanned the code at '{path}' and found these vulnerabilities:\n"
                f"{vuln_summary}\n\n"
                "Please provide:\n"
                "1. A risk summary\n"
                "2. Prioritised remediation steps\n"
                "3. Any additional security recommendations"
            )
            advice = self.llm.ask(
                self._build_rag_prompt(llm_prompt),
                system_prompt=_AGENT_SYSTEM_PROMPT,
            )
            if self.verbose:
                console.print(
                    Panel(Markdown(advice), title="LLM Security Advice", border_style="red")
                )
            report += "\n\n--- LLM Advice ---\n" + advice

        return report

    def cve(self, cve_id: str) -> str:
        """
        Look up a CVE by ID and provide an AI-powered explanation.

        Parameters
        ----------
        cve_id: CVE identifier, e.g. "CVE-2021-44228"
        """
        self._print_header("[bold magenta]CVE Lookup[/bold magenta]", cve_id)

        entry = self.cve_lookup.get_cve(cve_id)
        if entry is None:
            msg = f"CVE {cve_id} not found in NVD."
            console.print(f"[red]{msg}[/red]")
            return msg

        cve_text = str(entry)

        if self.verbose:
            console.print(Panel(cve_text, title=cve_id, border_style="magenta"))

        # Ask the LLM to explain the CVE and suggest mitigations
        llm_prompt = (
            f"Explain this CVE and provide actionable mitigation steps:\n\n{cve_text}"
        )
        explanation = self.llm.ask(
            self._build_rag_prompt(llm_prompt),
            system_prompt=_AGENT_SYSTEM_PROMPT,
        )

        if self.verbose:
            console.print(
                Panel(Markdown(explanation), title="AI Explanation", border_style="green")
            )

        return cve_text + "\n\n--- AI Explanation ---\n" + explanation

    def logs(self, log_path: str) -> str:
        """
        Analyse a log file for suspicious activity.

        Parameters
        ----------
        log_path: Path to the log file.
        """
        self._print_header("[bold blue]Log Analysis[/bold blue]", log_path)

        result = self.log_analyzer.analyze_file(log_path)

        report = result.summary() + "\n"
        for alert in result.alerts[:50]:  # cap at 50 for readability
            line_info = f"line {alert.line_number}" if alert.line_number else "summary"
            report += (
                f"\n  [{alert.severity:6}] {alert.category}"
                f" ({line_info})"
                + (f" – IP: {alert.ip_address}" if alert.ip_address else "")
            )

        if self.verbose:
            console.print(Panel(report, title="Log Analysis Report", border_style="blue"))

        # Ask the LLM to interpret the findings
        if result.alerts:
            alert_summary = "\n".join(
                f"- {a.severity}: {a.category}"
                + (f" from IP {a.ip_address}" if a.ip_address else "")
                for a in result.alerts[:20]
            )
            llm_prompt = (
                f"I analysed the log file '{log_path}' and found:\n{alert_summary}\n\n"
                "Please provide:\n"
                "1. Interpretation of these findings\n"
                "2. Whether they indicate an active attack\n"
                "3. Recommended incident response steps"
            )
            interpretation = self.llm.ask(
                self._build_rag_prompt(llm_prompt),
                system_prompt=_AGENT_SYSTEM_PROMPT,
            )
            if self.verbose:
                console.print(
                    Panel(
                        Markdown(interpretation),
                        title="AI Interpretation",
                        border_style="green",
                    )
                )
            report += "\n\n--- AI Interpretation ---\n" + interpretation

        return report

    def generate_secure_code(self, description: str, language: str = "python") -> str:
        """
        Generate a secure code snippet from a description.

        Parameters
        ----------
        description: What the code should do.
        language:    Target programming language.
        """
        self._print_header("[bold green]Secure Code Generation[/bold green]", description)
        code = self.code_gen.generate(description, language=language)
        if self.verbose:
            console.print(Panel(Markdown(code), title="Generated Code", border_style="green"))
        return code

    def build_knowledge_base(self) -> None:
        """
        (Re-)index all dataset documents into the ChromaDB vector store.
        Run this once after adding new documents to the datasets/ folders.
        """
        if self.rag is None:
            console.print("[yellow]RAG is disabled. Pass use_rag=True to enable.[/yellow]")
            return
        console.print("[cyan]Building knowledge base – this may take a few minutes…[/cyan]")
        count = self.rag.build_index()
        console.print(f"[green]✓ Knowledge base built with {count} chunks.[/green]")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_rag_prompt(self, question: str) -> str:
        """
        Prepend relevant RAG context to the prompt if available.
        """
        if self.rag is None:
            return question
        try:
            context = self.rag.get_context_string(question, k=3)
        except Exception:
            # Vector store may be empty on first run – that's OK
            context = ""

        if context:
            return (
                f"[Relevant Knowledge Base Context]\n{context}\n\n"
                f"[User Question]\n{question}"
            )
        return question

    def _print_header(self, label: str, value: str) -> None:
        if self.verbose:
            console.print(f"\n{label}: [white]{value[:120]}[/white]")
