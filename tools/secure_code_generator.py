"""
tools/secure_code_generator.py
===============================
Uses the local LLM to generate secure code examples and patch insecure code.

This module integrates with `models/llm_interface.py` to leverage the local
Ollama model for code generation tasks.

Features:
  - Generate secure code snippets for common operations
  - Suggest secure alternatives to vulnerable code
  - Create code templates with security best practices
"""

from models.llm_interface import LLMInterface

# System prompt that biases the model toward secure coding practices
_SECURE_CODING_SYSTEM_PROMPT = """\
You are a senior cyber-security engineer and secure coding expert.
Your primary goal is to write and review code with security as the top priority.

When writing code:
- Always validate and sanitise user input
- Use parameterised queries for database access
- Avoid dangerous functions (eval, exec, os.system with user input)
- Follow the principle of least privilege
- Add comments explaining WHY each security measure is in place

When reviewing or patching code:
- Identify the exact vulnerability
- Explain the risk clearly
- Provide a complete, working secure alternative
- Reference the relevant CWE or OWASP category where applicable

Format code blocks with proper language markers (```python, ```c, etc.)
"""


class SecureCodeGenerator:
    """
    Generates and reviews code using the local LLM with a security-focused
    system prompt.

    Usage:
        gen = SecureCodeGenerator()

        # Generate a secure function from scratch
        code = gen.generate("Secure file upload handler in Python (Flask)")
        print(code)

        # Audit and patch existing code
        vulnerable_code = "cursor.execute('SELECT * FROM users WHERE id=' + user_id)"
        patched = gen.patch(vulnerable_code, language="python")
        print(patched)
    """

    def __init__(self, llm: LLMInterface | None = None):
        # Accept an injected LLM instance (useful for testing) or create one
        self.llm = llm or LLMInterface()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate(self, description: str, language: str = "python") -> str:
        """
        Generate a secure code snippet based on a natural-language description.

        Parameters
        ----------
        description: What the code should do (e.g. "JWT authentication middleware").
        language:    Target programming language.

        Returns
        -------
        LLM response containing the secure code and explanations.
        """
        prompt = (
            f"Write a secure {language} implementation for:\n\n"
            f"{description}\n\n"
            "Include:\n"
            "1. Complete, working code\n"
            "2. Comments explaining each security measure\n"
            "3. A brief list of security considerations at the end"
        )
        return self.llm.ask(prompt, system_prompt=_SECURE_CODING_SYSTEM_PROMPT)

    def patch(self, code: str, language: str = "python", context: str = "") -> str:
        """
        Analyse insecure code and return a patched, secure version.

        Parameters
        ----------
        code:     The vulnerable source code to fix.
        language: Programming language of the code.
        context:  Optional extra context (e.g. "This is a login endpoint").

        Returns
        -------
        LLM response explaining the vulnerabilities and providing patched code.
        """
        context_block = f"\nContext: {context}\n" if context else ""
        prompt = (
            f"The following {language} code contains security vulnerabilities."
            f"{context_block}\n"
            f"```{language}\n{code}\n```\n\n"
            "Please:\n"
            "1. Identify all security vulnerabilities\n"
            "2. Explain the risk for each vulnerability (reference CWE/OWASP)\n"
            "3. Provide the complete patched, secure version of the code\n"
            "4. Highlight the key changes you made"
        )
        return self.llm.ask(prompt, system_prompt=_SECURE_CODING_SYSTEM_PROMPT)

    def explain_vulnerability(self, vulnerability_name: str) -> str:
        """
        Ask the LLM to explain a specific vulnerability type with examples.

        Parameters
        ----------
        vulnerability_name: e.g. "SQL Injection", "CWE-79", "OWASP A03:2021"
        """
        prompt = (
            f"Explain the security vulnerability: {vulnerability_name}\n\n"
            "Include:\n"
            "1. What it is and how it works\n"
            "2. A minimal vulnerable code example\n"
            "3. A secure code example that prevents the vulnerability\n"
            "4. Detection and prevention tips"
        )
        return self.llm.ask(prompt, system_prompt=_SECURE_CODING_SYSTEM_PROMPT)

    def review(self, code: str, language: str = "python") -> str:
        """
        Perform a security-focused code review.

        Parameters
        ----------
        code:     Source code to review.
        language: Programming language.
        """
        prompt = (
            f"Perform a thorough security review of the following {language} code:\n\n"
            f"```{language}\n{code}\n```\n\n"
            "Provide:\n"
            "- A severity rating (Critical / High / Medium / Low / Info) for each finding\n"
            "- The relevant CWE identifier\n"
            "- A concrete remediation for each issue\n"
            "- An overall security score out of 10"
        )
        return self.llm.ask(prompt, system_prompt=_SECURE_CODING_SYSTEM_PROMPT)
