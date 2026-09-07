# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
LLM prompt-template pack for N-AALP-conformant JSON-Schema authoring (R10 item 5).

The templates live as real markdown files under `prompt_templates/` (data, not code) and are
loaded from disk here -- never inlined as Python string literals -- so the content a caller
gets back is exactly the file a maintainer edits, and this module's own contract (read a
named template, or list what is available) stays a real file-system operation rather than a
lookup into a dict this module would otherwise need to keep in sync with the files by hand.
"""
import os

__all__ = ["list_prompts", "load_prompt"]

_TEMPLATES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "prompt_templates")


def list_prompts():
    """The sorted list of available prompt-template names (without the .md extension)."""
    return sorted(f[:-3] for f in os.listdir(_TEMPLATES_DIR) if f.endswith(".md"))


def load_prompt(name):
    """Return the full markdown text of the named prompt template. Raises FileNotFoundError
    (naming the available templates) if `name` is not one of them."""
    path = os.path.join(_TEMPLATES_DIR, name + ".md")
    if not os.path.isfile(path):
        raise FileNotFoundError(
            "no prompt template named %r; available: %s" % (name, ", ".join(list_prompts())))
    with open(path, encoding="utf-8") as f:
        return f.read()
