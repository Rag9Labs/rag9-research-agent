# RAG9 Labs — Research Agent

A secure, extensible research agent built on LangGraph and Ollama.

Searches the web, reasons about results, and structures findings clearly — with a Content Firewall that strips prompt injection attempts before they reach the model.

Built in the open. Every design decision earned through testing, not assumed.  
Read the full build story in the [Builder's Journal](https://rag9labs.com/blog).

---

## What This Is

A ReAct-pattern research agent — **Re**asoning + **Act**ing. The agent thinks, searches, reads what it found, thinks again, and searches again if needed. It does not stop at the first result.

Key behaviors built into the architecture — not just the prompt:

- **Forced multi-query search** — runs up to 3 targeted queries per question. The model cannot skip searching and answer from memory. This was enforced at the code level after testing showed local models ignore prompt instructions to search first.
- **Content Firewall** — every search result is scanned for prompt injection attempts before the agent sees it. Malicious instructions embedded in web pages are stripped silently. You get a visible warning when this happens.
- **PBOM Hash** — the system prompt is hashed at startup. The hash is displayed in the banner. If someone modifies the agent and redistributes it, the hash changes. You can verify the behavioral contract has not been tampered with.
- **Date injection** — today's date is injected into every session so the agent can anchor searches to the present and find recent events.

---

## Prerequisites

**Python 3.11 or higher**
```bash
python --version
```

**Ollama** — the local model runtime  
Install from [https://ollama.com](https://ollama.com)  
Ollama runs as a background service. Once installed, it starts automatically.

**A pulled model**
```powershell
ollama pull llama3.1:8b
```

> **Which model should I use?**  
> See the [Model Selection Guide](#model-selection-guide) below.

---

## Installation

**1. Clone the repo**
```powershell
git clone https://github.com/Rag9Labs/rag9-research-agent.git
cd rag9-research-agent
```

**2. Create and activate a virtual environment**
```powershell
python -m venv agent_env
agent_env\Scripts\Activate.ps1
```

**3. Install dependencies**
```powershell
pip install -r requirements.txt
```

---

## Configuration

This agent reads its model settings from **Windows System Environment Variables**.  
No `.env` files. No hardcoded credentials. This is the RAG9 secure way.

> **Why not a `.env` file?**  
> `.env` files inside project directories can be read by prompt injection attacks through poisoned MCP payloads. System environment variables are outside the project path and cannot be accessed this way. This is a real threat — not a theoretical one.

**Set your model permanently** (PowerShell, run as Administrator):
```powershell
[System.Environment]::SetEnvironmentVariable("RESEARCH_AGENT_MODEL", "llama3.1:8b", "Machine")
[System.Environment]::SetEnvironmentVariable("RESEARCH_AGENT_PROVIDER", "ollama", "Machine")
```
Restart your terminal after setting.

**Set your model for the current session only** (no admin required):
```powershell
$env:RESEARCH_AGENT_MODEL = "llama3.1:8b"
```

**Check what is currently set:**
```powershell
echo $env:RESEARCH_AGENT_MODEL
```

If no variable is set, the agent defaults to `llama3.1:8b`.

---

## Running

```powershell
python research_agent.py
```

You should see:
```
=================================================================
  RAG9 Labs — Research Agent v3.0.0
=================================================================

  Model     : llama3.1:8b
  Provider  : ollama
  Date      : May 13, 2026
  Security  : Content Firewall ACTIVE
  PBOM Hash : c9c7e5a8b4d5457a  ← verify this matches between sessions

✅ Research Agent ready.
```

The **PBOM Hash** should be the same every time you run unmodified code.  
If it changes without a version update — investigate.

---

## How to Prompt This Agent

This is the most important section in this README.

**The single biggest factor in result quality is how you phrase your question.**  
Specific questions return specific answers. General questions return general answers.

The agent runs 3 searches per question — broad first, then date-anchored variants.  
But the base query comes from your question. Give it something to work with.

### Weak vs Strong Prompts

| Weak | Strong |
|------|--------|
| What happened in AI security recently? | What supply chain attacks hit Python packages in May 2026? |
| Tell me about AI. | What is LangGraph and how does it handle tool calling in Python? |
| What are the latest AI models? | What models did Anthropic release in the first half of 2026? |
| Tell me about that attack. | Tell me about the Mini Shai-Hulud npm supply chain attack in May 2026. |

### Rules of thumb

**Include proper nouns** — names, companies, products, CVE numbers, package names.  
Vague: `"a recent security vulnerability"`  
Better: `"CVE-2026-45321 TanStack npm supply chain attack"`

**Include dates when you know them** — the agent adds the current year automatically, but if you know the month, include it.  
Vague: `"recent PyPI attack"`  
Better: `"PyPI supply chain attack May 2026"`

**Ask one thing at a time** — compound questions split the agent's focus.  
Vague: `"Tell me about AI security and also what models are available and how do I install them"`  
Better: Three separate questions.

**Be honest about what you don't know** — if you're not sure of the name, describe what you remember.  
`"There was a supply chain attack on a JavaScript routing library in May 2026 — what do you know about it?"`  
The agent will find it.

---

## Model Selection Guide

The right model depends on your hardware. This matters — the same code produces very different results on different models.

| Hardware | Recommended Model | Notes |
|----------|------------------|-------|
| Modern GPU, 12GB+ VRAM | `llama3.1:8b` or `mistral:7b` | Best local results |
| Older GPU, 8GB VRAM | `mistral:7b` or `qwen2.5:7b` | Solid performance |
| CPU only / low RAM | `phi3:mini` or `gemma2:2b` | Faster, less precise |
| Cloud API | See [Growth Path](#growth-path) | Best for current events |

**Pull any model with Ollama:**
```powershell
ollama pull mistral:7b
ollama pull gemma2:2b
ollama pull phi3:mini
```

**Then set it as your model:**
```powershell
$env:RESEARCH_AGENT_MODEL = "mistral:7b"
```

> **Important:** Local 7-8B models may not surface very recent events precisely.  
> This is a model capability limit, not a code limit. For current news research,  
> cloud models (Claude, GPT-4, Grok) perform significantly better.  
> See [Growth Path](#growth-path) for how to connect a cloud model.

---

## Known Limitations

These are honest. We built this through real testing and these are real findings.

**1. Local models struggle with very recent events**  
Even with forced web search, local 7-8B models generate imprecise queries for events from the last few days. Specific questions work better than general ones. Cloud models handle this significantly better.

**2. No session memory**  
Each question starts fresh. The agent does not remember what it found in the previous question. Ask follow-up questions by including the context in the new question.  
Works: `"Tell me more about the Mini Shai-Hulud attack you just described"`  
Does not work: `"Tell me more about that"` ← the agent has no memory of "that"

**3. Search quality depends on phrasing**  
See [How to Prompt This Agent](#how-to-prompt-this-agent) above.

**4. The agent can still be wrong**  
Web search results can be incomplete, outdated, or incorrect. The agent structures what it finds — it does not verify it. Always check sources for high-stakes decisions.

---

## Security Notes

**Content Firewall**  
Every search result is scanned for prompt injection attempts — malicious instructions embedded in web pages that try to hijack the agent. Suspicious sentences are stripped silently. You get a visible terminal warning when this happens:

```
⚠️  SECURITY WARNING: Injection attempt detected in search: 'your query'
   Suspicious content stripped. Research continues.
```

**PBOM Hash**  
The system prompt hash at startup is your tamper indicator. Note it the first time you run the agent. It should be identical every time you run the same version. A changed hash without a version update means the agent has been modified.

**No .env files**  
This agent deliberately does not use `.env` files. See [Configuration](#configuration) for why and how to set credentials securely.

---

## Growth Path

This agent is a foundation, not a ceiling. Here is where it goes next:

**Swap search providers**  
Replace `SecureDuckDuckGoSearch` with any LangChain-compatible search tool. Security rule: always wrap new tool output with `scan_for_injection()`.

**Connect a cloud model**  
```python
from langchain_anthropic import ChatAnthropic
self.llm = ChatAnthropic(
    model=os.environ.get("RESEARCH_AGENT_MODEL", "claude-sonnet-4-20250514"),
    api_key=os.environ.get("ANTHROPIC_API_KEY")
)
```
Store API keys in Windows System environment variables — never in code.

**Query decomposition**  
Ask the model to decompose the question into semantically different sub-queries before searching. More coverage, better results.

**Session memory**  
Use LangGraph checkpointers for full conversation history. Enables genuine follow-up questions.

**PBOM v2**  
Every instruction the agent acts on gets registered, hashed, and verified before execution. The hash in this version is the seed of that idea.  
Read more: [https://rag9labs.com/labs/scratch-pad](https://rag9labs.com/labs/scratch-pad)

**Multi-agent confirmation**  
Two models — one for search, one for verification. Compare outputs from different reasoning systems. This is the beginning of the Council of Minds pattern.

---

## About

Built by [DataBob](https://rag9.com) — founder of RAG9 and Framework Business Solutions.  
AI architect with 30+ years of data engineering experience.

Part of the RAG9 Labs open source community.  
The RAG9 way: build in the open, document what you learn, give away the harvest.

- Website: [https://rag9labs.com](https://rag9labs.com)
- Community: [https://github.com/Rag9Labs](https://github.com/Rag9Labs)
- Builder's Journal: [https://rag9labs.com/blog](https://rag9labs.com/blog)

---

## License

MIT License — free to use, modify, and distribute with attribution.  
See [LICENSE](LICENSE) for full terms.
