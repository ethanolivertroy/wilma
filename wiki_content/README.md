# Wilma Wiki Content

This directory contains educational wiki pages about AWS Bedrock security.

## How to Publish to GitHub Wiki

GitHub wikis are actually separate Git repositories. Here's how to publish this content:

### Method 1: Manual (First Time Setup)

1. **Initialize the wiki** (one-time):
   - Go to https://github.com/ethanolivertroy/wilma/wiki
   - Click "Create the first page"
   - Add any content and save

2. **Clone the wiki repository**:
   ```bash
   git clone https://github.com/ethanolivertroy/wilma.wiki.git
   cd wilma.wiki
   ```

3. **Copy content**:
   ```bash
   # From the main repo:
   cp ../wilma/wiki_content/*.md .
   ```

4. **Commit and push**:
   ```bash
   git add *.md
   git commit -m "Add comprehensive security education wiki"
   git push origin master
   ```

### Method 2: Automated (After Initial Setup)

Create a GitHub Action to sync wiki content:

```yaml
# .github/workflows/sync-wiki.yml
name: Sync Wiki
on:
  push:
    paths:
      - 'wiki_content/**'
    branches:
      - main

jobs:
  sync:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Sync to Wiki
        uses: Andrew-Chen-Wang/github-wiki-action@v4
        with:
          wiki-directory: wiki_content
```

## Wiki Pages Structure

### Core Educational Content
- **Home.md** - Overview and navigation
- **GenAI-Security-Fundamentals.md** - Core concepts (7 pillars)
- **OWASP-LLM-Top-10.md** - Threat taxonomy with real examples
- **Knowledge-Bases-RAG-Security.md** - Deep dive into RAG security (12 checks)

### Practical Guides
- **Installation-Guide.md** - Get started in 5 minutes

### Planned Pages
- Understanding-Wilma-Output.md
- Guardrails-Security.md
- Agents-Security.md
- Fine-Tuning-Security.md
- MITRE-ATLAS-Framework.md
- Real-World-Attack-Examples.md
- Remediation-Workflows.md
- CI-CD-Integration.md
- CloudShell-Guide.md
- AWS-Bedrock-Security-Checklist.md

## Content Philosophy

Each wiki page follows this structure:

1. **Start with "What It Is"** - Define the concept
2. **Explain the Threat** - Why it matters
3. **Real-World Examples** - Make it concrete
4. **How Wilma Helps** - Tie back to tool capabilities
5. **How to Fix** - Actionable remediation steps
6. **Defense in Depth** - Layered security approach

### Writing Style

- **Educational first** - Teach the "why", not just the "what"
- **Real-world focus** - Use actual attack scenarios
- **Avoid jargon** - Explain technical terms when used
- **Visual aids** - ASCII diagrams, code examples, tables
- **Actionable** - Every page should have "How to Fix" sections

## Contributing to the Wiki

To add new wiki pages:

1. Create markdown file in `wiki_content/`
2. Follow the naming convention: `Title-With-Hyphens.md`
3. Add navigation links at bottom: `[← Previous](Page) | [Next →](Page)`
4. Update `Home.md` with link to new page
5. Test locally with a markdown previewer
6. Commit and sync to wiki

## Maintenance

The wiki should be updated when:
- New security checks are implemented
- OWASP LLM Top 10 is updated
- Real-world incidents occur
- User feedback identifies gaps

## License

All wiki content is licensed under GPL v3, same as the main project.
