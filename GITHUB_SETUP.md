# Push to GitHub Instructions

Your RAG security evaluation project is now ready to push to GitHub!

## Steps:

1. **Create a new repository on GitHub**:
   - Go to https://github.com/new
   - Repository name: `rag-security-eval`
   - Description: "Security evaluation framework for Retrieval-Augmented Generation systems"
   - Choose Public or Private
   - Do NOT initialize with README, .gitignore, or license (we already have them)
   - Click "Create repository"

2. **Add the remote and push**:
   ```powershell
   cd C:\Users\srive\rag-security-eval
   git remote add origin https://github.com/YOUR_USERNAME/rag-security-eval.git
   git branch -M main
   git push -u origin main
   ```
   
   Replace `YOUR_USERNAME` with your GitHub username.

3. **Or use SSH** (if you have SSH keys configured):
   ```powershell
   git remote add origin git@github.com:YOUR_USERNAME/rag-security-eval.git
   git branch -M main
   git push -u origin main
   ```

## Repository Contents:

- `/data/` - Enterprise knowledge base text files
- `/attacks/` - Attack scenario definitions (prompt injection, retrieval poisoning, knowledge leakage)
- `/defenses/` - Defense mechanisms (filtering, prompt separation, redaction)
- `/evaluation/` - Experiment runner and metrics calculation
- `rag_system.py` - Core RAG pipeline with LangChain + FAISS
- `run_experiments.py` - Entry point to run all experiments
- `requirements.txt` - Python dependencies
- `README.md` - Full project documentation

## After Push:

Your repository will be live at:
- `https://github.com/YOUR_USERNAME/rag-security-eval`

You can then:
- Share the link with collaborators
- Set up GitHub Actions for CI/CD
- Enable GitHub Pages for documentation
- Add Issues and Pull Requests for feature tracking

---

Generated: May 29, 2026
