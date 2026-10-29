# GitHub Upload Instructions

Repository name: **mini-soc-log-analyzer**
Account: **mustbearman**
Final URL: `https://github.com/mustbearman/mini-soc-log-analyzer`

> The repository has NOT been uploaded for you. Uploading needs your GitHub login, which only you can provide.

## Before you start

1. Install Git: https://git-scm.com/downloads
2. Unzip `mini-soc-log-analyzer.zip` and open a terminal in the unzipped `mini-soc-log-analyzer` folder.
3. Run the tests once: `python -m unittest discover` (you should see `OK`).

## Step 1 - Create the empty repository on GitHub (browser)

1. Sign in at https://github.com as `mustbearman`.
2. Click **+** (top right) -> **New repository**.
3. Repository name: `mini-soc-log-analyzer`.
4. Description: `Python tool that analyzes SSH auth logs, flags repeated failed logins and writes a Markdown triage report (synthetic data, learning project).`
5. Choose **Public**.
6. **Do NOT** tick "Add a README", ".gitignore" or "license" (the project already has them).
7. Click **Create repository**.

## Step 2 - Push from your computer (terminal)

```bash
git config --global user.name "Your Name"
git config --global user.email "your-email@example.com"   # or your GitHub noreply address

git init -b main
git add .
git status                      # check: no output/ folder, no __pycache__
git commit -m "Initial commit: Mini SOC Log Analyzer"
git remote add origin https://github.com/mustbearman/mini-soc-log-analyzer.git
git push -u origin main
```

### Authentication (the step only you can do)

GitHub no longer accepts your account password for `git push`. Use ONE of:

- **GitHub CLI (easiest):** install from https://cli.github.com, run `gh auth login`, choose GitHub.com -> HTTPS -> "Login with a web browser", then run `git push -u origin main` again.
- **Personal access token:** GitHub -> Settings -> Developer settings -> Personal access tokens -> generate a token with `repo` scope. When `git push` asks for a password, paste the token. Never put the token in a file or commit it.
- **Git Credential Manager (Windows/Mac):** a browser sign-in window appears on first push; just sign in.

## Alternative - no command line (web upload)

On the empty repository page choose **uploading an existing file**, drag the *contents* of the unzipped folder (including `soc_analyzer`, `tests`, `docs`, etc.) into the page, and click **Commit changes**. Check that the folders kept their structure.

## Step 3 - After upload

1. Open the repository and confirm `README.md` renders and the Mermaid diagram in `docs/ARCHITECTURE.md` displays.
2. Add topics (gear icon next to "About"): `python`, `cybersecurity`, `soc`, `log-analysis`, `ssh`, `incident-response`.
3. Pin the repository on your profile and add the link to your resume and LinkedIn.
4. Optional: replace the placeholder name in `LICENSE` if you want your full legal name.
5. Check the repo contains no real logs, passwords or tokens.

## Common problems

| Problem | Fix |
|---|---|
| `remote origin already exists` | `git remote set-url origin https://github.com/mustbearman/mini-soc-log-analyzer.git` |
| `Authentication failed` | Use a token or `gh auth login` as above |
| `failed to push some refs` | You created the repo with a README; run `git pull origin main --allow-unrelated-histories`, resolve, push again |
| `python` not found on Windows | Use `py -m unittest discover` |
