Quick publish & preview instructions

Local preview

- From the project root, run a simple static server and open http://localhost:8000

  Python 3:

  ```bash
  python -m http.server 8000
  ```

  Then open the browser at `http://localhost:8000`.

Publish to GitHub Pages (automated)

1. Create a GitHub repository and push this folder as the repository root (or make this folder the repo).
2. Ensure the default branch is `main` (the workflow triggers on `push` to `main`).
3. Commit and push all files to GitHub.
4. The workflow `.github/workflows/pages.yml` will run and deploy the repository root to GitHub Pages.
5. After the workflow completes, go to your repository Settings → Pages to confirm the site URL (it should be available under the `Pages` section).

Notes

- This deploy uses GitHub Pages Actions and publishes the repository root. If you prefer a different branch or folder (e.g., `gh-pages`), let me know and I can adjust the workflow.
- If you want me to push the repo or open a PR, I can prepare a commit for you to inspect; you'll need to push it to GitHub from your machine.
