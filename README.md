# CyberShield — NGO Incident Response Toolkit

A free, static website that walks NGOs, activists and journalists through a 7-step questionnaire and generates a tailored cybersecurity action plan after a suspected hack. Includes a companion page for a Windows hardening helper tool.

## Files

| File | Purpose |
|------|---------|
| `ngo-incident-response.html` | Main assessment builder (landing + wizard + generated plan). |
| `windows-tool.html` | Landing page for the CyberShield Hardener Windows tool. |
| `tools/` | The real Windows tool — PowerShell + WinForms GUI, plus launcher scripts. See [`tools/README.md`](tools/README.md). |
| `robots.txt` | Allows all crawlers and points to the sitemap. |
| `sitemap.xml` | Lists both public pages for Google Search Console. |
| `vercel.json` | Clean URLs, redirects, security headers, caching config. |

## Local preview

Just open `ngo-incident-response.html` in a browser — no build step, no dependencies.

Or run a local static server:

```bash
npx serve .
# or
python3 -m http.server 8000
```

## Deploy to Vercel (2 options)

### Option A — drag-and-drop (easiest)

1. Go to <https://vercel.com/new>.
2. Drag the entire folder onto the upload area.
3. Vercel auto-detects it as a static site, builds in seconds, and gives you a live URL like `cybershield-xyz.vercel.app`.

### Option B — Git-connected (recommended for updates)

```bash
# 1. initialise a repo
git init
git add .
git commit -m "Initial CyberShield site"

# 2. push to GitHub / GitLab / Bitbucket
git remote add origin <your-repo-url>
git push -u origin main

# 3. install the Vercel CLI and link the project
npm i -g vercel
vercel            # first run links the repo to a Vercel project
vercel --prod     # subsequent pushes to main deploy automatically
```

### After deploy

1. In the Vercel project settings, add a custom domain (e.g. `cybershield.org`).
2. Update the `https://cybershield.example/...` placeholders in:
   - `ngo-incident-response.html` (`<link rel="canonical">`, OG tags, JSON-LD)
   - `windows-tool.html` (same)
   - `sitemap.xml`
   - `robots.txt`
3. Submit the sitemap to [Google Search Console](https://search.google.com/search-console).

## SEO checklist (already done)

- Unique, keyword-rich `<title>` and `<meta name="description">` on both pages.
- Open Graph + Twitter Card tags for social previews.
- Canonical URLs.
- `robots.txt` + `sitemap.xml`.
- Schema.org JSON-LD: `WebApplication` + `FAQPage` on the main page, `SoftwareApplication` on the tool page.
- Semantic HTML: `<header>`, `<nav>`, `<section>`, `<footer>`, `<main>`-able structure.
- Responsive layout (mobile-first CSS).
- Inline SVG favicon (no extra HTTP request).
- Accessible nav (`aria-label`) and meaningful link text.

## What still needs attention after you deploy

- Replace `cybershield.example` with the real domain in the meta tags & sitemap.
- Add a real 1200×630 social image and point `og:image` / `twitter:image` at it.
- Submit the sitemap in Google Search Console and Bing Webmaster Tools.
- Consider a blog / resources section with in-depth articles — it's the single biggest lever for organic traffic.
- Translate the site into the top 3–5 languages used by the NGOs you want to reach, and add `hreflang` tags.
- Run the deployed URL through [PageSpeed Insights](https://pagespeed.web.dev) and fix anything Core-Web-Vitals flags.

## License

Free to use and adapt for humanitarian purposes. If you redistribute, please credit the original project and keep the Access Now helpline links intact — they save lives.
