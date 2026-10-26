# Where the handoff HTML fixtures come from

Each `.html` file is the `bodyHTML` GitHub returned on 2026-10-26 from a read-only GraphQL query on an existing public
item of this repository. Nothing was written to GitHub. They are verbatim, apart from the one trailing newline.

| File | Source | Constructs it shows |
|---|---|---|
| `issue_comment_with_list.html` | issue comment on pull/5, `#issuecomment-6046653492` (`IssueComment.bodyHTML`) | top-level `<p>`, `<h3>`, `<ul>/<li>`, links |
| `pr_body_with_details_and_blockquote.html` | body of pull/38 (`PullRequest.bodyHTML`) | `<details>/<summary>`, `<blockquote>`, nested lists, inline `<code>` |
| `pr_body_with_fenced_code.html` | body of pull/5 (`PullRequest.bodyHTML`) | a fenced block as `<div class="snippet-clipboard-content ..."><div class="highlight ..."><pre>` |
| `pr_body_with_dropped_html_comment.html` | body of pull/39 (`PullRequest.bodyHTML`) | the raw body holds `<!-- raw HTML omitted -->`; the HTML holds no comment at all |
| `paragraph_with_hard_break_fragment.html` | one paragraph of the body of pull/40 | a hard break as `<br>` followed by a newline inside `<p dir="auto">` |

Same Markdown renderer, other node types: pull request bodies are not issue comments. The repository has no issue
comment with a fence, a blockquote or an HTML comment, so a pull request body was used where it had one.

No item in the repository shows these, so every test input for them is hand-written and UNVERIFIED against GitHub's
renderer: a four-space indented code block, a `<pre>` HTML block, a tilde fence, a nested fence whose inner fence has
fewer backticks than the opener, a top-level blockquote, a top-level list item holding a report, and a plain paragraph
with a report in it. They live in `tests/handoff_render.py` (a small stand-in renderer) and in inline strings in the
tests. The shapes they produce (`<pre class="notranslate"><code>`, `<blockquote>`, `<ul dir="auto"><li>`,
`<p dir="auto">...<br>\n...</p>`) are copied from the real fixtures above.
