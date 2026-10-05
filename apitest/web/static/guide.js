"use strict";

/* ================= how-to-use guide (opened from the "How to use" button) ================= */

const GUIDE_HTML = `<div class="guide">

  <div class="flow big">
    <div class="node"><b>1</b>Fix your Swagger</div><i>→</i>
    <div class="node"><b>2</b>Create a project</div><i>→</i>
    <div class="node"><b>3</b>Run the tests</div><i>→</i>
    <div class="node"><b>4</b>Read the report</div>
  </div>

  <h4><span class="step-n">1</span> Fix your Swagger first</h4>
  <p>apitest only knows what your Swagger says. A vague spec gives false findings and misses real bugs.
    Download the guides and give them to your developers or your AI assistant.</p>
  <div class="downloads">
    <a class="dl" href="/guides/SWAGGER_GUIDE.md" download><b>Swagger guide</b><span>What to put in the spec, with ASP.NET Core and Express examples, and a checklist</span><u>Download .md</u></a>
    <a class="dl" href="/guides/AI_RULES_OPENAPI.md" download><b>AI assistant rules</b><span>Paste into CLAUDE.md / AGENTS.md / Copilot instructions so the spec stays correct</span><u>Download .md</u></a>
  </div>
  <p class="hint">The spec must describe what the server really does:</p>
  <div class="match" role="img" aria-label="The spec and the server must agree on security, status codes, response shapes and input rules">
    <div class="end">Swagger spec</div><i>⟷</i>
    <div class="mid"><span>must match on</span>
      <ul>
        <li>Who needs a login (security)</li>
        <li>Every status code returned</li>
        <li>Response shapes and field types</li>
        <li>Rules for input (min, max, required…)</li>
      </ul></div><i>⟷</i>
    <div class="end">Real server</div>
  </div>

  <h4><span class="step-n">2</span> Create a project</h4>
  <p>One project = one app and its Swagger. Use <b>New project</b> on the Projects page.</p>
  <div class="flow">
    <div class="node"><b>Find the APIs</b><small>Paste the app or Swagger URL, click Discover</small></div><i>→</i>
    <div class="node"><b>Project</b><small>Name, base URL</small></div><i>→</i>
    <div class="node"><b>Test users</b><small>User A, User B, secrets, BOLA</small></div><i>→</i>
    <div class="node"><b>Tests</b><small>Pick the stages</small></div>
  </div>
  <ul class="tight">
    <li><b>User A</b> is the main test user. <b>User B</b> is an ordinary user from another organisation, used to check that A's data is private.</li>
    <li>Put <code>\${NAME}</code> where a password or key goes and enter its value in <b>Secrets</b>. It is stored encrypted.</li>
    <li>On the APIs tab, untick anything with side effects (email, SMS, password reset, bulk import).</li>
  </ul>
  <div class="warn">Use <b>staging</b> only. The tests send junk data and attacks, including POST, PUT and DELETE.</div>

  <h4><span class="step-n">3</span> What each stage tests</h4>
  <p>The stages run in this order. Click one for the details.</p>
  <div class="pipe">
    <details class="stage"><summary><span class="num">1</span><b>lint</b><em>Is the Swagger well written?</em><span class="tag quiet">no requests</span></summary>
      <ul><li>Valid OpenAPI, no broken references or duplicate operationIds</li>
        <li>Descriptions, tags, success responses, declared path parameters</li>
        <li>Examples match their schemas</li></ul></details>
    <details class="stage"><summary><span class="num">2</span><b>conformance</b><em>Does the API behave as the Swagger says?</em><span class="tag">many requests</span></summary>
      <div class="flow small">
        <div class="node">Swagger examples</div><i>→</i><div class="node">Edge cases</div><i>→</i>
        <div class="node">Random data</div><i>→</i><div class="node">Request chains</div></div>
      <ul><li>No 5xx errors; only documented status codes</li>
        <li>Response body matches the schema</li>
        <li>Bad input is rejected, good input is accepted</li>
        <li>Wrong method gets 405; deleted items stay deleted</li></ul></details>
    <details class="stage"><summary><span class="num">3</span><b>types</b><em>Are wrong data types rejected?</em><span class="tag">POST / PUT / PATCH</span></summary>
      <ul><li>Sends a valid request, then changes one field at a time</li>
        <li>For example <code>"1"</code> for a number, <code>"true"</code> for a boolean, <code>null</code>, arrays</li>
        <li>4xx passes, 2xx fails, 5xx is a crash</li></ul></details>
    <details class="stage"><summary><span class="num">4</span><b>authz</b><em>Who can get in, and to whose data?</em><span class="tag">needs users</span></summary>
      <div class="flow small">
        <div class="node">No token → must be refused</div><i>→</i><div class="node">Fake token → must be refused</div><i>→</i>
        <div class="node">User B reads A's data → must be refused</div></div>
      <ul><li>Checks every response for leaked stack traces, SQL errors and unsafe headers</li></ul></details>
    <details class="stage"><summary><span class="num">5</span><b>zap</b><em>Common web vulnerabilities</em><span class="tag">needs Docker</span></summary>
      <ul><li>OWASP ZAP scan: SQL injection, XSS, path traversal, command injection, missing security headers</li>
        <li>The most aggressive stage</li></ul></details>
  </div>
  <p class="hint">Not checked: business rules, whether values are correct (only shape and type), and load performance.</p>

  <h4><span class="step-n">4</span> Run and read the report</h4>
  <div class="flow">
    <div class="node"><b>Run</b><small>Watch requests live; Stop any time</small></div><i>→</i>
    <div class="node"><b>Findings</b><small>critical → high → medium → low → info</small></div><i>→</i>
    <div class="node"><b>Fix</b><small>Change the API or the Swagger</small></div><i>→</i>
    <div class="node"><b>Refresh and re-run</b><small>Reload the Swagger first</small></div>
  </div>
  <ul class="tight">
    <li>The run fails if any finding reaches the project's fail threshold.</li>
    <li>Download the HTML report or request log from the run page. <b>CLI config</b> gives a YAML file for CI.</li>
    <li>"Not really tested" means the server answered 401/403, so the check never got through.</li>
  </ul>
  <p class="hint">What each finding usually means and how to fix it is in section 6 of the Swagger guide.
    <a href="/guides/STAGES.md" download>Download the full stage reference</a>.</p>
</div>`;

async function showGuide() {
  const d = document.getElementById("dialog");
  d.classList.add("guide");
  d.addEventListener("close", () => d.classList.remove("guide"), { once: true });
  const closed = dialog("How to use apitest", GUIDE_HTML, [{ label: "Close", cls: "primary", value: true }]);
  // showModal() focuses the first link (the first download card); start at the top with nothing selected
  document.activeElement?.blur();
  document.getElementById("dialogBody").scrollTop = 0;
  await closed;
}

document.getElementById("helpBtn").addEventListener("click", showGuide);
