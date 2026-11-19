/**
 * Live smoke tests (blueprint section 6).
 * Soft-skip on network failure: these assert the pre-creation state
 * (npm + GitHub names still free, advisories live), never hard-fail CI.
 */
import test from "node:test";
import assert from "node:assert/strict";

async function getStatus(url, timeoutMs = 10000) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      method: "GET",
      signal: ctrl.signal,
      redirect: "follow",
    });
    return res.status;
  } finally {
    clearTimeout(t);
  }
}

test("live: npm package name `nginx2shell` is still unclaimed (404)", async (t) => {
  let status;
  try {
    status = await getStatus("https://registry.npmjs.org/nginx2shell");
  } catch {
    t.skip("network unavailable - cannot verify npm name");
    return;
  }
  assert.equal(status, 404, `expected npm 404 for nginx2shell, got ${status}`);
});

test("live: npm search for nginx2shell returns 0 packages", async (t) => {
  let body;
  try {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 10000);
    try {
      const res = await fetch(
        "https://registry.npmjs.org/-/v1/search?text=nginx2shell&size=5",
        { signal: ctrl.signal },
      );
      body = await res.json();
    } finally {
      clearTimeout(timer);
    }
  } catch {
    t.skip("network unavailable - cannot verify npm search");
    return;
  }
  assert.equal(
    body.total,
    0,
    `expected 0 npm search results, got ${body.total}`,
  );
});

test("live: GitHub repo techdevfun/nginx2shell does not exist yet (404)", async (t) => {
  let status;
  try {
    status = await getStatus(
      "https://api.github.com/repos/techdevfun/nginx2shell",
    );
  } catch {
    t.skip("network unavailable - cannot verify GitHub name");
    return;
  }
  // Unauthenticated API may rate-limit (403); that is not a 404 and
  // must not fail the test - it only means the check could not run.
  if (status === 403) {
    t.skip("GitHub API rate-limited (403) - cannot verify repo name");
    return;
  }
  assert.equal(
    status,
    404,
    `expected GitHub 404 for techdevfun/nginx2shell, got ${status}`,
  );
});

test("live: Wiz NGINX2Shell write-up is reachable (200)", async (t) => {
  let status;
  try {
    status = await getStatus("https://nginx2shell.com/");
  } catch {
    t.skip("network unavailable - cannot verify Wiz site");
    return;
  }
  assert.equal(status, 200, `expected Wiz site 200, got ${status}`);
});

test("live: NGINX security advisories page is reachable (200)", async (t) => {
  let status;
  try {
    status = await getStatus("https://nginx.org/en/security_advisories.html");
  } catch {
    t.skip("network unavailable - cannot verify nginx.org advisories");
    return;
  }
  assert.equal(status, 200, `expected nginx.org advisories 200, got ${status}`);
});
