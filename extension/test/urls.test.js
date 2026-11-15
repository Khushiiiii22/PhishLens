import test from "node:test";
import assert from "node:assert/strict";
import {
  isScannable,
  unwrapRedirect,
  sourceFor,
  buildDashboardUrl
} from "../lib/urls.js";

test("isScannable: accepts valid http and https URLs", () => {
  assert.equal(isScannable("http://example.com"), true);
  assert.equal(isScannable("https://example.com/test?a=1&b=2"), true);
  assert.equal(isScannable("https://sub.domain.co.uk:8080/path"), true);
  assert.equal(isScannable("https://www.google.com"), true);
});

test("isScannable: rejects non-http schemes and malformed URLs", () => {
  assert.equal(isScannable("chrome://extensions"), false);
  assert.equal(isScannable("chrome-extension://abcdef"), false);
  assert.equal(isScannable("file:///etc/passwd"), false);
  assert.equal(isScannable("javascript:alert(1)"), false);
  assert.equal(isScannable("about:blank"), false);
  assert.equal(isScannable("data:text/html,<h1>Hello</h1>"), false);
  assert.equal(isScannable("ftp://ftp.example.com"), false);
  assert.equal(isScannable("not-a-url"), false);
  assert.equal(isScannable(""), false);
  assert.equal(isScannable(null), false);
  assert.equal(isScannable(undefined), false);
});

test("isScannable: rejects URLs over 2048 characters", () => {
  const longPath = "a".repeat(2040);
  const tooLongUrl = `https://example.com/${longPath}`;
  assert.ok(tooLongUrl.length > 2048);
  assert.equal(isScannable(tooLongUrl), false);

  const exact2048 = `https://example.com/${"a".repeat(2048 - "https://example.com/".length)}`;
  assert.equal(exact2048.length, 2048);
  assert.equal(isScannable(exact2048), true);
});

test("unwrapRedirect: handles Google url redirect wrappers (q= and url=)", () => {
  const googleQ = "https://www.google.com/url?q=https%3A%2F%2Fdestination.com%2Fpage%3Fid%3D1&source=web";
  assert.equal(unwrapRedirect(googleQ), "https://destination.com/page?id=1");

  const googleUrl = "https://google.com/url?url=https%3A%2F%2Ftarget.org%2Fphish";
  assert.equal(unwrapRedirect(googleUrl), "https://target.org/phish");
});

test("unwrapRedirect: handles Outlook Safe Links wrappers", () => {
  const safeLink = "https://nam12.safelinks.protection.outlook.com/?url=https%3A%2F%2Fsecure-bank.example.com%2Flogin&data=04%7C01";
  assert.equal(unwrapRedirect(safeLink), "https://secure-bank.example.com/login");

  const customSafeLink = "https://emea01.safelinks.protection.outlook.com/?url=https%3A%2F%2Fevil-target.com";
  assert.equal(unwrapRedirect(customSafeLink), "https://evil-target.com");
});

test("unwrapRedirect: handles Facebook redirect wrappers", () => {
  const fb = "https://l.facebook.com/l.php?u=https%3A%2F%2Fnews.example.com%2Farticle%2F123&h=AT12345";
  assert.equal(unwrapRedirect(fb), "https://news.example.com/article/123");

  const fbMobile = "https://lm.facebook.com/l.php?u=https%3A%2F%2Fexternal-site.org";
  assert.equal(unwrapRedirect(fbMobile), "https://external-site.org");
});

test("unwrapRedirect: handles LinkedIn redirect wrappers", () => {
  const li = "https://www.linkedin.com/redir/redirect?url=https%3A%2F%2Fcareers.example.com%2Fjob%2F456&urlhash=abcd";
  assert.equal(unwrapRedirect(li), "https://careers.example.com/job/456");
});

test("unwrapRedirect: handles multi-level nested redirects up to 3 levels", () => {
  // Level 1: Outlook Safe Link wrapping Google redirect
  // Level 2: Google redirect wrapping LinkedIn redirect
  // Level 3: LinkedIn redirect wrapping Final Destination
  const level3Final = "https://real-final-site.com/destination";
  const level2LinkedIn = `https://www.linkedin.com/redir/redirect?url=${encodeURIComponent(level3Final)}`;
  const level1Google = `https://www.google.com/url?q=${encodeURIComponent(level2LinkedIn)}`;
  const level0Outlook = `https://nam12.safelinks.protection.outlook.com/?url=${encodeURIComponent(level1Google)}`;

  assert.equal(unwrapRedirect(level0Outlook), level3Final);
});

test("unwrapRedirect: enforces max 3 levels of unwrapping", () => {
  // 4 levels of wrapping
  const finalSite = "https://end-of-chain.com";
  const l3 = `https://www.linkedin.com/redir/redirect?url=${encodeURIComponent(finalSite)}`;
  const l2 = `https://l.facebook.com/l.php?u=${encodeURIComponent(l3)}`;
  const l1 = `https://www.google.com/url?q=${encodeURIComponent(l2)}`;
  const l0 = `https://nam12.safelinks.protection.outlook.com/?url=${encodeURIComponent(l1)}`;

  // Unwraps:
  // depth 1: l0 -> l1
  // depth 2: l1 -> l2
  // depth 3: l2 -> l3 (stops at 3 levels)
  assert.equal(unwrapRedirect(l0), l3);
});

test("unwrapRedirect: returns original URL if unwrapped target is invalid or non-http", () => {
  const badTarget = "https://www.google.com/url?q=javascript%3Aalert(1)";
  assert.equal(unwrapRedirect(badTarget), badTarget);

  const fileTarget = "https://www.google.com/url?q=file%3A%2F%2F%2Fetc%2Fpasswd";
  assert.equal(unwrapRedirect(fileTarget), fileTarget);
});

test("unwrapRedirect: returns non-redirect URLs unchanged", () => {
  const normalUrl = "https://www.google.com/search?q=phishing+detection";
  assert.equal(unwrapRedirect(normalUrl), normalUrl);

  const directSite = "https://github.com/my-repo";
  assert.equal(unwrapRedirect(directSite), directSite);
});

test("sourceFor: correctly maps email hostnames", () => {
  assert.equal(sourceFor("https://mail.google.com/mail/u/0/#inbox"), "email");
  assert.equal(sourceFor("https://outlook.live.com/mail/0/inbox"), "email");
  assert.equal(sourceFor("https://outlook.office.com/mail/"), "email");
  assert.equal(sourceFor("https://outlook.office365.com/owa/"), "email");
  assert.equal(sourceFor("https://mail.yahoo.com/d/folders/1"), "email");
});

test("sourceFor: correctly maps social_media hostnames", () => {
  assert.equal(sourceFor("https://x.com/home"), "social_media");
  assert.equal(sourceFor("https://twitter.com/notifications"), "social_media");
  assert.equal(sourceFor("https://www.facebook.com/feed"), "social_media");
  assert.equal(sourceFor("https://facebook.com/profile"), "social_media");
  assert.equal(sourceFor("https://instagram.com/direct/inbox"), "social_media");
  assert.equal(sourceFor("https://www.instagram.com/"), "social_media");
  assert.equal(sourceFor("https://linkedin.com/feed/"), "social_media");
  assert.equal(sourceFor("https://www.linkedin.com/in/user"), "social_media");
  assert.equal(sourceFor("https://reddit.com/r/security"), "social_media");
  assert.equal(sourceFor("https://www.reddit.com/"), "social_media");
});

test("sourceFor: correctly maps message hostnames", () => {
  assert.equal(sourceFor("https://web.whatsapp.com/"), "message");
  assert.equal(sourceFor("https://web.telegram.org/a/"), "message");
  assert.equal(sourceFor("https://messages.google.com/web/conversations"), "message");
});

test("sourceFor: returns null for other or invalid hosts", () => {
  assert.equal(sourceFor("https://www.google.com/"), null);
  assert.equal(sourceFor("https://github.com/"), null);
  assert.equal(sourceFor("http://localhost:5173/"), null);
  assert.equal(sourceFor("chrome://extensions"), null);
  assert.equal(sourceFor(""), null);
  assert.equal(sourceFor(null), null);
});

test("buildDashboardUrl: encodes URL and appends source & autoscan when source is present", () => {
  const result = buildDashboardUrl(
    "https://phishlens-doyc.onrender.com",
    "https://example.com/login?redirect=1&ref=email",
    "email"
  );

  assert.equal(
    result,
    "https://phishlens-doyc.onrender.com/?url=https%3A%2F%2Fexample.com%2Flogin%3Fredirect%3D1%26ref%3Demail&source=email&autoscan=true"
  );
});

test("buildDashboardUrl: excludes source & autoscan when source is null", () => {
  const result = buildDashboardUrl(
    "https://phishlens-doyc.onrender.com",
    "https://example.com/plain",
    null
  );

  assert.equal(
    result,
    "https://phishlens-doyc.onrender.com/?url=https%3A%2F%2Fexample.com%2Fplain"
  );
});

test("buildDashboardUrl: normalizes trailing slashes on base URL and trims whitespace", () => {
  const result = buildDashboardUrl(
    "http://localhost:5173///",
    "https://example.com",
    "social_media"
  );

  assert.equal(
    result,
    "http://localhost:5173/?url=https%3A%2F%2Fexample.com&source=social_media&autoscan=true"
  );
});
