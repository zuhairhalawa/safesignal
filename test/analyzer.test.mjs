// Run: node --test   (from the safespace/ folder)
// Verifies the heuristic analyzer on SYNTHETIC, author-created messages only.
// No real personal data, no real victims — exactly as the hackathon rules require.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { analyzeMessage, _internals } from '../analyzer.js';

const hasSignal = (r, id) => r.signals.some((s) => s.id === id);

// ---------- SCAM samples (synthetic) : should surface strong signals ----------

test('PayPal-style phish: urgency + credential request + disguised link => high', () => {
  const msg = `Dear Customer,
Your PayPal account has been suspended due to unusual sign-in activity.
Verify your account within 24 hours to avoid suspension:
http://paypa1-secure.top/login`;
  const r = analyzeMessage(msg);
  assert.equal(r.band, 'high');
  assert.ok(hasSignal(r, 'urgency'));
  assert.ok(hasSignal(r, 'credential-request'));
  assert.ok(hasSignal(r, 'risky-links'));
});

test('Gift-card boss scam: urgency + payment lure => high', () => {
  const msg = `I'm in a meeting right now and need a quick favour. Please buy 5 Google Play gift cards and send me the codes right away. Urgent.`;
  const r = analyzeMessage(msg);
  assert.equal(r.band, 'high');
  assert.ok(hasSignal(r, 'payment-lure'));
  assert.ok(hasSignal(r, 'urgency'));
});

test('Parcel/customs scam with shortener => caution or high, flags link + bait', () => {
  const msg = `Dear user, your parcel is held at customs. Pay the customs fee to release your delivery: https://bit.ly/3xmpl`;
  const r = analyzeMessage(msg);
  assert.ok(r.band === 'caution' || r.band === 'high');
  assert.ok(hasSignal(r, 'risky-links'));
  assert.ok(hasSignal(r, 'too-good-or-bait'));
});

test('Malware attachment lure: risky attachment + enable macros => high', () => {
  const msg = `Please open the attached invoice.docm and enable macros to view your receipt.`;
  const r = analyzeMessage(msg);
  assert.equal(r.band, 'high');
  assert.ok(hasSignal(r, 'attachment-risk'));
});

test('Header spoofing: Reply-To mismatch + auth fail raises signals', () => {
  const msg = `Hello, please review the document.`;
  const headers = `From: Billing <billing@microsoft.com>
Reply-To: refunds@secure-mail-xyz.top
Authentication-Results: spf=fail dkim=fail dmarc=fail`;
  const r = analyzeMessage(msg, { headers });
  assert.ok(hasSignal(r, 'replyto-mismatch'));
  assert.ok(hasSignal(r, 'auth-fail'));
  assert.equal(r.band, 'high');
});

// ---------- LEGIT samples (synthetic) : should stay low ----------

test('Order confirmation (no links, no asks) => low', () => {
  const msg = `Hi Zuhair, thanks for your order #12831. It shipped today and should arrive Thursday. You can track it in the app.`;
  const r = analyzeMessage(msg);
  assert.equal(r.band, 'low');
  assert.equal(r.signals.length, 0);
});

test('Appointment reminder with benign reply => low', () => {
  const msg = `Reminder: your dentist appointment is tomorrow at 3pm. Reply C to confirm, or call the clinic to reschedule.`;
  const r = analyzeMessage(msg);
  assert.equal(r.band, 'low');
});

test('Real brand domain link, no asks => low and not flagged as disguised', () => {
  const msg = `Your monthly statement is ready. Log in at https://www.hsbc.ae to view it.`;
  const r = analyzeMessage(msg);
  assert.equal(r.band, 'low');
  assert.equal(hasSignal(r, 'risky-links'), false);
});

// ---------- Unit tests for URL/brand internals ----------

test('extractUrls finds http, www and bare hosts; ignores trailing punctuation', () => {
  const urls = _internals.extractUrls('see http://a.top/login, www.b.com and plain c.co.uk.');
  assert.ok(urls.includes('http://a.top/login'));
  assert.ok(urls.includes('www.b.com'));
  assert.ok(urls.includes('c.co.uk'));
});

test('looksLikeBrand catches digit-substituted and embedded brand look-alikes', () => {
  assert.equal(_internals.looksLikeBrand('paypa1-secure.top'), 'paypal');
  assert.equal(_internals.looksLikeBrand('secure-amazon.verify.link'), 'amazon');
});

test('looksLikeBrand does not false-positive on ordinary words or the real brand', () => {
  assert.equal(_internals.looksLikeBrand('products.example.com'), null); // "du" must not match inside "products"
  assert.equal(_internals.looksLikeBrand('www.paypal.com'), null);       // exact real brand label
});

test('scores are bounded 0..100', () => {
  const spam = `URGENT act now! verify your account and confirm your password, pay with bitcoin gift cards, you have won, open invoice.exe enable macros http://paypa1.top@1.2.3.4/x`;
  const r = analyzeMessage(spam);
  assert.ok(r.score >= 0 && r.score <= 100);
  assert.equal(r.band, 'high');
});
