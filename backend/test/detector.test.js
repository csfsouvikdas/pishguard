const test = require('node:test');
const assert = require('node:assert');
const { analyze } = require('../../shared/detector');

test('official domain is safe', () => assert.strictEqual(analyze('https://www.google.com/search?q=x').verdict, 'safe'));
test('IP + http login is flagged', () => assert.notStrictEqual(analyze('http://192.168.4.5/login/verify').verdict, 'safe'));
test('brand impersonation is danger', () => assert.strictEqual(analyze('http://paypal.secure-login-update.xyz/signin').verdict, 'danger'));
test('typosquat detected', () => assert.notStrictEqual(analyze('https://paypa1.com/login').verdict, 'safe'));
test('@ trick flagged', () => assert.notStrictEqual(analyze('https://google.com@evil.top/').verdict, 'safe'));
test('blocklist wins', () => assert.strictEqual(analyze('https://bad.com', { blocklist: new Set(['bad.com']) }).verdict, 'danger'));
test('non-http ignored', () => assert.strictEqual(analyze('mailto:a@b.com').verdict, 'ignored'));
