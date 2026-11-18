// SPDX-License-Identifier: MIT
// Tests of the browser-side SHA-512 crypt (luci-app's haproxy_advanced/crypt.js)
// against the test vectors of Ulrich Drepper's specification and Node's SHA-512.
'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const file = path.join(__dirname, '../../luci-app-haproxy-advanced/htdocs/luci-static/resources/haproxy_advanced/crypt.js');
const src = fs.readFileSync(file, 'utf8').replace(/^'require [^']+';$/mg, '');
global.window = { crypto: { getRandomValues: (a) => crypto.randomFillSync(a) } };
const mod = new Function('baseclass', src)({ extend: (o) => o });

// SHA-512 against Node for lengths around the block boundaries.
for (const n of [ 0, 1, 3, 55, 56, 111, 112, 113, 127, 128, 129, 255, 1000 ]) {
	const buf = crypto.randomBytes(n);
	const want = crypto.createHash('sha512').update(buf).digest('hex');
	const got = Buffer.from(mod.sha512(new Uint8Array(buf))).toString('hex');

	assert.equal(got, want, `sha512 of ${n} bytes`);
}

// Vectors from https://www.akkadia.org/drepper/SHA-crypt.txt
const vectors = [
	[ 'Hello world!', 'saltstring', null,
	  '$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1' ],
	[ 'Hello world!', 'saltstringsaltstring', 10000,
	  '$6$rounds=10000$saltstringsaltst$OW1/O6BYHV6BcXZu8QVeXbDWra3Oeqh0sbHbbMCVNSnCM/UrjmM0Dp8vOuZeHBy/YTBmSK6H9qs/y3RnOaw5v.' ],
	[ 'This is just a test', 'toolongsaltstring', 5000,
	  '$6$rounds=5000$toolongsaltstrin$lQ8jolhgVRVhY4b5pZKaysCLi0QBxGoNeKQzQ3glMhwllF7oGDZxUhx1yxdYcz/e1JSbq3y6JMxxl8audkUEm0' ],
	[ 'a very much longer text to encrypt.  This one even stretches over morethan one line.', 'anotherlongsaltstring', 1400,
	  '$6$rounds=1400$anotherlongsalts$POfYwTEok97VWcjxIiSOjiykti.o/pQs.wPvMxQ6Fm7I6IoYN3CmLs66x9t0oSwbtEW7o7UmJEiDwGqd8p4ur1' ],
	[ 'we have a short salt string but not a short password', 'short', 77777,
	  '$6$rounds=77777$short$WuQyW2YR.hBNpjjRhpYD/ifIw05xdfeEyQoMxIXbkvr0gge1a1x3yRULJ5CCaUeOxFmtlcGZelFl5CxtgfiAc0' ],
	[ 'a short string', 'asaltof16chars..', 123456,
	  '$6$rounds=123456$asaltof16chars..$BtCwjqMJGx5hrJhZywWvt0RLE8uZ4oPwcelCjmw2kSYu.Ec6ycULevoBK25fs2xXgMNrCzIMVcgEJAstJeonj1' ],
	[ 'the minimum number is still observed', 'roundstoolow', 10,
	  '$6$rounds=1000$roundstoolow$kUMsbe306n21p9R.FRkW3IGn.S9NPN0x50YhH1xhLsPuWGsUSklZt58jaTfF4ZEQpyUNGc0dqbpBYYBaHHrsX.' ]
];

for (const [ pw, salt, rounds, want ] of vectors)
	assert.equal(mod.sha512crypt(pw, salt, rounds), want, `crypt vector ${want.substring(0, 24)}`);

// Random salts are 16 characters of the crypt alphabet.
const h = mod.hash('secret');
assert.match(h, /^\$6\$[./0-9A-Za-z]{16}\$[./0-9A-Za-z]{86}$/);
assert.notEqual(mod.hash('secret'), h);

console.log('crypt.js: all tests passed');
