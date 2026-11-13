'use strict';
'require baseclass';

// SHA-512 crypt ($6$, Ulrich Drepper's specification) in plain JavaScript.
// The hash is made in the browser so the password never reaches the router
// (decision D6 of goal A). WebCrypto is not used: LuCI is often served over
// plain HTTP, where browsers do not offer it.

const K = [
	0x428a2f98, 0xd728ae22, 0x71374491, 0x23ef65cd, 0xb5c0fbcf, 0xec4d3b2f, 0xe9b5dba5, 0x8189dbbc,
	0x3956c25b, 0xf348b538, 0x59f111f1, 0xb605d019, 0x923f82a4, 0xaf194f9b, 0xab1c5ed5, 0xda6d8118,
	0xd807aa98, 0xa3030242, 0x12835b01, 0x45706fbe, 0x243185be, 0x4ee4b28c, 0x550c7dc3, 0xd5ffb4e2,
	0x72be5d74, 0xf27b896f, 0x80deb1fe, 0x3b1696b1, 0x9bdc06a7, 0x25c71235, 0xc19bf174, 0xcf692694,
	0xe49b69c1, 0x9ef14ad2, 0xefbe4786, 0x384f25e3, 0x0fc19dc6, 0x8b8cd5b5, 0x240ca1cc, 0x77ac9c65,
	0x2de92c6f, 0x592b0275, 0x4a7484aa, 0x6ea6e483, 0x5cb0a9dc, 0xbd41fbd4, 0x76f988da, 0x831153b5,
	0x983e5152, 0xee66dfab, 0xa831c66d, 0x2db43210, 0xb00327c8, 0x98fb213f, 0xbf597fc7, 0xbeef0ee4,
	0xc6e00bf3, 0x3da88fc2, 0xd5a79147, 0x930aa725, 0x06ca6351, 0xe003826f, 0x14292967, 0x0a0e6e70,
	0x27b70a85, 0x46d22ffc, 0x2e1b2138, 0x5c26c926, 0x4d2c6dfc, 0x5ac42aed, 0x53380d13, 0x9d95b3df,
	0x650a7354, 0x8baf63de, 0x766a0abb, 0x3c77b2a8, 0x81c2c92e, 0x47edaee6, 0x92722c85, 0x1482353b,
	0xa2bfe8a1, 0x4cf10364, 0xa81a664b, 0xbc423001, 0xc24b8b70, 0xd0f89791, 0xc76c51a3, 0x0654be30,
	0xd192e819, 0xd6ef5218, 0xd6990624, 0x5565a910, 0xf40e3585, 0x5771202a, 0x106aa070, 0x32bbd1b8,
	0x19a4c116, 0xb8d2d0c8, 0x1e376c08, 0x5141ab53, 0x2748774c, 0xdf8eeb99, 0x34b0bcb5, 0xe19b48a8,
	0x391c0cb3, 0xc5c95a63, 0x4ed8aa4a, 0xe3418acb, 0x5b9cca4f, 0x7763e373, 0x682e6ff3, 0xd6b2b8a3,
	0x748f82ee, 0x5defb2fc, 0x78a5636f, 0x43172f60, 0x84c87814, 0xa1f0ab72, 0x8cc70208, 0x1a6439ec,
	0x90befffa, 0x23631e28, 0xa4506ceb, 0xde82bde9, 0xbef9a3f7, 0xb2c67915, 0xc67178f2, 0xe372532b,
	0xca273ece, 0xea26619c, 0xd186b8c7, 0x21c0c207, 0xeada7dd6, 0xcde0eb1e, 0xf57d4f7f, 0xee6ed178,
	0x06f067aa, 0x72176fba, 0x0a637dc5, 0xa2c898a6, 0x113f9804, 0xbef90dae, 0x1b710b35, 0x131c471b,
	0x28db77f5, 0x23047d84, 0x32caab7b, 0x40c72493, 0x3c9ebe0a, 0x15c9bebc, 0x431d67c4, 0x9c100d4c,
	0x4cc5d4be, 0xcb3e42b6, 0x597f299c, 0xfc657e2a, 0x5fcb6fab, 0x3ad6faec, 0x6c44198c, 0x4a475817
];

const H0 = [
	0x6a09e667, 0xf3bcc908, 0xbb67ae85, 0x84caa73b, 0x3c6ef372, 0xfe94f82b, 0xa54ff53a, 0x5f1d36f1,
	0x510e527f, 0xade682d1, 0x9b05688c, 0x2b3e6c1f, 0x1f83d9ab, 0xfb41bd6b, 0x5be0cd19, 0x137e2179
];

// SHA-512 of a byte array; returns 64 bytes. 64-bit words are pairs of 32-bit
// halves (hi, lo) because JavaScript numbers cannot hold them.
function sha512(bytes) {
	const len = bytes.length;
	const padded = new Uint8Array(((len + 17 + 127) >> 7) << 7);
	const w = new Int32Array(160);
	const h = Int32Array.from(H0);

	padded.set(bytes);
	padded[len] = 0x80;

	const bits = len * 8;
	const end = padded.length;

	padded[end - 1] = bits & 0xff;
	padded[end - 2] = (bits >>> 8) & 0xff;
	padded[end - 3] = (bits >>> 16) & 0xff;
	padded[end - 4] = (bits >>> 24) & 0xff;
	padded[end - 5] = Math.floor(bits / 0x100000000) & 0xff;

	for (let off = 0; off < end; off += 128) {
		for (let i = 0; i < 32; i++) {
			const p = off + i * 4;

			w[i] = (padded[p] << 24) | (padded[p + 1] << 16) | (padded[p + 2] << 8) | padded[p + 3];
		}

		for (let i = 16; i < 80; i++) {
			// sigma0 of w[i-15], sigma1 of w[i-2]
			let xh = w[(i - 15) * 2], xl = w[(i - 15) * 2 + 1];
			const s0h = ((xh >>> 1) | (xl << 31)) ^ ((xh >>> 8) | (xl << 24)) ^ (xh >>> 7);
			const s0l = ((xl >>> 1) | (xh << 31)) ^ ((xl >>> 8) | (xh << 24)) ^ ((xl >>> 7) | (xh << 25));

			xh = w[(i - 2) * 2]; xl = w[(i - 2) * 2 + 1];
			const s1h = ((xh >>> 19) | (xl << 13)) ^ ((xl >>> 29) | (xh << 3)) ^ (xh >>> 6);
			const s1l = ((xl >>> 19) | (xh << 13)) ^ ((xh >>> 29) | (xl << 3)) ^ ((xl >>> 6) | (xh << 26));

			let lo = (s0l >>> 0) + (s1l >>> 0) + (w[(i - 7) * 2 + 1] >>> 0) + (w[(i - 16) * 2 + 1] >>> 0);
			let hi = s0h + s1h + w[(i - 7) * 2] + w[(i - 16) * 2] + Math.floor(lo / 0x100000000);

			w[i * 2] = hi | 0;
			w[i * 2 + 1] = lo | 0;
		}

		let ah = h[0], al = h[1], bh = h[2], bl = h[3], ch = h[4], cl = h[5], dh = h[6], dl = h[7];
		let eh = h[8], el = h[9], fh = h[10], fl = h[11], gh = h[12], gl = h[13], hh = h[14], hl = h[15];

		for (let i = 0; i < 80; i++) {
			const S1h = ((eh >>> 14) | (el << 18)) ^ ((eh >>> 18) | (el << 14)) ^ ((el >>> 9) | (eh << 23));
			const S1l = ((el >>> 14) | (eh << 18)) ^ ((el >>> 18) | (eh << 14)) ^ ((eh >>> 9) | (el << 23));
			const chh = (eh & fh) ^ (~eh & gh);
			const chl = (el & fl) ^ (~el & gl);

			let lo = (hl >>> 0) + (S1l >>> 0) + (chl >>> 0) + (K[i * 2 + 1] >>> 0) + (w[i * 2 + 1] >>> 0);
			let hi = hh + S1h + chh + K[i * 2] + w[i * 2] + Math.floor(lo / 0x100000000);
			const t1h = hi | 0, t1l = lo | 0;

			const S0h = ((ah >>> 28) | (al << 4)) ^ ((al >>> 2) | (ah << 30)) ^ ((al >>> 7) | (ah << 25));
			const S0l = ((al >>> 28) | (ah << 4)) ^ ((ah >>> 2) | (al << 30)) ^ ((ah >>> 7) | (al << 25));
			const mah = (ah & bh) ^ (ah & ch) ^ (bh & ch);
			const mal = (al & bl) ^ (al & cl) ^ (bl & cl);

			lo = (S0l >>> 0) + (mal >>> 0);
			hi = S0h + mah + Math.floor(lo / 0x100000000);
			const t2h = hi | 0, t2l = lo | 0;

			hh = gh; hl = gl; gh = fh; gl = fl; fh = eh; fl = el;
			lo = (dl >>> 0) + (t1l >>> 0);
			eh = (dh + t1h + Math.floor(lo / 0x100000000)) | 0; el = lo | 0;
			dh = ch; dl = cl; ch = bh; cl = bl; bh = ah; bl = al;
			lo = (t1l >>> 0) + (t2l >>> 0);
			ah = (t1h + t2h + Math.floor(lo / 0x100000000)) | 0; al = lo | 0;
		}

		const add = (i, xh, xl) => {
			const lo = (h[i + 1] >>> 0) + (xl >>> 0);

			h[i] = (h[i] + xh + Math.floor(lo / 0x100000000)) | 0;
			h[i + 1] = lo | 0;
		};

		add(0, ah, al); add(2, bh, bl); add(4, ch, cl); add(6, dh, dl);
		add(8, eh, el); add(10, fh, fl); add(12, gh, gl); add(14, hh, hl);
	}

	const out = new Uint8Array(64);

	for (let i = 0; i < 16; i++) {
		out[i * 4] = (h[i] >>> 24) & 0xff;
		out[i * 4 + 1] = (h[i] >>> 16) & 0xff;
		out[i * 4 + 2] = (h[i] >>> 8) & 0xff;
		out[i * 4 + 3] = h[i] & 0xff;
	}

	return out;
}

function utf8(s) {
	return new TextEncoder().encode(s);
}

function concat(parts) {
	let n = 0;

	for (const p of parts)
		n += p.length;

	const out = new Uint8Array(n);
	let o = 0;

	for (const p of parts) {
		out.set(p, o);
		o += p.length;
	}

	return out;
}

// n bytes taken from digest d, repeated.
function repeat(d, n) {
	const out = new Uint8Array(n);

	for (let i = 0; i < n; i++)
		out[i] = d[i % 64];

	return out;
}

const B64 = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';

function b64_from(b2, b1, b0, n) {
	let w = (b2 << 16) | (b1 << 8) | b0, s = '';

	while (n-- > 0) {
		s += B64[w & 0x3f];
		w >>>= 6;
	}

	return s;
}

const ORDER = [
	[ 0, 21, 42 ], [ 22, 43, 1 ], [ 44, 2, 23 ], [ 3, 24, 45 ], [ 25, 46, 4 ], [ 47, 5, 26 ],
	[ 6, 27, 48 ], [ 28, 49, 7 ], [ 50, 8, 29 ], [ 9, 30, 51 ], [ 31, 52, 10 ], [ 53, 11, 32 ],
	[ 12, 33, 54 ], [ 34, 55, 13 ], [ 56, 14, 35 ], [ 15, 36, 57 ], [ 37, 58, 16 ], [ 59, 17, 38 ],
	[ 18, 39, 60 ], [ 40, 61, 19 ], [ 62, 20, 41 ]
];

function sha512crypt(password, salt, rounds) {
	const custom = rounds != null;

	rounds = custom ? Math.min(Math.max(rounds, 1000), 999999999) : 5000;
	salt = salt.substring(0, 16);

	const P = utf8(password), S = utf8(salt);
	const B = sha512(concat([ P, S, P ]));
	const aparts = [ P, S, repeat(B, P.length) ];

	for (let n = P.length; n > 0; n >>= 1)
		aparts.push((n & 1) ? B : P);

	let A = sha512(concat(aparts));

	const dpParts = [];

	for (let i = 0; i < P.length; i++)
		dpParts.push(P);

	const PS = repeat(sha512(concat(dpParts)), P.length);
	const dsParts = [];

	for (let i = 0; i < 16 + A[0]; i++)
		dsParts.push(S);

	const SS = repeat(sha512(concat(dsParts)), S.length);
	let C = A;

	for (let r = 0; r < rounds; r++) {
		const parts = [];

		parts.push((r & 1) ? PS : C);

		if (r % 3)
			parts.push(SS);

		if (r % 7)
			parts.push(PS);

		parts.push((r & 1) ? C : PS);
		C = sha512(concat(parts));
	}

	let out = '';

	for (const [ a, b, c ] of ORDER)
		out += b64_from(C[a], C[b], C[c], 4);

	out += b64_from(0, 0, C[63], 2);

	return '$6$' + (custom ? 'rounds=' + rounds + '$' : '') + salt + '$' + out;
}

function random_salt(n) {
	const bytes = new Uint8Array(n);
	let s = '';

	window.crypto.getRandomValues(bytes);

	for (let i = 0; i < n; i++)
		s += B64[bytes[i] & 0x3f];

	return s;
}

return baseclass.extend({
	sha512: sha512,
	sha512crypt: sha512crypt,

	// A new $6$ hash with a random 16-character salt.
	hash: function(password, rounds) {
		return sha512crypt(password, random_salt(16), rounds);
	}
});
