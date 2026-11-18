// SPDX-License-Identifier: MIT
// Run the generator on the host: ucode tools/gen_host.uc CONFIG ENV.json
// Prints the result as JSON (config and report).
'use strict';

import * as fs from 'fs';
import { parse } from '../tests/lib/uci.uc';
import { generate } from '../haproxy-advanced/files/ucode/core.uc';

let res = generate(parse(fs.readfile(ARGV[0])), json(fs.readfile(ARGV[1])));

print(sprintf('%J\n', res));
