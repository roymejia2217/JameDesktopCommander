import { appendFileSync } from 'node:fs';
import { exit } from 'node:process';

/** Native Task Scheduler isolated-process test fixture; never opens a network port. */
const [, , receiptPath] = process.argv;
if (!receiptPath || process.argv.length !== 3) {
  exit(64);
}
try {
  appendFileSync(receiptPath, 'exit-zero\n', { encoding: 'utf8', flag: 'a' });
  exit(0);
} catch {
  exit(70);
}
