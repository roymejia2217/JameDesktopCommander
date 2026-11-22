import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { runFuzzySearch } from '../dist/tools/fuzzySearchCore.js';

test('fuzzy match finds the exact near-typo line in the real 500-line integration fixture', () => {
  const salt = 'python-fuzzy-25';
  const exact = 'unique_report_anchor_python_fuzzy_25 = "original: Desktop Commander MCP handles files, commands, and edit blocks"';
  const query = exact.replace('Commander', 'Comander');
  const README_LINES = readFileSync('README.md', 'utf8').split(/\r?\n/)
    .map(line => line.trim()).filter(line => line.length > 0 && !line.startsWith('!['));
  const saltValue = Array.from(salt).reduce((sum, char) => sum + char.charCodeAt(0), 0);
  const getLine = index => README_LINES[
    (index * 37 + saltValue * 13 + Math.floor(index / 11) * 17) % README_LINES.length
  ];
  const sanitize = value => value.replace(/\\/g, '\\\\').replace(/"/g, '\\"')
    .replace(/[\u0000-\u001f\u007f]/g, ' ').slice(0, 180);
  const lines = ['# Generated Python fuzzy fixture using varied README-derived text',
    exact, '', 'README_NOTES = ['];
  for (let index = 1; index <= 500; index++) {
    lines.push('    "' + sanitize(getLine(index * 11)) + '",');
  }
  lines.push(']', '', 'def collect_notes():', '    return "\\n".join(README_NOTES)');
  const { result } = runFuzzySearch(lines.join('\n'), query);
  assert.equal(result.value, exact, 'Recursive half-selection discarded a near-exact match');
  assert.equal(result.distance, 1);
});

test('near-exact line matching handles CRLF without including carriage returns', () => {
  const exact = 'report_entry = "original: Desktop Commander MCP handles files, commands and edit blocks"';
  const query = exact.replace('Commander', 'Comander');
  const text = ['header', exact, 'unrelated conclusion'].join('\r\n');
  const { result } = runFuzzySearch(text, query);
  assert.equal(result.value, exact);
  assert.equal(result.start, text.indexOf(exact));
  assert.equal(result.end, result.start + exact.length);
  assert.equal(result.distance, 1);
});

test('whole-line preflight selects the closest candidate, not the first similarity', () => {
  const expected = 'report_entry = "Desktop Commander handles important file operations with care"';
  const query = expected.replace('Commander', 'Comander');
  const weaker = expected.replace('Commander', 'Comander').replace('important', 'difficult');
  const text = ['preface', weaker, 'unrelated filler', expected, 'end'].join('\n');
  const { result } = runFuzzySearch(text, query);
  assert.equal(result.value, expected);
  assert.equal(result.distance, 1);
});
