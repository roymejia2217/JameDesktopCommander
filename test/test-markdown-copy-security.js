import assert from 'node:assert/strict';
import { test } from 'node:test';
import { getRenderedMarkdownCopyText } from '../dist/ui/file-preview/src/markdown/preview.js';

const cases = [
  {
    name: 'preserves nested HTML entities without double decoding',
    input: 'A &amp;lt;script&amp;gt; &lt;script&gt; &amp;amp;',
    expected: 'A &lt;script&gt; <script> &amp;',
  },
  {
    name: 'copies literal malicious-looking HTML strictly as text',
    input: '<script>alert(1)</script>\n\n<img src=x onerror=alert(1)>',
    expected: '<script>alert(1)</script>\n\n<img src=x onerror=alert(1)>',
  },
  {
    name: 'preserves headings, emphasis, links and compact bullets',
    input: '# Title\n\n- **Bold** &amp;lt;tag&amp;gt;\n- [Link](https://example.test/)',
    expected: 'Title\n\n- Bold &lt;tag&gt;\n- Link',
  },
  {
    name: 'preserves ordered list numbering',
    input: '3. Three\n4. Four',
    expected: '3. Three\n4. Four',
  },
  {
    name: 'preserves nested bullets',
    input: '- parent\n  - nested\n- tail',
    expected: '- parent\n  - nested\n- tail',
  },
  {
    name: 'preserves hard and soft line breaks without HTML',
    input: 'First  \nSecond\nThird',
    expected: 'First\nSecond\nThird',
  },
  {
    name: 'preserves fenced code as literal copied text',
    input: '~~~html\n<script>alert(1)</script>\n~~~',
    expected: '<script>alert(1)</script>',
  },
  {
    name: 'preserves inline code, wiki display labels and Unicode',
    input: 'Use `<img>` with [[Meeting Notes|Notas]] — café',
    expected: 'Use <img> with Notas — café',
  },
  {
    name: 'preserves image alternative text, not the URL',
    input: 'Photo: ![A <cat>](https://example.test/unsafe.png)',
    expected: 'Photo: A <cat>',
  },
  {
    name: 'does not expand nested entities, comments or attributes',
    input: 'A &amp;amp; B &lt;img onerror=alert(1)&gt; <!-- text -->',
    expected: 'A &amp; B <img onerror=alert(1)> <!-- text -->',
  },
  {
    name: 'does not add empty output',
    input: '  ',
    expected: '',
  },
];
for (const { name, input, expected } of cases) {
  test(name, () => {
    assert.equal(getRenderedMarkdownCopyText(input), expected);
  });
}
