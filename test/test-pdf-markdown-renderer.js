#!/usr/bin/env node

import assert from 'node:assert/strict';

import { renderMarkdownDocument } from '../dist/tools/pdf/markdown.js';

const html = renderMarkdownDocument(
    '# Hello\n\n<script>alert("x")</script>\n\n**bold**',
    {
        document_title: 'A < B',
        body_class: ['safe-class', 'bad"quote'],
        css: 'body { letter-spacing: 0; }',
    },
);

assert.match(html, /<h1>Hello<\/h1>/);
assert.match(html, /<strong>bold<\/strong>/);
assert.equal(html.includes('<script>'), false, 'raw HTML must remain disabled');
assert.match(html, /&lt;script&gt;alert\(&quot;x&quot;\)&lt;\/script&gt;/);
assert.match(html, /<title>A &lt; B<\/title>/);
assert.match(html, /<body class="safe-class">/);
assert.equal(html.includes('bad"quote'), false, 'unsafe body class must be removed');
assert.match(html, /letter-spacing: 0/);

console.log('Markdown PDF renderer test passed');
