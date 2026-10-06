import assert from 'node:assert/strict';
import { zodToJsonSchema } from 'zod-to-json-schema';
import {
  EditBlockArgsSchema,
  ReadFileArgsSchema,
  RenderWorkspaceArgsSchema,
} from '../dist/tools/schemas.js';

function findEmptySchemaNodes(value, path = '$', matches = []) {
  if (Array.isArray(value)) {
    value.forEach((item, index) => findEmptySchemaNodes(item, `${path}[${index}]`, matches));
    return matches;
  }

  if (!value || typeof value !== 'object') {
    return matches;
  }

  const keys = Object.keys(value);
  if (keys.length === 0) {
    matches.push(path);
    return matches;
  }

  for (const [key, child] of Object.entries(value)) {
    findEmptySchemaNodes(child, `${path}.${key}`, matches);
  }
  return matches;
}

const contracts = {
  read_file: ReadFileArgsSchema,
  render_workspace: RenderWorkspaceArgsSchema,
  edit_block: EditBlockArgsSchema,
};

const emptyNodes = [];
for (const [name, schema] of Object.entries(contracts)) {
  const jsonSchema = zodToJsonSchema(schema);
  for (const path of findEmptySchemaNodes(jsonSchema)) {
    emptyNodes.push(`${name}:${path}`);
  }
}

assert.deepEqual(
  emptyNodes,
  [],
  `MCP tool schemas must not contain unconstrained empty schema nodes:\n${emptyNodes.join('\n')}`,
);

assert.doesNotThrow(() => {
  ReadFileArgsSchema.parse({
    path: 'example.txt',
    options: {
      renderer: 'default',
      nested: { enabled: true, retries: 2, tags: ['a', 'b'], nullable: null },
    },
  });
});

assert.doesNotThrow(() => {
  EditBlockArgsSchema.parse({
    file_path: 'example.xlsx',
    range: 'Sheet1!A1:B2',
    content: [
      [1, 'formula', true, null],
      [{ rich: { text: 'value' } }, ['nested', 2]],
    ],
    options: {
      outputPath: 'copy.xlsx',
      nested: { preserveFormatting: true },
    },
  });
});

console.log('MCP schema hardening contract: PASS');
