import assert from 'node:assert/strict';
import ExcelJS from 'exceljs';

const workbook = new ExcelJS.Workbook();
const worksheet = workbook.addWorksheet('Audit');
worksheet.getCell('A1').value = 10;
worksheet.getCell('A2').value = 20;

worksheet.addConditionalFormatting({
  ref: 'A1:A2',
  rules: [
    {
      type: 'dataBar',
      gradient: false,
      cfvo: [
        { type: 'min' },
        { type: 'max' },
      ],
      color: { argb: 'FF638EC6' },
    },
  ],
});

const buffer = await workbook.xlsx.writeBuffer();
assert.ok(buffer.byteLength > 0, 'ExcelJS should serialize a workbook using extended data bars');

const rule = worksheet.conditionalFormattings[0]?.rules[0];
assert.equal(rule?.type, 'dataBar');
assert.match(
  String(rule?.x14Id ?? ''),
  /^\{[0-9A-F]{8}-[0-9A-F]{4}-4[0-9A-F]{3}-[89AB][0-9A-F]{3}-[0-9A-F]{12}\}$/,
  'ExcelJS should generate an RFC-compatible v4 UUID for the extended rule',
);

console.log('ExcelJS uuid override compatibility test passed');
