import { execFile } from 'node:child_process';
import { stat } from 'node:fs/promises';
import path from 'node:path';
import type { ServerResult } from '../types.js';

export type ScriptValidationStatus = 'passed' | 'failed' | 'unavailable' | 'skipped';
export interface ScriptValidation {
    status: ScriptValidationStatus;
    engine: string;
    scope: 'syntax' | 'syntax-and-lint';
    diagnostics: string[];
    lint?: { engine: string; status: 'passed' | 'failed' | 'unavailable' };
}

const MAX_SCRIPT_BYTES = 1024 * 1024;
const MAX_OUTPUT_BYTES = 8192;
const MAX_MESSAGES = 6;
const TIMEOUT_MS = 5000;
const EXTENSIONS = new Set(['.js', '.cjs', '.mjs', '.ts', '.tsx', '.mts', '.cts',
    '.py', '.sh', '.bash', '.ps1', '.psm1', '.psd1']);

export function isScriptFile(filePath: string): boolean {
    return EXTENSIONS.has(path.extname(filePath).toLowerCase());
}
const POWERSHELL_PARSE = [
    '$tokens = $null; $parseErrors = $null',
    '[System.Management.Automation.Language.Parser]::ParseFile($env:JDC_SYNTAX_TARGET, [ref]$tokens, [ref]$parseErrors) | Out-Null',
    'if ($parseErrors.Count -gt 0) {',
    '  foreach ($issue in $parseErrors | Select-Object -First 6) {',
    '    [Console]::Error.WriteLine(("{0}:{1}: {2}" -f $issue.Extent.StartLineNumber, $issue.Extent.StartColumnNumber, $issue.Message))',
    '  }',
    '  exit 2',
    '}',
].join('; ');

const POWERSHELL_LINT = [
    '$module = Get-Module -ListAvailable -Name PSScriptAnalyzer | Select-Object -First 1',
    'if ($null -eq $module) { [Console]::Out.WriteLine("JDC_OPTIONAL_LINTER_MISSING"); exit 4 }',
    'Import-Module PSScriptAnalyzer -ErrorAction Stop',
    '$issues = @(Invoke-ScriptAnalyzer -Path $env:JDC_SYNTAX_TARGET -Severity Error,Warning -ErrorAction Stop)',
    'foreach ($issue in $issues | Select-Object -First 6) {',
    '  [Console]::Error.WriteLine(("{0}:{1}: {2} {3}" -f $issue.Line, $issue.Column, $issue.RuleName, $issue.Message))',
    '}',
    'if ($issues.Count -gt 0) { exit 2 }',
].join('; ');

const PYTHON_PARSE = [
    'import ast, sys',
    'with open(sys.argv[1], "rb") as source: ast.parse(source.read(), filename=sys.argv[1])',
].join('\n');

type Parser = { command: string; args: string[]; engine: string; env?: Record<string, string> };
function selectParser(filePath: string): Parser | null {
    const ext = path.extname(filePath).toLowerCase();
    if (['.js', '.cjs', '.mjs'].includes(ext)) {
        return { command: process.execPath, args: ['--check', filePath], engine: 'Node.js syntax checker' };
    }
    if (ext === '.py') {
        return { command: process.platform === 'win32' ? 'python' : 'python3',
            args: ['-I', '-c', PYTHON_PARSE, filePath], engine: 'Python ast.parse' };
    }
    if (ext === '.sh' || ext === '.bash') {
        return { command: 'bash', args: ['-n', filePath], engine: 'Bash syntax checker' };
    }
    if (['.ps1', '.psm1', '.psd1'].includes(ext)) {
        return { command: process.platform === 'win32' ? 'powershell.exe' : 'pwsh',
            args: ['-NoProfile', '-NonInteractive', '-Command', POWERSHELL_PARSE],
            engine: 'PowerShell Parser.ParseFile', env: { JDC_SYNTAX_TARGET: filePath } };
    }
    return null;
}

function selectOptionalLinter(filePath: string): Parser | null {
    const ext = path.extname(filePath).toLowerCase();
    if (ext === '.sh' || ext === '.bash') {
        return { command: 'shellcheck', args: ['--format=gcc', '--severity=warning', filePath], engine: 'ShellCheck' };
    }
    if (['.ps1', '.psm1', '.psd1'].includes(ext)) {
        return { command: process.platform === 'win32' ? 'powershell.exe' : 'pwsh',
            args: ['-NoProfile', '-NonInteractive', '-Command', POWERSHELL_LINT],
            engine: 'PSScriptAnalyzer', env: { JDC_SYNTAX_TARGET: filePath } };
    }
    if (ext === '.py') {
        return { command: 'ruff', args: ['check', '--output-format=concise', filePath], engine: 'Ruff' };
    }
    return null;
}

function sanitizedEnvironment(extra?: Record<string, string>): NodeJS.ProcessEnv {
    const env = { ...process.env, ...extra };
    for (const key of ['NODE_OPTIONS', 'NODE_PATH', 'BASH_ENV', 'ENV',
        'PYTHONPATH', 'PYTHONHOME', 'PYTHONSTARTUP']) delete env[key];
    return env;
}

async function invokeParser(parser: Parser): Promise<ScriptValidation> {
    return new Promise((resolve) => {
        execFile(parser.command, parser.args, {
            shell: false, windowsHide: true, timeout: TIMEOUT_MS,
            maxBuffer: MAX_OUTPUT_BYTES, env: sanitizedEnvironment(parser.env),
        }, (error, stdout, stderr) => {
            const diagnosticText = (stderr || stdout || '').trim();
            const diagnostics = diagnosticText.split(/\r?\n/).filter(Boolean)
                .slice(0, MAX_MESSAGES).map(line => line.slice(0, 360));
            if (!error) {
                resolve({ status: 'passed', engine: parser.engine,
                    scope: 'syntax', diagnostics: [] });
                return;
            }
            const code = (error as Error & { code?: string | number }).code;
            if (code === 'ENOENT' || error.killed || code === 'ERR_CHILD_PROCESS_STDIO_MAXBUFFER'
                || (code === 4 && stdout.trim() === 'JDC_OPTIONAL_LINTER_MISSING')) {
                resolve({ status: 'unavailable', engine: parser.engine, scope: 'syntax',
                    diagnostics: ['Validator unavailable or exceeded its execution limit.'] });
                return;
            }
            resolve({ status: 'failed', engine: parser.engine, scope: 'syntax',
                diagnostics: diagnostics.length ? diagnostics : ['Script syntax check failed.'] });
        });
    });
}

export async function checkScriptSyntax(filePath: string): Promise<ScriptValidation> {
    const parser = selectParser(path.resolve(filePath));
    if (!parser) {
        if (isScriptFile(filePath)) {
            return { status: 'unavailable', engine: 'TypeScript project compiler', scope: 'syntax',
                diagnostics: ['No trusted TypeScript parser is bundled with the installed runtime; run the project type checker.'] };
        }
        return { status: 'skipped', engine: 'none', scope: 'syntax', diagnostics: [] };
    }
    try {
        const info = await stat(path.resolve(filePath));
        if (!info.isFile() || info.size > MAX_SCRIPT_BYTES) {
            return { status: 'unavailable', engine: parser.engine, scope: 'syntax',
                diagnostics: ['Script is not a regular file or exceeds the 1 MiB inspection limit.'] };
        }
        const syntax = await invokeParser(parser);
        if (syntax.status !== 'passed') return syntax;
        const optional = selectOptionalLinter(filePath);
        if (!optional) return syntax;
        const lint = await invokeParser(optional);
        return {
            status: lint.status === 'failed' ? 'failed' : 'passed',
            engine: parser.engine, scope: lint.status === 'unavailable' ? 'syntax' : 'syntax-and-lint',
            lint: { engine: optional.engine, status: lint.status === 'skipped' ? 'unavailable' : lint.status },
            diagnostics: lint.status === 'unavailable'
                ? [`${optional.engine} is not available; only syntax was checked.`]
                : lint.diagnostics,
        };
    } catch {
        return { status: 'unavailable', engine: parser.engine, scope: 'syntax',
            diagnostics: ['Script cannot be read for syntax validation.'] };
    }
}
/**
 * Adds machine-readable feedback to a successful write/edit result.
 * Never changes a successful file write to isError: a malformed saved script
 * must remain accessible to the agent for correction. Never executes the script.
 * This is a diagnostic, not an authorization or pre-execution security gate.
 */
export async function withScriptSyntaxFeedback(result: ServerResult, filePath: string): Promise<ServerResult> {
    if (result.isError || !isScriptFile(filePath)) return result;
    const report = await checkScriptSyntax(filePath);
    const statusText = report.status.toUpperCase();
    const details = report.diagnostics.join('\n');
    const lintState = report.lint ? ` ${report.lint.engine}: ${report.lint.status.toUpperCase()}.` : '';
    const message = `Script syntax/lint validation: ${statusText} (${report.engine}).${lintState}` +
        (details ? `\n${details}` : '') +
        '\nFile was saved. Syntax validation does not execute or prove runtime correctness.';
    return {
        ...result,
        content: [...result.content, { type: 'text', text: message }],
        structuredContent: { ...result.structuredContent, scriptValidation: report },
    };
}
