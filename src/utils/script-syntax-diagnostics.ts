import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import path from 'node:path';
import type { ServerResult } from '../types.js';

export type ScriptValidationStatus = 'passed' | 'failed' | 'unavailable' | 'skipped';
export interface ScriptValidation {
    status: ScriptValidationStatus;
    engine: string;
    scope: 'syntax' | 'syntax-and-lint';
    diagnostics: string[];
    basis: 'submitted-text';
    persistedRevisionVerified: false;
    lint?: { engine: string; status: 'passed' | 'failed' | 'unavailable' };
}

const MAX_SOURCE_BYTES = 1024 * 1024;
const MAX_OUTPUT_BYTES = 8192;
const MAX_MESSAGES = 6;
const TIMEOUT_MS = 5000;
const EXTENSIONS = new Set([
    '.js', '.cjs', '.mjs', '.ts', '.tsx', '.mts', '.cts',
    '.py', '.sh', '.bash', '.ps1', '.psm1', '.psd1',
]);

export function isScriptFile(filePath: string): boolean {
    return EXTENSIONS.has(path.extname(filePath).toLowerCase());
}

const POWERSHELL_PARSE = [
    '$source = [Console]::In.ReadToEnd()',
    '$tokens = $null; $parseErrors = $null',
    '[System.Management.Automation.Language.Parser]::ParseInput($source, [ref]$tokens, [ref]$parseErrors) | Out-Null',
    'if ($parseErrors.Count -gt 0) {',
    '  foreach ($issue in $parseErrors | Select-Object -First 6) {',
    '    [Console]::Error.WriteLine(("{0}:{1}: {2}" -f $issue.Extent.StartLineNumber, $issue.Extent.StartColumnNumber, $issue.Message))',
    '  }',
    '  exit 2',
    '}',
].join('; ');

const POWERSHELL_LINT = [
    '$source = [Console]::In.ReadToEnd()',
    '$module = Get-Module -ListAvailable -Name PSScriptAnalyzer | Select-Object -First 1',
    'if ($null -eq $module) { [Console]::Out.WriteLine("JDC_OPTIONAL_LINTER_MISSING"); exit 4 }',
    'Import-Module PSScriptAnalyzer -ErrorAction Stop',
    '$issues = @(Invoke-ScriptAnalyzer -ScriptDefinition $source -Severity Error,Warning -ErrorAction Stop)',
    'foreach ($issue in $issues | Select-Object -First 6) {',
    '  [Console]::Error.WriteLine(("{0}:{1}: {2} {3}" -f $issue.Line, $issue.Column, $issue.RuleName, $issue.Message))',
    '}',
    'if ($issues.Count -gt 0) { exit 2 }',
].join('; ');

const PYTHON_PARSE = [
    'import ast, sys',
    'ast.parse(sys.stdin.read(), filename="agent.py")',
].join('\n');

type Parser = { command: string; args: string[]; engine: string };
function selectParser(filePath: string): Parser | null {
    const ext = path.extname(filePath).toLowerCase();
    if (['.js', '.cjs', '.mjs'].includes(ext)) {
        const mode = ext === '.mjs' ? ['--input-type=module']
            : ext === '.cjs' ? ['--input-type=commonjs'] : [];
        return { command: process.execPath, args: ['--check', ...mode, '-'],
            engine: 'Node.js syntax checker' };
    }
    if (ext === '.py') {
        return { command: process.platform === 'win32' ? 'python' : 'python3',
            args: ['-I', '-c', PYTHON_PARSE], engine: 'Python ast.parse' };
    }
    if (ext === '.sh' || ext === '.bash') {
        return { command: 'bash', args: ['-n', '-'], engine: 'Bash syntax checker' };
    }
    if (['.ps1', '.psm1', '.psd1'].includes(ext)) {
        return { command: process.platform === 'win32' ? 'powershell.exe' : 'pwsh',
            args: ['-NoProfile', '-NonInteractive', '-Command', POWERSHELL_PARSE],
            engine: 'PowerShell Parser.ParseInput' };
    }
    return null;
}

function selectOptionalLinter(filePath: string): Parser | null {
    const ext = path.extname(filePath).toLowerCase();
    if (ext === '.sh' || ext === '.bash') {
        return { command: 'shellcheck', args: ['--format=gcc', '--severity=warning', '-'],
            engine: 'ShellCheck' };
    }
    if (['.ps1', '.psm1', '.psd1'].includes(ext)) {
        return { command: process.platform === 'win32' ? 'powershell.exe' : 'pwsh',
            args: ['-NoProfile', '-NonInteractive', '-Command', POWERSHELL_LINT],
            engine: 'PSScriptAnalyzer' };
    }
    if (ext === '.py') {
        return { command: 'ruff', args: ['check', '--isolated', '--no-cache',
                '--output-format=concise', '--stdin-filename', 'agent.py', '-'],
            engine: 'Ruff' };
    }
    return null;
}

function sanitizedEnvironment(): NodeJS.ProcessEnv {
    const env = { ...process.env };
    for (const key of ['NODE_OPTIONS', 'NODE_PATH', 'BASH_ENV', 'ENV',
        'PYTHONPATH', 'PYTHONHOME', 'PYTHONSTARTUP']) delete env[key];
    return env;
}

function unavailable(engine: string, reason: string): ScriptValidation {
    return { status: 'unavailable', engine, scope: 'syntax', diagnostics: [reason],
        basis: 'submitted-text', persistedRevisionVerified: false };
}

async function invokeParser(parser: Parser, source: string): Promise<ScriptValidation> {
    return new Promise((resolve) => {
        let child: ChildProcessWithoutNullStreams;
        try {
            child = spawn(parser.command, parser.args, {
                shell: false, windowsHide: true, stdio: 'pipe',
                env: sanitizedEnvironment(),
            });
        } catch {
            resolve(unavailable(parser.engine, 'Validator process could not start.'));
            return;
        }
        let stdout = '';
        let stderr = '';
        let collected = 0;
        let timedOut = false;
        let overflowed = false;
        let spawnError: NodeJS.ErrnoException | undefined;
        const timer = setTimeout(() => {
            timedOut = true;
            child.kill();
        }, TIMEOUT_MS);
        timer.unref();

        const collect = (part: 'stdout' | 'stderr', chunk: Buffer): void => {
            if (overflowed) return;
            collected += chunk.byteLength;
            if (collected > MAX_OUTPUT_BYTES) {
                overflowed = true;
                child.kill();
                return;
            }
            if (part === 'stdout') stdout += chunk.toString('utf8');
            else stderr += chunk.toString('utf8');
        };
        child.stdout.on('data', (data: Buffer) => collect('stdout', data));
        child.stderr.on('data', (data: Buffer) => collect('stderr', data));
        child.stdin.on('error', () => {
            // Validator may exit while source is being written.
        });
        child.on('error', (error: NodeJS.ErrnoException) => { spawnError = error; });
        child.on('close', (code) => {
            clearTimeout(timer);
            if (spawnError || timedOut || overflowed) {
                resolve(unavailable(parser.engine, 'Validator unavailable or exceeded its execution limit.'));
                return;
            }
            if (code === 0) {
                resolve({ status: 'passed', engine: parser.engine, scope: 'syntax',
                    diagnostics: [], basis: 'submitted-text', persistedRevisionVerified: false });
                return;
            }
            if (code === 4 && stdout.trim() === 'JDC_OPTIONAL_LINTER_MISSING') {
                resolve(unavailable(parser.engine, 'Optional linter is not installed.'));
                return;
            }
            const diagnosticText = (stderr || stdout || '').trim();
            const diagnostics = diagnosticText.split(/\r?\n/).filter(Boolean)
                .slice(0, MAX_MESSAGES).map(line => line.slice(0, 360));
            resolve({ status: 'failed', engine: parser.engine, scope: 'syntax',
                diagnostics: diagnostics.length ? diagnostics : ['Static analysis failed.'],
                basis: 'submitted-text', persistedRevisionVerified: false });
        });
        child.stdin.end(source, 'utf8');
    });
}

/**
 * Checks supplied immutable text only. No path reopen is performed by this module.
 * Advisory static analysis does not certify bytes persisted or runtime safety.
 */
export async function checkScriptSyntax(
    filePath: string, submittedText?: string,
): Promise<ScriptValidation> {
    if (!isScriptFile(filePath)) {
        return { status: 'skipped', engine: 'none', scope: 'syntax',
            diagnostics: [], basis: 'submitted-text', persistedRevisionVerified: false };
    }
    if (submittedText === undefined) {
        return unavailable('source snapshot', 'Complete source snapshot unavailable; no pathname reopen performed.');
    }
    if (Buffer.byteLength(submittedText, 'utf8') > MAX_SOURCE_BYTES) {
        return unavailable('source snapshot', 'Script exceeds the 1 MiB inspection limit.');
    }
    const parser = selectParser(filePath);
    if (!parser) {
        return unavailable('TypeScript project compiler',
            'No trusted TypeScript parser is bundled with the installed runtime; run the project type checker.');
    }
    const syntax = await invokeParser(parser, submittedText);
    if (syntax.status !== 'passed') return syntax;
    const linter = selectOptionalLinter(filePath);
    if (!linter) return syntax;
    const lint = await invokeParser(linter, submittedText);
    return {
        status: lint.status === 'failed' ? 'failed' : 'passed',
        engine: parser.engine,
        scope: lint.status === 'unavailable' ? 'syntax' : 'syntax-and-lint',
        basis: 'submitted-text', persistedRevisionVerified: false,
        lint: { engine: linter.engine, status: lint.status === 'skipped' ? 'unavailable' : lint.status },
        diagnostics: lint.status === 'unavailable'
            ? [linter.engine + ' is not available; only syntax was checked.'] : lint.diagnostics,
    };
}

/** Attach advisory diagnostics without changing a successful file-write outcome. */
export async function withScriptSyntaxFeedback(
    result: ServerResult, filePath: string, submittedText?: string,
): Promise<ServerResult> {
    if (result.isError || !isScriptFile(filePath)) return result;
    const report = await checkScriptSyntax(filePath, submittedText);
    const diagnostics = report.diagnostics.join('\n');
    const lintState = report.lint ? ' ' + report.lint.engine + ': ' + report.lint.status.toUpperCase() + '.' : '';
    const message = 'Script syntax/lint validation: ' + report.status.toUpperCase() +
        ' (' + report.engine + ').' + lintState +
        (diagnostics ? '\n' + diagnostics : '') +
        '\nAnalyzed submitted text in memory. No script executed or target path reopened.' +
        '\nA successful check does not verify the stored file revision or runtime correctness.';
    return { ...result, content: [...result.content, { type: 'text', text: message }],
        structuredContent: { ...result.structuredContent, scriptValidation: report } };
}
