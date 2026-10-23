import { execFile } from 'node:child_process';
import path from 'node:path';

/** Historical Task Scheduler events are observations, not restart authorization. */
export interface WindowsTunnelTaskEvent {
    timeUtc: string;
    eventId: number;
    resultCode: string | null;
}
export interface WindowsTunnelTaskEvents {
    kind: 'observational_only';
    /** True if the bounded query reached its search ceiling; other events may be omitted. */
    capped: boolean;
    events: WindowsTunnelTaskEvent[];
}
export interface WindowsTunnelTaskEventsDependencies {
    platform?: NodeJS.Platform;
    environment?: Record<string, string | undefined>;
    run?: (executable: string, args: readonly string[]) =>
        Promise<{ stdout: string; stderr: string }>;
}

const EVENT_IDS = new Set([100, 102, 110, 111, 118, 129, 200, 201, 325]);
const MAX_EVENTS = 50;
const MAX_OUTPUT_BYTES = 64 * 1024;

function record(value: unknown): Record<string, unknown> | null {
    return value !== null && typeof value === 'object' && !Array.isArray(value)
        ? value as Record<string, unknown> : null;
}
function exactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
    const actual = Object.keys(value);
    return actual.length === expected.length &&
        actual.every((key) => expected.includes(key));
}

/** Strictly project only allowlisted metadata, never raw event messages or identifiers. */
export function parseWindowsTunnelTaskEvents(raw: string): WindowsTunnelTaskEvents {
    if (Buffer.byteLength(raw, 'utf8') > MAX_OUTPUT_BYTES) {
        throw new Error('Scheduler diagnostic output exceeds the size limit.');
    }
    let decoded: unknown;
    try { decoded = JSON.parse(raw); }
    catch { throw new Error('Scheduler diagnostic output must be valid JSON.'); }
    const root = record(decoded);
    if (!root || !exactKeys(root, ['kind', 'capped', 'events']) ||
        root.kind !== 'observational_only' || typeof root.capped !== 'boolean' ||
        !Array.isArray(root.events) || root.events.length > MAX_EVENTS) {
        throw new Error('Scheduler diagnostic output has an invalid envelope.');
    }
    const events: WindowsTunnelTaskEvent[] = root.events.map((value: unknown) => {
        const item = record(value);
        if (!item || !exactKeys(item, ['timeUtc', 'eventId', 'resultCode']) ||
            typeof item.timeUtc !== 'string' ||
            !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{7}Z$/.test(item.timeUtc) ||
            !Number.isFinite(Date.parse(item.timeUtc)) ||
            typeof item.eventId !== 'number' || !EVENT_IDS.has(item.eventId) ||
            !(item.resultCode === null ||
                (typeof item.resultCode === 'string' &&
                    /^\d{1,10}$/.test(item.resultCode) &&
                    Number(item.resultCode) <= 0xffffffff))) {
            throw new Error('Scheduler diagnostic output contains an invalid event.');
        }
        return {
            timeUtc: item.timeUtc,
            eventId: item.eventId,
            resultCode: item.resultCode,
        };
    });
    return { kind: 'observational_only', capped: root.capped, events };
}

/** An XPath string literal with no executable interpolation. */
function xpathLiteral(value: string): string {
    if (!value.includes("'")) return "'" + value + "'";
    if (!value.includes('"')) return '"' + value + '"';
    // The native Windows Event Log XPath subset does not implement concat().
    // No exact filter can be formed for values containing both quote kinds.
    throw new Error('Task name cannot be represented in Windows Event Log XPath.');
}

/** Encode a native Event Log XPath expression as XML element text. */
function xmlText(value: string): string {
    return value.replace(/&/g, '&amp;').replace(/</g, '&lt;')
        .replace(/>/g, '&gt;');
}

/** Bounded native-filtered query, no raw messages, task paths or secrets. */
export function buildWindowsTunnelTaskEventsPowerShell(taskName: string): string {
    const normalized = taskName.trim();
    if (!normalized || normalized.length > 256 ||
        /[\0\r\n\u0001-\u001f]/.test(normalized)) {
        throw new Error('Unsupported Windows tunnel task name.');
    }
    const canonicalName = normalized.startsWith('\\')
        ? normalized : '\\' + normalized;
    const channel = 'Microsoft-Windows-TaskScheduler/Operational';
    const eventIds = [...EVENT_IDS].map((id) => 'EventID=' + id).join(' or ');
    const xpath = '*[System[(' + eventIds +
        ') and TimeCreated[timediff(@SystemTime) <= 259200000]]' +
        ' and EventData[Data[@Name=\'TaskName\']=' +
        xpathLiteral(canonicalName) + ']]';
    const queryXml = '<QueryList><Query Id="0" Path="' + channel +
        '"><Select Path="' + channel + '">' + xmlText(xpath) +
        '</Select></Query></QueryList>';

    // A PowerShell single-quoted string does not interpolate variables.
    const literal = queryXml.replace(/'/g, "''");
    return [
        "$ErrorActionPreference='Stop'",
        "$taskName='" + normalized.replace(/'/g, "''") + "'",
        "$canonicalName=if($taskName.StartsWith('\\')){$taskName}else{'\\'+$taskName}",
        "$logName='" + channel + "'",
        '$log=Get-WinEvent -ListLog $logName -ErrorAction Stop',
        "if(-not $log.IsEnabled){ throw 'Scheduler operational log is disabled.' }",
        "$filterXml=[xml]'" + literal + "'",
        '$records=@()',
        'try {',
        '  $records=@(Get-WinEvent -FilterXml $filterXml -MaxEvents 51 -ErrorAction Stop)',
        '} catch {',
        "  if($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*'){",
        "    throw 'Scheduler operational event query failed.'",
        '  }',
        '}',
        '$matched=@($records | Where-Object {',
        '    [xml]$eventXml=$_.ToXml()',
        '    $taskData=@($eventXml.Event.EventData.Data) |',
        "      Where-Object { $_.Name -eq 'TaskName' } | Select-Object -First 1",
        "    $null -ne $taskData -and ([string]$taskData.'#text') -eq $canonicalName",
        '  })',
        '$rows=@($matched | Select-Object -First 50 | ForEach-Object {',
        '    $resultCode=$null',
        '    if($_.Id -eq 201){',
        '      [xml]$xml=$_.ToXml()',
        '      $entry=@($xml.Event.EventData.Data) |',
        "        Where-Object { $_.Name -eq 'ResultCode' } | Select-Object -First 1",
        "      if($null -ne $entry){ $resultCode=[string]$entry.'#text' }",
        '    }',
        '    [pscustomobject]@{',
        "      timeUtc=$_.TimeCreated.ToUniversalTime().ToString('o',[cultureinfo]::InvariantCulture)",
        '      eventId=[int]$_.Id',
        '      resultCode=$resultCode',
        '    }',
        '  })',
        "[pscustomobject]@{kind='observational_only';capped=($records.Count -gt 50);events=$rows} |",
        '  ConvertTo-Json -Depth 4 -Compress',
    ].join('\r\n');
}

function systemPowerShell(environment: Record<string, string | undefined>): string {
    const root = environment.SystemRoot?.trim();
    if (!root || !path.win32.isAbsolute(root)) {
        throw new Error('SystemRoot must contain an absolute Windows path.');
    }
    return path.win32.join(root, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
}

const defaultRun = (executable: string, args: readonly string[]) =>
    new Promise<{ stdout: string; stderr: string }>((resolve, reject) => {
        execFile(executable, [...args], {
            windowsHide: true, shell: false, encoding: 'utf8',
            timeout: 10000, maxBuffer: MAX_OUTPUT_BYTES,
        }, (error, stdout, stderr) => {
            if (error) reject(error);
            else resolve({ stdout, stderr });
        });
    });

/** Independently query Scheduler even when the tunnel health API is offline. */
export async function readWindowsTunnelTaskEvents(
    taskName: string,
    dependencies: WindowsTunnelTaskEventsDependencies = {},
): Promise<WindowsTunnelTaskEvents> {
    if ((dependencies.platform ?? process.platform) !== 'win32') {
        throw new Error('Windows tunnel event diagnostics are available only on Windows.');
    }
    const executable = systemPowerShell(dependencies.environment ?? process.env);
    const encoded = Buffer.from(
        buildWindowsTunnelTaskEventsPowerShell(taskName), 'utf16le',
    ).toString('base64');
    let raw: string;
    try {
        raw = (await (dependencies.run ?? defaultRun)(executable, [
            '-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', encoded,
        ])).stdout;
    } catch {
        // Native exceptions can contain arbitrary command line / environment data.
        throw new Error('Windows Task Scheduler event query failed.');
    }
    return parseWindowsTunnelTaskEvents(raw);
}
