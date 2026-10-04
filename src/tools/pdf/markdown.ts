import fs from 'fs/promises';
import { existsSync, readdirSync } from 'fs';
import { dirname, isAbsolute, join, relative, resolve, sep } from 'path';
import MarkdownIt from 'markdown-it';
import type { LaunchOptions, PDFOptions } from 'puppeteer-core';
import type { PageRange } from './lib/pdf2md.js';
import { PdfParseResult, pdf2md } from './lib/pdf2md.js';
import { CONFIG_FILE } from '../../config.js';

const isUrl = (source: string): boolean =>
    source.startsWith('http://') || source.startsWith('https://');

// Cached Chrome path to avoid repeated lookups
let cachedChromePath: string | undefined | null = null; // null = not checked yet
let chromeCheckPromise: Promise<string | undefined> | null = null;

interface CachedPuppeteerChrome {
    executablePath: string;
}

/**
 * Get Desktop Commander's private Puppeteer cache directory.
 */
function getPuppeteerCacheDir(): string {
    return join(dirname(CONFIG_FILE), 'puppeteer-cache');
}

/**
 * Get the cache path where Puppeteer stores Chrome for Testing builds.
 */
function getPuppeteerChromeDir(cacheDir = getPuppeteerCacheDir()): string {
    return join(cacheDir, 'chrome');
}

/**
 * Find the platform-specific executable within a cached Chrome build directory.
 */
function getChromeExecutablePath(chromeDir: string, version: string): string | undefined {
    const chromePath = process.platform === 'win32'
        ? join(chromeDir, version, 'chrome-win64', 'chrome.exe')
        : process.platform === 'darwin'
        ? join(chromeDir, version, 'chrome-mac-x64', 'Google Chrome for Testing.app', 'Contents', 'MacOS', 'Google Chrome for Testing')
        : join(chromeDir, version, 'chrome-linux64', 'chrome');

    if (existsSync(chromePath)) {
        return chromePath;
    }

    // Also check for arm64 mac
    if (process.platform === 'darwin') {
        const armPath = join(chromeDir, version, 'chrome-mac-arm64', 'Google Chrome for Testing.app', 'Contents', 'MacOS', 'Google Chrome for Testing');
        if (existsSync(armPath)) {
            return armPath;
        }
    }

    return undefined;
}

/**
 * Resolve the cached Chrome build directory that owns an executable path.
 */
function getCachedChromeBuildDir(chromeDir: string, executablePath: string): string | undefined {
    const relativePath = relative(chromeDir, executablePath);
    if (relativePath === '..' || relativePath.startsWith(`..${sep}`) || isAbsolute(relativePath)) {
        return undefined;
    }

    const [buildDir] = relativePath.split(sep);
    return buildDir ? join(chromeDir, buildDir) : undefined;
}

/**
 * Find Chrome in puppeteer's cache directory
 * Returns the executable path if found, undefined otherwise
 */
export function findPuppeteerChrome(cacheDir = getPuppeteerCacheDir()): CachedPuppeteerChrome | undefined {
    const chromeDir = getPuppeteerChromeDir(cacheDir);

    if (!existsSync(chromeDir)) {
        return undefined;
    }

    try {
        // Look for chrome directories (e.g., win64-143.0.7499.169)
        const versions = readdirSync(chromeDir, { withFileTypes: true })
            .filter(entry => entry.isDirectory())
            .map(entry => entry.name)
            .sort((a, b) => b.localeCompare(a, undefined, { numeric: true }));
        
        for (const version of versions) {
            const executablePath = getChromeExecutablePath(chromeDir, version);
            if (executablePath) {
                return { executablePath };
            }
        }
    } catch {
        // Ignore errors reading cache directory
    }

    return undefined;
}

/**
 * Remove stale Puppeteer Chrome builds while preserving the active build.
 */
export async function pruneOldPuppeteerChromeBuilds(activeExecutablePath: string, cacheDir = getPuppeteerCacheDir()): Promise<void> {
    const chromeDir = getPuppeteerChromeDir(cacheDir);
    const activeBuildDir = getCachedChromeBuildDir(chromeDir, activeExecutablePath);
    if (!activeBuildDir) {
        return;
    }

    let entries;
    try {
        entries = await fs.readdir(chromeDir, { withFileTypes: true });
    } catch {
        return;
    }

    await Promise.all(entries
        .filter(entry => entry.isDirectory())
        .map(async entry => {
            const buildDir = join(chromeDir, entry.name);
            if (resolve(buildDir) === resolve(activeBuildDir)) {
                return;
            }

            try {
                await fs.rm(buildDir, { recursive: true, force: true });
            } catch (error) {
                console.error(`Failed to remove old Chrome cache build at ${buildDir}:`, error);
            }
        }));
}

/**
 * Find system-installed Chrome/Chromium browser
 * Returns the executable path if found, undefined otherwise
 */
function findSystemChrome(): string | undefined {
    const paths: string[] = process.platform === 'win32' 
        ? [
            'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
            'C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe',
            `${process.env.LOCALAPPDATA}\\Google\\Chrome\\Application\\chrome.exe`,
            'C:\\Program Files\\Chromium\\Application\\chrome.exe',
            'C:\\Program Files (x86)\\Chromium\\Application\\chrome.exe',
        ]
        : process.platform === 'darwin'
        ? [
            '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
            '/Applications/Chromium.app/Contents/MacOS/Chromium',
            '/Applications/Google Chrome Canary.app/Contents/MacOS/Google Chrome Canary',
        ]
        : [
            // Linux paths
            '/usr/bin/google-chrome',
            '/usr/bin/google-chrome-stable',
            '/usr/bin/chromium',
            '/usr/bin/chromium-browser',
            '/snap/bin/chromium',
        ];
    
    return paths.find(p => existsSync(p));
}

/**
 * Download and install Chrome using @puppeteer/browsers
 * Returns the executable path after installation
 */
async function installChrome(): Promise<CachedPuppeteerChrome> {
    // Dynamic import to avoid loading if not needed
    const { install, Browser, detectBrowserPlatform, resolveBuildId } = await import('@puppeteer/browsers');
    
    const cacheDir = getPuppeteerCacheDir();
    const platform = detectBrowserPlatform()!;
    const buildId = await resolveBuildId(Browser.CHROME, platform, 'stable');
    
    console.error('Downloading Chrome for PDF generation (this may take a few minutes)...');
    await fs.mkdir(cacheDir, { recursive: true });

    const installedBrowser = await install({
        browser: Browser.CHROME,
        buildId,
        cacheDir,
        downloadProgressCallback: (downloadedBytes: number, totalBytes: number) => {
            const percent = Math.round((downloadedBytes / totalBytes) * 100);
            process.stderr.write(`\rDownloading Chrome: ${percent}%`);
        },
    });
    
    console.error('\nChrome download complete.');
    
    return {
        executablePath: installedBrowser.executablePath,
    };
}

/**
 * Find or install Chrome for PDF generation
 * Priority: 1. Puppeteer cache, 2. System Chrome, 3. Install Chrome
 * Results are cached to avoid repeated lookups
 */
async function getChromePath(): Promise<string | undefined> {
    // Return cached result if available
    if (cachedChromePath !== null) {
        return cachedChromePath;
    }
    
    // If a check is already in progress, wait for it
    if (chromeCheckPromise) {
        return chromeCheckPromise;
    }
    
    // Start the check
    chromeCheckPromise = (async () => {
        // 1. Check puppeteer cache first (exact compatible version)
        const cachedChrome = findPuppeteerChrome();
        if (cachedChrome) {
            await pruneOldPuppeteerChromeBuilds(cachedChrome.executablePath);
            cachedChromePath = cachedChrome.executablePath;
            return cachedChrome.executablePath;
        }
        
        // 2. Check system Chrome
        const systemChrome = findSystemChrome();
        if (systemChrome) {
            cachedChromePath = systemChrome;
            return systemChrome;
        }
        
        // 3. Install Chrome as last resort
        try {
            const installedChrome = await installChrome();
            await pruneOldPuppeteerChromeBuilds(installedChrome.executablePath);
            cachedChromePath = installedChrome.executablePath;
            return installedChrome.executablePath;
        } catch (error) {
            console.error('Failed to install Chrome:', error);
            cachedChromePath = undefined;
            return undefined;
        }
    })();
    
    const result = await chromeCheckPromise;
    chromeCheckPromise = null;
    return result;
}

/**
 * Preemptively ensure Chrome is available for PDF generation.
 * Call this at server startup to trigger download in background if needed.
 * Returns immediately, download happens in background.
 */
export function ensureChromeAvailable(): void {
    // Don't await - let it run in background
    getChromePath().catch((error) => {
        console.error('Background Chrome check failed:', error);
    });
}

async function loadPdfToBuffer(source: string): Promise<Buffer | ArrayBuffer> {
    if (isUrl(source)) {
        const response = await fetch(source);
        return await response.arrayBuffer();
    } else {
        return await fs.readFile(source);
    }
}

/**
 * Convert PDF to Markdown using @opendocsg/pdf2md
 */
export async function parsePdfToMarkdown(source: string, pageNumbers: number[] | PageRange = []): Promise<PdfParseResult> {
    try {
        const data = await loadPdfToBuffer(source);

        // @ts-ignore: Type definition mismatch for ESM usage
        return await pdf2md(new Uint8Array(data), pageNumbers);

    } catch (error) {
        console.error("Error converting PDF to Markdown (v3):", error);
        throw error;
    }
}

export interface MarkdownPdfOptions {
    launch_options?: Partial<Omit<LaunchOptions, 'executablePath'>>;
    pdf_options?: PDFOptions;
    css?: string;
    document_title?: string;
    body_class?: string[];
    page_media_type?: 'screen' | 'print';
}

const DEFAULT_PDF_OPTIONS: PDFOptions = {
    printBackground: true,
    format: 'A4',
    margin: {
        top: '30mm',
        right: '40mm',
        bottom: '30mm',
        left: '20mm',
    },
};

const DEFAULT_MARKDOWN_CSS = [
    ':root { color-scheme: light; }',
    'body { margin: 0; color: #1f2328; background: #ffffff; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Arial, sans-serif; font-size: 14px; line-height: 1.6; overflow-wrap: anywhere; }',
    'h1, h2, h3, h4, h5, h6 { line-height: 1.25; margin: 1.25em 0 0.5em; }',
    'h1, h2 { border-bottom: 1px solid #d0d7de; padding-bottom: 0.3em; }',
    'pre, code { font-family: Consolas, "Liberation Mono", monospace; }',
    'code { background: #f6f8fa; border-radius: 4px; padding: 0.15em 0.35em; }',
    'pre { background: #f6f8fa; border-radius: 6px; padding: 16px; overflow: auto; }',
    'pre code { padding: 0; background: transparent; }',
    'blockquote { margin: 0; padding: 0 1em; color: #59636e; border-left: 0.25em solid #d0d7de; }',
    'table { border-collapse: collapse; width: 100%; }',
    'th, td { border: 1px solid #d0d7de; padding: 6px 13px; text-align: left; }',
    'img { max-width: 100%; height: auto; }',
].join('\n');

function escapeHtml(value: string): string {
    return value
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function sanitizeBodyClasses(classes: string[] | undefined): string {
    if (!classes) return '';
    return classes
        .filter(value => /^[A-Za-z0-9_-]+$/.test(value))
        .join(' ');
}

export function renderMarkdownDocument(
    markdown: string,
    options: Pick<MarkdownPdfOptions, 'css' | 'document_title' | 'body_class'> = {},
): string {
    const renderer = new MarkdownIt({
        html: false,
        linkify: true,
        typographer: false,
    });
    const title = escapeHtml(options.document_title ?? 'Document');
    const bodyClass = sanitizeBodyClasses(options.body_class);
    const classAttribute = bodyClass ? ' class="' + bodyClass + '"' : '';
    const content = renderer.render(markdown);

    return [
        '<!doctype html>',
        '<html>',
        '<head>',
        '<meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        '<title>' + title + '</title>',
        '<style>' + DEFAULT_MARKDOWN_CSS + '\n' + (options.css ?? '') + '</style>',
        '</head>',
        '<body' + classAttribute + '>',
        content,
        '</body>',
        '</html>',
    ].join('\n');
}

export async function parseMarkdownToPdf(
    markdown: string,
    options: MarkdownPdfOptions = {},
): Promise<Buffer> {
    const chromePath = await getChromePath();
    if (!chromePath) {
        throw new Error(
            'PDF generation requires Chrome or Chromium browser. ' +
            'Please install Google Chrome or Chromium, then try again.'
        );
    }

    const { launch } = await import('puppeteer-core');
    const browser = await launch({
        ...(options.launch_options ?? {}),
        executablePath: chromePath,
        headless: true,
    });

    try {
        const page = await browser.newPage();
        await page.setJavaScriptEnabled(false);
        await page.emulateMediaType(options.page_media_type ?? 'screen');
        await page.setContent(renderMarkdownDocument(markdown, options), {
            waitUntil: 'load',
        });

        const pdf = await page.pdf({
            ...DEFAULT_PDF_OPTIONS,
            ...(options.pdf_options ?? {}),
        });

        return Buffer.from(pdf);
    } finally {
        await browser.close();
    }
}
