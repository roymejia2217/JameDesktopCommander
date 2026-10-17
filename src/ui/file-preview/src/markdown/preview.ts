import { createMarkdownIt, prepareMarkdownSource, type MarkdownToken } from './parser.js';

// Copy uses markdown-it tokens, not rendered HTML or hand-written tag stripping.
// The existing parser disables raw HTML and decodes character references once.
const copyMarkdown = createMarkdownIt();

interface ListLevel {
    ordered: boolean;
    nextNumber: number;
    marker: string;
    hasContent: boolean;
}

function inlineCopyText(tokens: MarkdownToken[]): string {
    return tokens.map((token) => {
        if (token.type === 'text' || token.type === 'code_inline') {
            return typeof token.content === 'string' ? token.content : '';
        }
        if (token.type === 'softbreak' || token.type === 'hardbreak') {
            return '\n';
        }
        if (token.type === 'image') {
            const children = Array.isArray(token.children) ? token.children as MarkdownToken[] : [];
            return children.length > 0
                ? inlineCopyText(children)
                : typeof token.content === 'string' ? token.content : '';
        }
        return '';
    }).join('').split('\u00a0').join(' ');
}
export function getRenderedMarkdownCopyText(content: string): string {
    const tokens = copyMarkdown.parse(prepareMarkdownSource(content));
    const lists: ListLevel[] = [];
    const blocks: Array<{ value: string; compact: boolean }> = [];
    let quoteDepth = 0;

    function emit(value: string): void {
        const clean = value.trimEnd();
        if (!clean) return;

        let text = clean;
        const level = lists[lists.length - 1];
        if (level) {
            const indent = '  '.repeat(lists.length - 1);
            const prefix = level.hasContent ? '  ' : level.marker;
            text = indent + prefix + text;
            level.hasContent = true;
        }
        if (quoteDepth > 0) {
            text = '> '.repeat(quoteDepth) + text;
        }
        blocks.push({ value: text, compact: lists.length > 0 });
    }

    for (const token of tokens) {
        switch (token.type) {
            case 'bullet_list_open':
                lists.push({ ordered: false, nextNumber: 0, marker: '- ', hasContent: false });
                break;
            case 'ordered_list_open': {
                const start = Number.parseInt(token.attrGet?.('start') ?? '1', 10);
                lists.push({
                    ordered: true,
                    nextNumber: Number.isFinite(start) ? start : 1,
                    marker: '',
                    hasContent: false,
                });
                break;
            }
            case 'bullet_list_close':
            case 'ordered_list_close':
                lists.pop();
                break;
            case 'list_item_open': {
                const level = lists[lists.length - 1];
                if (level) {
                    level.marker = level.ordered ? `${level.nextNumber++}. ` : '- ';
                    level.hasContent = false;
                }
                break;
            }
            case 'blockquote_open':
                quoteDepth++;
                break;
            case 'blockquote_close':
                quoteDepth = Math.max(0, quoteDepth - 1);
                break;
            case 'inline':
                emit(inlineCopyText(Array.isArray(token.children) ? token.children as MarkdownToken[] : []));
                break;
            case 'fence':
            case 'code_block':
                emit(typeof token.content === 'string' ? token.content : '');
                break;
            case 'hr':
                emit('---');
                break;
            default:
                break;
        }
    }

    return blocks.map((block, index) => {
        const previous = blocks[index - 1];
        const separator = index === 0 ? '' : block.compact && previous.compact ? '\n' : '\n\n';
        return separator + block.value;
    }).join('').trim();
}
