import { ChangeDetectionStrategy, Component, computed, input } from '@angular/core';

type ReportBlock =
  | { type: 'heading'; text: string; level: number }
  | { type: 'paragraph' | 'quote' | 'code'; text: string }
  | { type: 'list'; items: string[]; ordered: boolean }
  | { type: 'table'; headers: string[]; rows: string[][] }
  | { type: 'rule' };

const inline = (value: string) => value
  .replace(/!\[([^\]]*)\]\([^)]*\)/g, '$1')
  .replace(/\[([^\]]+)\]\((https?:\/\/[^)]+)\)/g, '$1 — $2')
  .replace(/\*\*([^*]+)\*\*/g, '$1')
  .replace(/__([^_]+)__/g, '$1')
  .replace(/`([^`]+)`/g, '$1')
  .trim();

export function parseReportSummary(source: string): ReportBlock[] {
  const lines = source.replace(/\r/g, '').split('\n');
  const blocks: ReportBlock[] = [];
  let index = 0;
  while (index < lines.length) {
    const line = lines[index]!.trim();
    if (!line) { index += 1; continue; }
    if (/^```/.test(line)) {
      const code: string[] = []; index += 1;
      while (index < lines.length && !/^```/.test(lines[index]!.trim())) code.push(lines[index++]!);
      index += 1; blocks.push({ type: 'code', text: code.join('\n') }); continue;
    }
    const heading = line.match(/^(#{1,4})\s+(.+)$/);
    if (heading) { blocks.push({ type: 'heading', level: heading[1]!.length, text: inline(heading[2]!) }); index += 1; continue; }
    if (/^(?:---+|\*\*\*+)$/.test(line)) { blocks.push({ type: 'rule' }); index += 1; continue; }
    if (line.includes('|') && index + 1 < lines.length && /^\s*\|?\s*:?-{3,}/.test(lines[index + 1]!)) {
      const cells = (value: string) => value.replace(/^\||\|$/g, '').split('|').map((cell) => inline(cell));
      const headers = cells(line); const rows: string[][] = []; index += 2;
      while (index < lines.length && lines[index]!.includes('|') && lines[index]!.trim()) rows.push(cells(lines[index++]!));
      blocks.push({ type: 'table', headers, rows }); continue;
    }
    if (/^(?:[-*+]\s+)/.test(line)) {
      const items: string[] = [];
      while (index < lines.length && /^\s*[-*+]\s+/.test(lines[index]!)) items.push(inline(lines[index++]!.replace(/^\s*[-*+]\s+/, '')));
      blocks.push({ type: 'list', items, ordered: false }); continue;
    }
    if (/^\d+[.)]\s+/.test(line)) {
      const items: string[] = [];
      while (index < lines.length && /^\s*\d+[.)]\s+/.test(lines[index]!)) items.push(inline(lines[index++]!.replace(/^\s*\d+[.)]\s+/, '')));
      blocks.push({ type: 'list', items, ordered: true }); continue;
    }
    if (/^>\s?/.test(line)) {
      const values: string[] = [];
      while (index < lines.length && /^\s*>/.test(lines[index]!)) values.push(inline(lines[index++]!.replace(/^\s*>\s?/, '')));
      blocks.push({ type: 'quote', text: values.join(' ') }); continue;
    }
    const paragraph: string[] = [line]; index += 1;
    while (index < lines.length && lines[index]!.trim() && !/^(?:#{1,4}\s|```|[-*+]\s+|\d+[.)]\s+|>\s?|---+$)/.test(lines[index]!.trim())) {
      if (lines[index]!.includes('|') && index + 1 < lines.length && /^\s*\|?\s*:?-{3,}/.test(lines[index + 1]!)) break;
      paragraph.push(lines[index++]!.trim());
    }
    blocks.push({ type: 'paragraph', text: inline(paragraph.join(' ')) });
  }
  return blocks;
}

@Component({
  selector: 'wg-report-summary',
  template: `
    <div class="report-markdown">
      @for (block of blocks(); track $index) {
        @switch (block.type) {
          @case ('heading') { <h4 [attr.data-level]="block.level">{{ block.text }}</h4> }
          @case ('paragraph') { <p>{{ block.text }}</p> }
          @case ('quote') { <blockquote>{{ block.text }}</blockquote> }
          @case ('code') { <pre>{{ block.text }}</pre> }
          @case ('rule') { <hr> }
          @case ('list') {
            @if (block.ordered) { <ol>@for (item of block.items; track $index) { <li>{{ item }}</li> }</ol> }
            @else { <ul>@for (item of block.items; track $index) { <li>{{ item }}</li> }</ul> }
          }
          @case ('table') {
            <div class="report-table-wrap"><table><thead><tr>@for (cell of block.headers; track $index) { <th>{{ cell }}</th> }</tr></thead><tbody>@for (row of block.rows; track $index) { <tr>@for (cell of row; track $index) { <td>{{ cell }}</td> }</tr> }</tbody></table></div>
          }
        }
      }
    </div>
  `,
  changeDetection: ChangeDetectionStrategy.OnPush
})
export class ReportSummaryComponent {
  readonly text = input.required<string>();
  protected readonly blocks = computed(() => parseReportSummary(this.text()));
}
