import type { ReactNode } from 'react';

// Report text is always rendered through React. HTML and unsupported Markdown
// remain text; no raw HTML, embedded media, or model reasoning fields are used.
function inline(text: string): ReactNode[] {
  return text.split(/(\*\*[^*]+\*\*|`[^`]+`|\[[^\]]+\]\(https?:\/\/[^\s)]+\))/g).map((part, index) => {
    if (part.startsWith('**') && part.endsWith('**')) return <strong key={index}>{part.slice(2, -2)}</strong>;
    if (part.startsWith('`') && part.endsWith('`')) return <code key={index}>{part.slice(1, -1)}</code>;
    const link = /^\[([^\]]+)\]\((https?:\/\/[^\s)]+)\)$/.exec(part);
    if (link) return <a key={index} href={link[2]} target="_blank" rel="noreferrer noopener">{link[1]}</a>;
    return part;
  });
}

export function IncidentDocument({ markdown }: { markdown: string }) {
  const blocks: ReactNode[] = [];
  const lines = markdown.replaceAll('\r\n', '\n').split('\n');
  let index = 0;
  while (index < lines.length) {
    const line = lines[index];
    const key = index;
    if (!line.trim()) { index += 1; continue; }
    if (/^```/.test(line)) {
      const code: string[] = [];
      index += 1;
      while (index < lines.length && !/^```/.test(lines[index])) code.push(lines[index++]);
      if (index < lines.length) index += 1;
      blocks.push(<pre key={key}><code>{code.join('\n')}</code></pre>);
      continue;
    }
    const heading = /^(#{1,6})\s+(.+)$/.exec(line);
    if (heading) {
      blocks.push(heading[1].length < 3 ? <h3 key={key}>{inline(heading[2])}</h3> : <h4 key={key}>{inline(heading[2])}</h4>);
      index += 1; continue;
    }
    if (/^\s*([-*_])(?:\s*\1){2,}\s*$/.test(line)) { blocks.push(<hr key={key}/>); index += 1; continue; }
    const list = /^\s*(?:[-*+]\s+|\d+[.)]\s+)/;
    if (list.test(line)) {
      const ordered = /^\s*\d+[.)]\s+/.test(line);
      const items: ReactNode[] = [];
      while (index < lines.length && list.test(lines[index]) && /^\s*\d+[.)]\s+/.test(lines[index]) === ordered) {
        items.push(<li key={index}>{inline(lines[index++].replace(list, ''))}</li>);
      }
      blocks.push(ordered ? <ol key={key}>{items}</ol> : <ul key={key}>{items}</ul>);
      continue;
    }
    const paragraph = [line];
    index += 1;
    while (index < lines.length && lines[index].trim() && !/^(#{1,6}\s|```)/.test(lines[index]) && !list.test(lines[index])) paragraph.push(lines[index++]);
    blocks.push(<p key={key}>{inline(paragraph.join('\n'))}</p>);
  }
  return <div className="cp-document">{blocks}</div>;
}
