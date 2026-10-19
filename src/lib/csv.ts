export function parseCsv(text: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let field = "";
  let quoted = false;

  for (let i = 0; i < text.length; i += 1) {
    const char = text[i];
    if (quoted) {
      if (char === '"') {
        if (text[i + 1] === '"') {
          field += '"';
          i += 1;
        } else {
          quoted = false;
        }
      } else {
        field += char;
      }
      continue;
    }
    if (char === '"') {
      quoted = true;
    } else if (char === ",") {
      row.push(field.trim());
      field = "";
    } else if (char === "\n") {
      row.push(field.trim());
      if (row.some((cell) => cell.length > 0)) rows.push(row);
      row = [];
      field = "";
    } else if (char !== "\r") {
      field += char;
    }
  }

  if (field.length > 0 || row.length > 0) {
    row.push(field.trim());
    if (row.some((cell) => cell.length > 0)) rows.push(row);
  }
  return rows;
}

export function stripHashComments(text: string): { body: string; comments: string[] } {
  const comments: string[] = [];
  const kept: string[] = [];
  for (const line of text.split(/\r?\n/)) {
    if (line.startsWith("#")) comments.push(line);
    else kept.push(line);
  }
  return { body: kept.join("\n"), comments };
}

export function headerFromComments(comments: string[], marker: string): string[] | null {
  const line = comments.find((comment) => comment.toLowerCase().includes(marker.toLowerCase()));
  if (!line) return null;
  const parsed = parseCsv(line.replace(/^#\s?/, ""));
  return parsed[0]?.map((cell) => cell.replace(/^"|"$/g, "").trim()) ?? null;
}

export function blankToNull(value: string | undefined): string | null {
  if (value == null) return null;
  const trimmed = value.trim();
  if (!trimmed || trimmed.toLowerCase() === "none" || trimmed.toLowerCase() === "null") return null;
  return trimmed;
}

export function rowObject(header: string[], row: string[]): Record<string, string> {
  const out: Record<string, string> = {};
  header.forEach((key, index) => {
    out[key] = row[index] ?? "";
  });
  return out;
}
