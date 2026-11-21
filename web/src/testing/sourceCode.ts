import ts from "typescript";

/**
 * TS/TSX source with its comments removed, for the contract tests that read
 * source text. It parses the file with TypeScript, so a `//` inside a string,
 * a template or JSX text ("https://…") is kept. The regex these tests used
 * before deleted the rest of the line after any URL, so a class name after one
 * went unchecked. A bare scanner isn't enough either: without the parser it
 * reads an apostrophe in JSX text as the start of a string.
 *
 * Each comment becomes a space (or just its newlines, if it spans lines), so
 * line structure and token boundaries survive.
 */
export function stripComments(source: string, fileName = "file.tsx"): string {
    const kind = fileName.endsWith(".tsx") || fileName.endsWith(".jsx") ? ts.ScriptKind.TSX : ts.ScriptKind.TS;
    const sf = ts.createSourceFile(fileName, source, ts.ScriptTarget.Latest, true, kind);
    const ranges = new Map<number, number>();
    const add = (rs: ts.CommentRange[] | undefined) => {
        for (const r of rs ?? []) ranges.set(r.pos, r.end);
    };
    const visit = (node: ts.Node) => {
        // JSX text carries no trivia: a "//" in it is text, not a comment.
        if (node.kind !== ts.SyntaxKind.JsxText) {
            add(ts.getLeadingCommentRanges(source, node.pos));
            add(ts.getTrailingCommentRanges(source, node.end));
        }
        for (const child of node.getChildren(sf)) visit(child);
    };
    visit(sf);

    let out = "";
    let at = 0;
    for (const pos of [...ranges.keys()].sort((a, b) => a - b)) {
        if (pos < at) continue;
        const end = ranges.get(pos) ?? pos;
        const newlines = source.slice(pos, end).replace(/[^\n]/g, "");
        out += source.slice(at, pos) + (newlines === "" ? " " : newlines);
        at = end;
    }
    return out + source.slice(at);
}
