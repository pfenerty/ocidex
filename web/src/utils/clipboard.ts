/**
 * Copy text to clipboard. Uses the modern Clipboard API when available
 * (requires secure context / HTTPS), with a textarea execCommand fallback
 * for plain HTTP.
 */
export async function copyText(text: string): Promise<void> {
    const clipboard = navigator.clipboard as Clipboard | undefined;
    if (clipboard !== undefined) {
        await clipboard.writeText(text);
        return;
    }
    const el = document.createElement("textarea");
    el.value = text;
    el.style.position = "fixed";
    el.style.opacity = "0";
    document.body.appendChild(el);
    el.focus();
    el.select();
    const ok = document.execCommand("copy");
    document.body.removeChild(el);
    if (!ok) throw new Error("execCommand copy failed");
}
