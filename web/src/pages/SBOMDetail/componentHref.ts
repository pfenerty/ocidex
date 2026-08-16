/** componentHref is the canonical link into the component overview page. */
export const componentHref = (name: string, group?: string, version?: string) => {
    const base = `/components/overview?name=${encodeURIComponent(name)}`;
    const g =
        group !== undefined && group !== ""
            ? `&group=${encodeURIComponent(group)}`
            : "";
    const v =
        version !== undefined && version !== ""
            ? `&version=${encodeURIComponent(version)}`
            : "";
    return `${base}${g}${v}`;
};
