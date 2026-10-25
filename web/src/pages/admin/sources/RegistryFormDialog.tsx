import { For, Show, createEffect, createSignal, onCleanup } from "solid-js";
import { Button, Card, CheckboxField, FormField, Modal } from "~/components/ui";
import { useToast } from "~/context/toast";
import type { Registry } from "~/api/client";
import {
    useCreateRegistry,
    useUpdateRegistry,
    useTestRegistryConnection,
    useGetSystemStatus,
    usePreviewRegistryConfig,
    useRegistryPreview,
    type RegistryPreviewBody,
} from "~/api/queries";
import {
    SCOPE_PRESETS,
    TYPE_CAPS,
    emptyForm,
    presetFor,
    scopeWarning,
    toPatternArray,
    type RegType,
    type RegistryFormState,
    type ScanMode,
    type ScopePreset,
    type TagOrder,
    type VerificationMode,
    type Visibility,
} from "./registryTypes";

/** Imperative handle — the dialog is opened by the table's Edit/Add buttons. */
export interface RegistryDialogHandle {
    /**
     * `prefill` seeds the form for callers that already know something about
     * the registry being added — a deep link from the cluster Gaps tab carries
     * the host of an image nothing is configured for.
     */
    openAdd: (prefill?: Partial<RegistryFormState>) => void;
    openEdit: (reg: Registry) => void;
}

const monoInput = "w-full text-[0.85rem] [font-family:monospace]";

/** How long the form waits after the last keystroke before asking for a preview. */
const PREVIEW_DEBOUNCE_MS = 600;

/** previewBodyOf is the part of a form the scan window depends on. */
function previewBodyOf(f: RegistryFormState): RegistryPreviewBody {
    return {
        type: f.type, url: f.url.trim(), insecure: f.insecure,
        authUsername: f.authUsername.trim() || undefined, authToken: f.authToken.trim() || undefined,
        repositories: toPatternArray(f.repositories),
        repositoryPatterns: toPatternArray(f.repositoryPatterns),
        tagPatterns: toPatternArray(f.tagPatterns),
        includeUntagged: f.includeUntagged,
        tagLimit: f.tagLimit, tagOrder: f.tagOrder, maxTagAgeDays: f.maxTagAgeDays,
    };
}

export function RegistryFormDialog(props: {
    ref: (handle: RegistryDialogHandle) => void;
    /** Called with a freshly minted webhook secret, which is only shown once. */
    onSecretRevealed: (secret: string) => void;
}) {
    const createReg = useCreateRegistry();
    const updateReg = useUpdateRegistry();
    const testConn = useTestRegistryConnection();
    const statusQuery = useGetSystemStatus();
    const toast = useToast();

    const [form, setForm] = createSignal<RegistryFormState>(emptyForm());
    const [testResult, setTestResult] = createSignal<{ reachable: boolean; message: string } | null>(null);
    const [editingID, setEditingID] = createSignal<string | null>(null);
    const [editEnabled, setEditEnabled] = createSignal(true);
    const [editManagedRef, setEditManagedRef] = createSignal<string | null>(null);
    const [editHasAuth, setEditHasAuth] = createSignal(false);
    const [scopePreset, setScopePreset] = createSignal<ScopePreset>("releases");
    const [open, setOpen] = createSignal(false);

    // The preview dials the registry, so it waits for typing to stop. An edit
    // of a registry with stored credentials previews the saved config instead
    // (the API never returns the token, so the form cannot send it) until a
    // new token is typed.
    const [previewBody, setPreviewBody] = createSignal<RegistryPreviewBody | undefined>(undefined);
    const usesSavedPreview = () => editingID() !== null && editHasAuth() && form().authToken.trim() === "";
    createEffect(() => {
        const f = form();
        const ready = open() && !editingManaged() && !usesSavedPreview() && f.url.trim() !== "";
        const t = setTimeout(() => setPreviewBody(ready ? previewBodyOf(f) : undefined), PREVIEW_DEBOUNCE_MS);
        onCleanup(() => clearTimeout(t));
    });
    const unsavedPreview = usePreviewRegistryConfig(previewBody);
    const savedPreview = useRegistryPreview(() => (open() && usesSavedPreview() ? (editingID() ?? undefined) : undefined));
    const preview = () => (usesSavedPreview() ? savedPreview : unsavedPreview);
    const warning = () => scopeWarning(form().tagLimit, preview().data?.estimatedSboms);

    function applyPreset(p: ScopePreset) {
        setScopePreset(p);
        if (p !== "custom") setForm(f => ({ ...f, ...SCOPE_PRESETS[p].fields }));
    }

    // An external controller reconciles its own spec over whatever is stored, so
    // a save here would be reverted within seconds. Locking the form is more
    // honest than accepting an edit that silently disappears.
    const editingManaged = () => editingID() !== null && editManagedRef() !== null;

    const showPollOptions = () =>
        statusQuery.data?.scanner.pollerEnabled === true ||
        (editingID() !== null && (form().scanMode === "poll" || form().scanMode === "both"));

    let dialogRef: HTMLDialogElement | undefined;

    function reset() {
        setForm(emptyForm());
        setEditingID(null);
        setEditEnabled(true);
        setEditManagedRef(null);
        setEditHasAuth(false);
        setScopePreset("releases");
        setTestResult(null);
        setOpen(false);
    }

    // A one-shot imperative handle, like a native `ref` callback: the parent
    // holds it for the lifetime of this component, so handing it over once at
    // setup is exactly the intent.
    // eslint-disable-next-line solid/reactivity
    props.ref({
        openAdd: (prefill) => {
            reset();
            if (prefill !== undefined) setForm((f) => ({ ...f, ...prefill }));
            setScopePreset(presetFor(form()));
            setOpen(true);
            dialogRef?.showModal();
        },
        openEdit: (reg) => {
            setEditingID(reg.id);
            setEditEnabled(reg.enabled);
            // Fall back to the owner name when the ref is absent, so the dialog can
            // always say *something* about who owns a marked registry.
            const owner = reg.managedBy ?? "";
            setEditManagedRef(owner === "" ? null : (reg.managedRef ?? owner));
            setEditHasAuth(reg.hasAuth);
            setForm({
                name: reg.name,
                // Not shown when editing: the update endpoint cannot move a
                // registry, and RegistryResponse does not carry the namespace
                // back, so a field here could only be blank or a lie.
                namespace: "",
                type: reg.type as RegType,
                url: reg.url,
                insecure: reg.insecure,
                authUsername: "",
                authToken: "",
                repositories: (reg.repositories ?? []).join("\n"),
                repositoryPatterns: (reg.repositoryPatterns ?? []).join("\n"),
                tagPatterns: (reg.tagPatterns ?? []).join("\n"),
                scanMode: reg.scanMode as ScanMode,
                pollIntervalMinutes: reg.pollIntervalMinutes,
                visibility: reg.visibility as Visibility,
                includeUntagged: reg.includeUntagged,
                verificationMode: ["public_key", "keyless"].includes(reg.verificationMode)
                    ? reg.verificationMode
                    : "none",
                trustPublicKey: reg.trustPublicKey ?? "",
                trustIdentity: reg.trustIdentity ?? "",
                trustIssuer: reg.trustIssuer ?? "",
                tagLimit: reg.tagLimit,
                tagOrder: reg.tagOrder,
                maxTagAgeDays: reg.maxTagAgeDays,
            });
            setScopePreset(presetFor(form()));
            setOpen(true);
            dialogRef?.showModal();
        },
    });

    function handleSubmit(e: Event) {
        e.preventDefault();
        const f = form();
        const authUsername = f.authUsername.trim() || undefined;
        const authToken = f.authToken.trim() || undefined;

        const repos = toPatternArray(f.repositories);
        const repoPats = toPatternArray(f.repositoryPatterns);
        const tagPats = toPatternArray(f.tagPatterns);

        const currentID = editingID();
        const trustPublicKey = f.verificationMode === "public_key" ? (f.trustPublicKey.trim() || undefined) : undefined;
        const trustIdentity = f.verificationMode === "keyless" ? (f.trustIdentity.trim() || undefined) : undefined;
        const trustIssuer = f.verificationMode === "keyless" ? (f.trustIssuer.trim() || undefined) : undefined;

        const shared = {
            name: f.name, type: f.type, url: f.url, insecure: f.insecure,
            authUsername, authToken,
            repositories: repos, repositoryPatterns: repoPats, tagPatterns: tagPats,
            scanMode: f.scanMode, pollIntervalMinutes: f.pollIntervalMinutes,
            visibility: f.visibility, includeUntagged: f.includeUntagged,
            verificationMode: f.verificationMode, trustPublicKey,
            trustIdentity, trustIssuer,
            tagLimit: f.tagLimit, tagOrder: f.tagOrder, maxTagAgeDays: f.maxTagAgeDays,
        };

        // Create only. The update endpoint takes no namespace: moving a
        // registry would silently change who can see everything under it.
        const namespace = f.namespace.trim() || undefined;

        if (currentID !== null) {
            updateReg.mutate(
                { id: currentID, enabled: editEnabled(), ...shared },
                {
                    onSuccess: () => { toast("Registry updated", "success"); dialogRef?.close(); },
                    onError: () => toast("Failed to update registry", "error"),
                }
            );
        } else {
            createReg.mutate({ ...shared, namespace }, {
                onSuccess: (data) => {
                    toast("Registry created", "success");
                    dialogRef?.close();
                    if (data.webhookSecret !== undefined) {
                        props.onSecretRevealed(data.webhookSecret);
                    }
                },
                onError: () => toast("Failed to create registry", "error"),
            });
        }
    }

    return (
        <Modal
            ref={(el) => (dialogRef = el)}
            title={editingID() !== null ? "Edit Registry" : "Add Registry"}
            onClose={reset}
        >
            <Show when={editingManaged()}>
                <Card
                    tone="warning"
                    data-testid="managed-notice"
                    class="mb-3 text-[0.85rem]"
                >
                    This registry is configured by Kubernetes
                    (<code>{editManagedRef()}</code>). Its settings are reconciled from
                    the <code>OCIRegistry</code> resource, so changes saved here would be
                    overwritten. Edit the resource instead.
                </Card>
            </Show>
            <form onSubmit={handleSubmit}>
                <fieldset disabled={editingManaged()} class="m-0 border-none p-0">
                    <div class="mb-3 grid grid-cols-[1fr_1fr] gap-3">
                        <FormField label="Name">
                            <input
                                type="text"
                                value={form().name}
                                onInput={(e) => setForm(f => ({ ...f, name: e.currentTarget.value }))}
                                placeholder="my-registry"
                                class="w-full"
                                required
                            />
                        </FormField>
                        {/* Create only. Registry resolution is namespace-local
                            — a cluster only ever sees registries in its own
                            namespace — so this is the field that decides
                            whether the registry is any use to the caller, and
                            the deep link from a cluster gap sets it. */}
                        <Show when={editingID() === null}>
                            <FormField label="Namespace" hint="created on first use; blank gives the registry a namespace of its own">
                                <input
                                    type="text"
                                    value={form().namespace}
                                    onInput={(e) => setForm(f => ({ ...f, namespace: e.currentTarget.value }))}
                                    placeholder="leave blank for a namespace of its own"
                                    class="w-full"
                                />
                            </FormField>
                        </Show>
                        <FormField label="Type">
                            <select
                                value={form().type}
                                onChange={(e) => {
                                    const newType = e.currentTarget.value as RegType;
                                    const caps = TYPE_CAPS[newType];
                                    setForm(f => ({
                                        ...f,
                                        type: newType,
                                        url: caps.fixedUrl ?? (newType === f.type ? f.url : ""),
                                        scanMode: !caps.webhook ? "poll" : f.scanMode,
                                        includeUntagged: caps.untagged ? f.includeUntagged : false,
                                    }));
                                }}
                                class="w-full"
                            >
                                <For each={Object.entries(TYPE_CAPS) as [RegType, typeof TYPE_CAPS[RegType]][]}>{([type, caps]) => (
                                    <option value={type}>{caps.label}</option>
                                )}</For>
                            </select>
                        </FormField>
                        <FormField label="URL">
                            <div class="flex gap-[0.4rem]">
                                <input
                                    type="text"
                                    value={form().url}
                                    onInput={(e) => { setForm(f => ({ ...f, url: e.currentTarget.value })); setTestResult(null); }}
                                    placeholder="registry:5000"
                                    class="flex-1"
                                    classList={{ "cursor-not-allowed bg-[var(--color-surface-hover)]": TYPE_CAPS[form().type].fixedUrl !== null }}
                                    readOnly={TYPE_CAPS[form().type].fixedUrl !== null}
                                    required
                                />
                                <Button
                                    type="button"
                                    disabled={testConn.isPending || !form().url.trim()}
                                    onClick={() => {
                                        setTestResult(null);
                                        testConn.mutate(
                                            { url: form().url.trim(), insecure: form().insecure, authUsername: form().authUsername.trim() || undefined, authToken: form().authToken.trim() || undefined },
                                            { onSuccess: (data) => setTestResult(data) }
                                        );
                                    }}
                                >
                                    {testConn.isPending ? "Testing…" : "Test"}
                                </Button>
                            </div>
                            <Show when={testResult()}>
                                <div class={`mt-[0.3rem] text-[0.8rem] ${testResult()?.reachable === true ? "text-[var(--color-success)]" : "text-[var(--color-danger)]"}`}>
                                    {testResult()?.reachable === true ? "✓" : "✗"} {testResult()?.message}
                                </div>
                            </Show>
                        </FormField>
                        <FormField label="Auth Username" hint="(optional; for registries requiring credentials)">
                            <input
                                type="text"
                                value={form().authUsername}
                                onInput={(e) => setForm(f => ({ ...f, authUsername: e.currentTarget.value }))}
                                placeholder={editingID() !== null ? "Leave blank to keep existing" : "Leave blank for anonymous"}
                                class="w-full"
                            />
                        </FormField>
                        <FormField label="Auth Token" hint="(PAT or password; for registries requiring credentials)">
                            <input
                                type="password"
                                value={form().authToken}
                                onInput={(e) => setForm(f => ({ ...f, authToken: e.currentTarget.value }))}
                                placeholder={editingID() !== null ? "Leave blank to keep existing" : "Leave blank for anonymous"}
                                class="w-full"
                            />
                        </FormField>
                        <FormField
                            label="Repositories"
                            hintEmphasis={form().type === "ghcr"}
                            hint={form().type === "ghcr"
                                ? "(required for ghcr.io — catalog discovery is not supported)"
                                : "(one per line; bypasses catalog discovery — required for ghcr.io, quay.io)"}
                        >
                            <textarea
                                value={form().repositories}
                                onInput={(e) => setForm(f => ({ ...f, repositories: e.currentTarget.value }))}
                                placeholder={form().type === "ghcr" ? "my-org/my-image\nmy-org/other-image" : "buildah/buildah\nbuildah/buildah-testing"}
                                rows={3}
                                class={monoInput}
                            />
                        </FormField>
                        <FormField label="Repository Patterns" hint="(one per line; filters catalog-discovered repos; empty = all)">
                            <textarea
                                value={form().repositoryPatterns}
                                onInput={(e) => setForm(f => ({ ...f, repositoryPatterns: e.currentTarget.value }))}
                                placeholder={"my/project/**\nmy/other/app"}
                                rows={3}
                                class={monoInput}
                            />
                        </FormField>
                        <FormField label="Scan scope" hint={scopePreset() === "custom" ? "(tags and window below)" : `(${SCOPE_PRESETS[scopePreset() as Exclude<ScopePreset, "custom">].hint})`}>
                            <select
                                data-testid="scope-preset"
                                value={scopePreset()}
                                onChange={(e) => applyPreset(e.currentTarget.value as ScopePreset)}
                                class="w-full"
                            >
                                <For each={Object.entries(SCOPE_PRESETS)}>{([name, p]) => (
                                    <option value={name}>{p.label}</option>
                                )}</For>
                                <option value="custom">Custom</option>
                            </select>
                        </FormField>
                        <Show when={scopePreset() === "custom"}>
                            <FormField label="Tag Patterns" hint={'(one per line; "semver" for semantic versions; empty = all)'}>
                                <textarea
                                    value={form().tagPatterns}
                                    onInput={(e) => setForm(f => ({ ...f, tagPatterns: e.currentTarget.value }))}
                                    placeholder={"semver\nlatest"}
                                    rows={3}
                                    class={monoInput}
                                />
                            </FormField>
                            <FormField label="Tag order" hint="(which tags count as newest)">
                                <select
                                    value={form().tagOrder}
                                    onChange={(e) => {
                                        const tagOrder = e.currentTarget.value as TagOrder;
                                        setForm(f => ({ ...f, tagOrder, maxTagAgeDays: tagOrder === "created" || tagOrder === "auto" ? f.maxTagAgeDays : 0 }));
                                    }}
                                    class="w-full"
                                >
                                    <option value="auto">Auto (semver if the patterns say so, else build date)</option>
                                    <option value="semver">Semantic version</option>
                                    <option value="created">Build date</option>
                                    <option value="lexical">Tag name (A→Z)</option>
                                </select>
                            </FormField>
                            <FormField label="Tags per repository" hint="(newest kept; 0 = unlimited)">
                                <input
                                    type="number"
                                    min={0}
                                    value={form().tagLimit}
                                    onInput={(e) => setForm(f => ({ ...f, tagLimit: Math.max(0, parseInt(e.currentTarget.value, 10) || 0) }))}
                                    class="w-full"
                                />
                            </FormField>
                            <FormField label="Max tag age (days)" hint="(build-date order only; 0 = no limit)">
                                <input
                                    type="number"
                                    min={0}
                                    value={form().maxTagAgeDays}
                                    disabled={form().tagOrder !== "created" && !(form().tagOrder === "auto" && !toPatternArray(form().tagPatterns).includes("semver"))}
                                    onInput={(e) => setForm(f => ({ ...f, maxTagAgeDays: Math.max(0, parseInt(e.currentTarget.value, 10) || 0) }))}
                                    class="w-full"
                                />
                            </FormField>
                        </Show>
                        <FormField label="Scan Mode">
                            <select
                                value={form().scanMode}
                                onChange={(e) => setForm(f => ({ ...f, scanMode: e.currentTarget.value as ScanMode }))}
                                class="w-full"
                                disabled={!TYPE_CAPS[form().type].webhook}
                            >
                                <Show when={TYPE_CAPS[form().type].webhook}>
                                    <option value="webhook">Webhook</option>
                                </Show>
                                <option value="poll">Poll</option>
                                <Show when={TYPE_CAPS[form().type].webhook}>
                                    <option value="both">Both</option>
                                </Show>
                            </select>
                            <Show when={!TYPE_CAPS[form().type].webhook && !showPollOptions()}>
                                <div class="mt-[0.3rem] text-[0.8rem] text-[var(--color-danger)]">
                                    Requires REGISTRY_POLLER_ENABLED=true — this registry type only supports polling.
                                </div>
                            </Show>
                        </FormField>
                        <FormField label="Visibility">
                            <select
                                value={form().visibility}
                                onChange={(e) => setForm(f => ({ ...f, visibility: e.currentTarget.value as Visibility }))}
                                class="w-full"
                            >
                                <option value="public">Public</option>
                                <option value="private">Private</option>
                            </select>
                        </FormField>
                        <Show when={form().scanMode !== "webhook"}>
                            <FormField label="Poll Interval (minutes)">
                                <input
                                    type="number"
                                    min={1}
                                    value={form().pollIntervalMinutes}
                                    onInput={(e) => setForm(f => ({ ...f, pollIntervalMinutes: parseInt(e.currentTarget.value, 10) || 60 }))}
                                    class="w-full"
                                />
                            </FormField>
                        </Show>
                        <FormField label="Verification Mode">
                            <select
                                value={form().verificationMode}
                                onChange={(e) => setForm(f => ({
                                    ...f,
                                    verificationMode: e.currentTarget.value as VerificationMode,
                                    trustPublicKey: e.currentTarget.value !== "public_key" ? "" : f.trustPublicKey,
                                    trustIdentity: e.currentTarget.value !== "keyless" ? "" : f.trustIdentity,
                                    trustIssuer: e.currentTarget.value !== "keyless" ? "" : f.trustIssuer,
                                }))}
                                class="w-full"
                            >
                                <option value="none">None</option>
                                <option value="public_key">Public Key</option>
                                <option value="keyless">Keyless (Fulcio/Rekor)</option>
                            </select>
                        </FormField>
                        <Show when={form().verificationMode === "public_key"}>
                            <FormField label="Trust Public Key (PEM)" fullWidth>
                                <textarea
                                    value={form().trustPublicKey}
                                    onInput={(e) => setForm(f => ({ ...f, trustPublicKey: e.currentTarget.value }))}
                                    rows={6}
                                    placeholder={"-----BEGIN PUBLIC KEY-----\n..."}
                                    class={monoInput}
                                />
                            </FormField>
                        </Show>
                        <Show when={form().verificationMode === "keyless"}>
                            <FormField label="Trust Identity (SAN regex)">
                                <input
                                    type="text"
                                    value={form().trustIdentity}
                                    onInput={(e) => setForm(f => ({ ...f, trustIdentity: e.currentTarget.value }))}
                                    placeholder="https://github.com/org/repo/.*"
                                    class={monoInput}
                                />
                            </FormField>
                            <FormField label="Trust Issuer">
                                <input
                                    type="text"
                                    value={form().trustIssuer}
                                    onInput={(e) => setForm(f => ({ ...f, trustIssuer: e.currentTarget.value }))}
                                    placeholder="https://token.actions.githubusercontent.com"
                                    class={monoInput}
                                />
                            </FormField>
                        </Show>
                    </div>
                    <div class="mb-3 flex items-center gap-4">
                        <CheckboxField
                            label="Allow insecure (HTTP)"
                            checked={form().insecure}
                            onChange={(checked) => setForm(f => ({ ...f, insecure: checked }))}
                        />
                        <CheckboxField
                            label="Include untagged manifests"
                            checked={form().includeUntagged}
                            disabled={!TYPE_CAPS[form().type].untagged}
                            onChange={(checked) => setForm(f => ({ ...f, includeUntagged: checked }))}
                        />
                        <Show when={editingID() !== null}>
                            <CheckboxField label="Enabled" checked={editEnabled()} onChange={setEditEnabled} />
                        </Show>
                    </div>
                    <div data-testid="scope-preview" class="mb-3 text-[0.85rem]">
                        <Show
                            when={preview().data}
                            fallback={
                                <span class="text-[var(--color-text-muted)]">
                                    {preview().isFetching
                                        ? "Checking what this would scan…"
                                        : preview().isError
                                            ? `Preview unavailable: ${preview().error?.message ?? "the registry could not be read"}`
                                            : "Enter a URL to see what this would scan."}
                                </span>
                            }
                        >
                            {(p) => (
                                <span>
                                    Will scan <strong>~{p().estimatedSboms.toLocaleString()}</strong> images
                                    ({p().selected.toLocaleString()} tags across {(p().repositories ?? []).length} repositories
                                    {p().skippedByLimit > 0 ? `; ${p().skippedByLimit.toLocaleString()} older tags left out` : ""})
                                    {usesSavedPreview() ? " — saved settings; enter the token to preview edits" : ""}
                                </span>
                            )}
                        </Show>
                    </div>
                    <Show when={warning()}>
                        {(w) => (
                            <Card tone="warning" data-testid="scope-warning" class="mb-3 text-[0.85rem]">
                                {w()}
                            </Card>
                        )}
                    </Show>
                </fieldset>
                <div class="flex gap-2">
                    <Button variant="primary" type="submit" disabled={createReg.isPending || updateReg.isPending || editingManaged()}>
                        {editingID() !== null ? "Save" : "Create"}
                    </Button>
                    <Button type="button" onClick={() => dialogRef?.close()}>
                        Cancel
                    </Button>
                </div>
            </form>
        </Modal>
    );
}
