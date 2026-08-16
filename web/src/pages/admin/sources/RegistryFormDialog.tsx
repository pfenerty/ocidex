import { For, Show, createSignal } from "solid-js";
import { CheckboxField, FormField, Modal } from "~/components/ui";
import { useToast } from "~/context/toast";
import type { Registry } from "~/api/client";
import {
    useCreateRegistry,
    useUpdateRegistry,
    useTestRegistryConnection,
    useGetSystemStatus,
} from "~/api/queries";
import {
    TYPE_CAPS,
    emptyForm,
    toPatternArray,
    type RegType,
    type RegistryFormState,
    type ScanMode,
    type VerificationMode,
    type Visibility,
} from "./registryTypes";

/** Imperative handle — the dialog is opened by the table's Edit/Add buttons. */
export interface RegistryDialogHandle {
    openAdd: () => void;
    openEdit: (reg: Registry) => void;
}

const monoInput = { width: "100%", "font-family": "monospace", "font-size": "0.85rem" };

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

    // An external controller reconciles its own spec over whatever is stored, so
    // a save here would be reverted within seconds. Locking the form is more
    // honest than accepting an edit that silently disappears.
    const editingManaged = () => editingID() !== null && editManagedRef() !== null;

    const showPollOptions = () =>
        statusQuery.data?.scanner.poller_enabled === true ||
        (editingID() !== null && (form().scanMode === "poll" || form().scanMode === "both"));

    let dialogRef: HTMLDialogElement | undefined;

    function reset() {
        setForm(emptyForm());
        setEditingID(null);
        setEditEnabled(true);
        setEditManagedRef(null);
        setTestResult(null);
    }

    // A one-shot imperative handle, like a native `ref` callback: the parent
    // holds it for the lifetime of this component, so handing it over once at
    // setup is exactly the intent.
    // eslint-disable-next-line solid/reactivity
    props.ref({
        openAdd: () => {
            reset();
            dialogRef?.showModal();
        },
        openEdit: (reg) => {
            setEditingID(reg.id);
            setEditEnabled(reg.enabled);
            // Fall back to the owner name when the ref is absent, so the dialog can
            // always say *something* about who owns a marked registry.
            const owner = reg.managed_by ?? "";
            setEditManagedRef(owner === "" ? null : (reg.managed_ref ?? owner));
            setForm({
                name: reg.name,
                type: reg.type as RegType,
                url: reg.url,
                insecure: reg.insecure,
                authUsername: "",
                authToken: "",
                repositories: (reg.repositories ?? []).join("\n"),
                repositoryPatterns: (reg.repository_patterns ?? []).join("\n"),
                tagPatterns: (reg.tag_patterns ?? []).join("\n"),
                scanMode: reg.scan_mode as ScanMode,
                pollIntervalMinutes: reg.poll_interval_minutes,
                visibility: reg.visibility as Visibility,
                includeUntagged: reg.include_untagged,
                verificationMode: ["public_key", "keyless"].includes(reg.verification_mode)
                    ? reg.verification_mode
                    : "none",
                trustPublicKey: reg.trust_public_key ?? "",
                trustIdentity: reg.trust_identity ?? "",
                trustIssuer: reg.trust_issuer ?? "",
            });
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
            auth_username: authUsername, auth_token: authToken,
            repositories: repos, repository_patterns: repoPats, tag_patterns: tagPats,
            scan_mode: f.scanMode, poll_interval_minutes: f.pollIntervalMinutes,
            visibility: f.visibility, include_untagged: f.includeUntagged,
            verification_mode: f.verificationMode, trust_public_key: trustPublicKey,
            trust_identity: trustIdentity, trust_issuer: trustIssuer,
        };

        if (currentID !== null) {
            updateReg.mutate(
                { id: currentID, enabled: editEnabled(), ...shared },
                {
                    onSuccess: () => { toast("Registry updated", "success"); dialogRef?.close(); },
                    onError: () => toast("Failed to update registry", "error"),
                }
            );
        } else {
            createReg.mutate(shared, {
                onSuccess: (data) => {
                    toast("Registry created", "success");
                    dialogRef?.close();
                    if (data.webhook_secret !== undefined) {
                        props.onSecretRevealed(data.webhook_secret);
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
                <div
                    class="card"
                    data-testid="managed-notice"
                    style={{ "border-color": "var(--color-warning, #d69e2e)", "margin-bottom": "0.75rem", "font-size": "0.85rem" }}
                >
                    This registry is configured by Kubernetes
                    (<code>{editManagedRef()}</code>). Its settings are reconciled from
                    the <code>OCIRegistry</code> resource, so changes saved here would be
                    overwritten. Edit the resource instead.
                </div>
            </Show>
            <form onSubmit={handleSubmit}>
                <fieldset disabled={editingManaged()} style={{ border: "none", padding: "0", margin: "0" }}>
                    <div style={{ display: "grid", "grid-template-columns": "1fr 1fr", gap: "0.75rem", "margin-bottom": "0.75rem" }}>
                        <FormField label="Name">
                            <input
                                type="text"
                                value={form().name}
                                onInput={(e) => setForm(f => ({ ...f, name: e.currentTarget.value }))}
                                placeholder="my-registry"
                                style={{ width: "100%" }}
                                required
                            />
                        </FormField>
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
                                style={{ width: "100%" }}
                            >
                                <For each={Object.entries(TYPE_CAPS) as [RegType, typeof TYPE_CAPS[RegType]][]}>{([type, caps]) => (
                                    <option value={type}>{caps.label}</option>
                                )}</For>
                            </select>
                        </FormField>
                        <FormField label="URL">
                            <div style={{ display: "flex", gap: "0.4rem" }}>
                                <input
                                    type="text"
                                    value={form().url}
                                    onInput={(e) => { setForm(f => ({ ...f, url: e.currentTarget.value })); setTestResult(null); }}
                                    placeholder="registry:5000"
                                    style={{ flex: "1", ...(TYPE_CAPS[form().type].fixedUrl !== null ? { background: "var(--color-surface-2, #f0f0f0)", cursor: "not-allowed" } : {}) }}
                                    readOnly={TYPE_CAPS[form().type].fixedUrl !== null}
                                    required
                                />
                                <button
                                    type="button"
                                    class="btn"
                                    disabled={testConn.isPending || !form().url.trim()}
                                    onClick={() => {
                                        setTestResult(null);
                                        testConn.mutate(
                                            { url: form().url.trim(), insecure: form().insecure, auth_username: form().authUsername.trim() || undefined, auth_token: form().authToken.trim() || undefined },
                                            { onSuccess: (data) => setTestResult(data) }
                                        );
                                    }}
                                >
                                    {testConn.isPending ? "Testing…" : "Test"}
                                </button>
                            </div>
                            <Show when={testResult()}>
                                <div style={{
                                    "margin-top": "0.3rem",
                                    "font-size": "0.8rem",
                                    color: testResult()?.reachable === true ? "var(--color-success)" : "var(--color-error, #e53e3e)",
                                }}>
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
                                style={{ width: "100%" }}
                            />
                        </FormField>
                        <FormField label="Auth Token" hint="(PAT or password; for registries requiring credentials)">
                            <input
                                type="password"
                                value={form().authToken}
                                onInput={(e) => setForm(f => ({ ...f, authToken: e.currentTarget.value }))}
                                placeholder={editingID() !== null ? "Leave blank to keep existing" : "Leave blank for anonymous"}
                                style={{ width: "100%" }}
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
                                style={monoInput}
                            />
                        </FormField>
                        <FormField label="Repository Patterns" hint="(one per line; filters catalog-discovered repos; empty = all)">
                            <textarea
                                value={form().repositoryPatterns}
                                onInput={(e) => setForm(f => ({ ...f, repositoryPatterns: e.currentTarget.value }))}
                                placeholder={"my/project/**\nmy/other/app"}
                                rows={3}
                                style={monoInput}
                            />
                        </FormField>
                        <FormField label="Tag Patterns" hint={'(one per line; "semver" for semantic versions; empty = all)'}>
                            <textarea
                                value={form().tagPatterns}
                                onInput={(e) => setForm(f => ({ ...f, tagPatterns: e.currentTarget.value }))}
                                placeholder={"semver\nlatest"}
                                rows={3}
                                style={monoInput}
                            />
                        </FormField>
                        <FormField label="Scan Mode">
                            <select
                                value={form().scanMode}
                                onChange={(e) => setForm(f => ({ ...f, scanMode: e.currentTarget.value as ScanMode }))}
                                style={{ width: "100%" }}
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
                                <div style={{ "margin-top": "0.3rem", "font-size": "0.8rem", color: "var(--color-error, #e53e3e)" }}>
                                    Requires REGISTRY_POLLER_ENABLED=true — this registry type only supports polling.
                                </div>
                            </Show>
                        </FormField>
                        <FormField label="Visibility">
                            <select
                                value={form().visibility}
                                onChange={(e) => setForm(f => ({ ...f, visibility: e.currentTarget.value as Visibility }))}
                                style={{ width: "100%" }}
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
                                    style={{ width: "100%" }}
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
                                style={{ width: "100%" }}
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
                                    style={monoInput}
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
                                    style={monoInput}
                                />
                            </FormField>
                            <FormField label="Trust Issuer">
                                <input
                                    type="text"
                                    value={form().trustIssuer}
                                    onInput={(e) => setForm(f => ({ ...f, trustIssuer: e.currentTarget.value }))}
                                    placeholder="https://token.actions.githubusercontent.com"
                                    style={monoInput}
                                />
                            </FormField>
                        </Show>
                    </div>
                    <div style={{ display: "flex", gap: "1rem", "align-items": "center", "margin-bottom": "0.75rem" }}>
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
                </fieldset>
                <div style={{ display: "flex", gap: "0.5rem" }}>
                    <button class="btn btn-primary" type="submit" disabled={createReg.isPending || updateReg.isPending || editingManaged()}>
                        {editingID() !== null ? "Save" : "Create"}
                    </button>
                    <button class="btn" type="button" onClick={() => dialogRef?.close()}>
                        Cancel
                    </button>
                </div>
            </form>
        </Modal>
    );
}
