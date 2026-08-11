// Free-tier starter policies (BR-11): flight-recorder defaults, monitor mode.
// Nothing in this build blocks (ADR-3). enforce_action is the graduation knob
// (ADR-14): flipping one to "block" makes the record read "would have blocked"
// today and blocks once the actuator lands. on_error is spelled out because
// fail-open is a choice (FR-11), not an accident. A permit carries neither.

@id("allow-all-monitor")
permit (principal, action, resource);

@id("flag-credential-read")
@enforce_action("flag")
@on_error("open")
forbid (
    principal,
    action == Action::"mcp/tools_call",
    resource
) when {
    context has resource_path &&
    (context.resource_path like "*/.ssh/*" ||
     context.resource_path like "*/.aws/*" ||
     context.resource_path like "*/.env")
};

// Shallow name heuristic over the lowercased tool name (context.tool is
// normalized by the engine). Signature-based binding replaces this when the
// aliasing control (§7) lands with the adversarial corpus.
@id("flag-destructive-op")
@enforce_action("flag")
@on_error("open")
forbid (
    principal,
    action == Action::"mcp/tools_call",
    resource
) when {
    context has tool &&
    (context.tool like "delete*" ||
     context.tool like "remove*" ||
     context.tool like "rmdir*" ||
     context.tool like "unlink*" ||
     context.tool == "rm")
};

// Model calls are actions in the same taxonomy as tool calls (§5.3, v0.8.4),
// so they are governed by ordinary rules. This family is metadata-only —
// which model, which destination — because what was *in* the payload is a
// classifier's opinion that arrives later as an advisory finding and never
// reaches this evaluation (ADR-7, permanent).
@id("flag-model-call-to-unlisted-host")
@enforce_action("flag")
@on_error("open")
forbid (
    principal,
    action == Action::"llm/completion",
    resource
) when {
    context has provider && context.provider == "unlisted"
};

// NOT shipped as a starter rule: "flag every model call that is unattested".
// Until the SDK can attest (D1) that is *every* model call, and a control which
// fires on 100% of traffic is noise rather than a control — it also duplicates
// assertion_status, which every record already carries. It belongs in the
// agent-security pack once attestation is achievable and its absence is a
// finding instead of the default state.
