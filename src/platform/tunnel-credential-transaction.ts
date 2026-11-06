/**
 * Non-operational credential rotation coordinator for a future LOCAL OS operator UI.
 *
 * This module has NO filesystem, task, service, network, CLI or MCP binding.
 * Passing an object that implements these interfaces is NOT authorization.
 * A production port must independently prove the OS token, installed service
 * identity, anchored file custody, exclusive lock, durable recovery journal,
 * atomic publication, and conditional lifecycle transitions.
 *
 * Never expose this function through a remote MCP tool or unauthenticated UI.
 */

export type RotationReasonCode =
    | 'AUTHENTICATED_CONTROL_PLANE'
    | 'CREDENTIAL_INPUT_INVALID'
    | 'AUTHORITY_UNVERIFIED'
    | 'OPERATOR_STOPPED'
    | 'STAGING_OR_PUBLICATION_REVERTED'
    | 'ACTIVATION_DENIED_REVERTED'
    | 'OPERATOR_STOPPED_DURING_HANDOVER'
    | 'CONTROL_PLANE_401_REVERTED'
    | 'CONTROL_PLANE_403_REVERTED'
    | 'CONTROL_PLANE_429_REVERTED'
    | 'AUTHENTICATION_UNVERIFIED_REVERTED'
    | 'RESTORATION_UNCERTAIN'
    | 'FINALIZATION_UNCERTAIN'
    | 'LEASE_RELEASE_UNCERTAIN';

export type RotationState =
    | 'provider_authenticated'
    | 'denied'
    | 'prior_credential_restored_unverified'
    | 'recovery_required';

export interface CredentialRotationResult {
    kind: 'local_credential_rotation_v1';
    state: RotationState;
    reasonCode: RotationReasonCode;
    /** A successful provider poll is NOT a fresh remote MCP request/result. */
    remoteRoundTrip: 'not_observed';
}

/**
 * This is an OS adapter contract, NOT a capability created by this module.
 *
 * Each session must hold an OS-level exclusive writer lease covering all phases.
 * These methods must never use user-supplied filesystem paths or credentials
 * in argv, environment, logs, telemetry, crash reports, or success responses.
 */
export interface RegisteredCredentialRotationSession {
    /** Both OS caller/principal and exact installed registered target must match. */
    verifyRegisteredAuthority(): Promise<
        'authorized_running' | 'operator_stopped' | 'unverified' | 'wrong_principal'
    >;
    /**
     * Restrictive, same-directory staging; stage bytes durably before returning.
     * The buffer is borrowed only during this call and zeroed as it returns.
     * A staging error may leave a partial candidate; restore cleans that up.
     */
    stage(bytes: Uint8Array): Promise<void>;
    /** Publish only after rechecking the protected target and fencing epoch. */
    publish(): Promise<void>;
    /**
     * Recheck the registered service and durable STOP at the side-effect
     * boundary; DO NOT revive a deliberately stopped service.
     */
    activateIfStillAuthorized(): Promise<'activated' | 'operator_stopped' | 'denied'>;
    /**
     * Return authenticated only from a fresh official provider control-plane
     * check, not local readyz, TCP connectivity or a cached health snapshot.
     */
    verifyProviderAuthentication(): Promise<
        'authenticated' | 'rejected_401' | 'forbidden_403'
        | 'rate_limited_429' | 'unverified'
    >;
    /**
     * Mark the durable journal committed and discard the protected temporary
     * old credential; exceptions MUST preserve evidence for offline recovery.
     */
    finalize(): Promise<void>;
    /**
     * Restore only when the OS-fenced generation is still current. Include
     * cleanup of partial staged files and preserve intentional STOP.
     * Never claim the restored old credential is still authenticated.
     */
    restorePriorIfSafe(): Promise<'restored' | 'pending'>;
    /** Release the OS-exclusive lease, reporting failure (never suppress it). */
    close(): Promise<void>;
}

export interface RegisteredCredentialRotationPort {
    /**
     * Acquire the locally authenticated OS principal and installed service
     * writer lease. Reject competing writers and unresolved prior recovery.
     */
    acquire(): Promise<RegisteredCredentialRotationSession>;
}

function result(state: RotationState, reasonCode: RotationReasonCode): CredentialRotationResult {
    return { kind: 'local_credential_rotation_v1', state, reasonCode,
        remoteRoundTrip: 'not_observed' };
}

const denied = (reason: RotationReasonCode): CredentialRotationResult =>
    result('denied', reason);

const uncertain = (reason: RotationReasonCode): CredentialRotationResult =>
    result('recovery_required', reason);

function isValidSecret(input: unknown): input is Uint8Array {
    if (!(input instanceof Uint8Array) ||
        input.byteLength === 0 || input.byteLength > 8192) {
        return false;
    }
    // Opaque provider key: do not guess its prefix, expiry, permissions or scope.
    // Reject control characters incompatible with an explicit one-time key field.
    for (const value of input) {
        if (value < 0x20 || value === 0x7f) return false;
    }
    return true;
}

async function execute(
    session: RegisteredCredentialRotationSession,
    ephemeral: Uint8Array,
): Promise<CredentialRotationResult> {
    let stageAttempted = false;
    let rollbackReason: RotationReasonCode = 'STAGING_OR_PUBLICATION_REVERTED';
    try {
        const authority = await session.verifyRegisteredAuthority();
        if (authority === 'operator_stopped') return denied('OPERATOR_STOPPED');
        if (authority !== 'authorized_running') {
            return denied('AUTHORITY_UNVERIFIED');
        }

        stageAttempted = true;
        // Only stage() receives bytes. Do not retain any copy during
        // service handover, provider polling, confirmation, or rollback.
        try {
            await session.stage(ephemeral);
        } finally {
            ephemeral.fill(0);
        }
        await session.publish();

        rollbackReason = 'ACTIVATION_DENIED_REVERTED';
        const activation = await session.activateIfStillAuthorized();
        if (activation !== 'activated') {
            if (activation === 'operator_stopped') {
                rollbackReason = 'OPERATOR_STOPPED_DURING_HANDOVER';
            }
            throw new Error('Conditional activation unavailable');
        }

        rollbackReason = 'AUTHENTICATION_UNVERIFIED_REVERTED';
        const verified = await session.verifyProviderAuthentication();
        if (verified !== 'authenticated') {
            if (verified === 'rejected_401') {
                rollbackReason = 'CONTROL_PLANE_401_REVERTED';
            } else if (verified === 'forbidden_403') {
                rollbackReason = 'CONTROL_PLANE_403_REVERTED';
            } else if (verified === 'rate_limited_429') {
                rollbackReason = 'CONTROL_PLANE_429_REVERTED';
            }
            throw new Error('Provider authentication not demonstrated');
        }

        // After verified publication, a failed finalization is ambiguous:
        // do not automatically revert a live authenticated credential.
        try {
            await session.finalize();
        } catch {
            return uncertain('FINALIZATION_UNCERTAIN');
        }
        return result('provider_authenticated', 'AUTHENTICATED_CONTROL_PLANE');
    } catch {
        if (!stageAttempted) return denied('AUTHORITY_UNVERIFIED');

        try {
            const restored = await session.restorePriorIfSafe();
            if (restored !== 'restored') {
                return uncertain('RESTORATION_UNCERTAIN');
            }
            return result('prior_credential_restored_unverified', rollbackReason);
        } catch {
            return uncertain('RESTORATION_UNCERTAIN');
        }
    }
}

/**
 * Consume a single ephemeral key and return only a fixed sanitized receipt.
 *
 * This coordinates an already OS-authorized backend; it DOES NOT perform
 * credential replacement by itself. Passing a caller-supplied fake port
 * cannot confer filesystem or service permissions.
 */
export async function runCredentialRotation(
    secret: Uint8Array,
    port: RegisteredCredentialRotationPort,
): Promise<CredentialRotationResult> {
    let ephemeral: Uint8Array | undefined;
    try {
        if (!isValidSecret(secret)) return denied('CREDENTIAL_INPUT_INVALID');
        // Take local ownership before the first asynchronous operation.
        // This is best-effort erasure of JS buffers, NOT a guarantee that the
        // runtime, OS or renderer made no other immutable copies.
        ephemeral = Uint8Array.from(secret);
        secret.fill(0);

        let session: RegisteredCredentialRotationSession;
        try {
            session = await port.acquire();
        } catch {
            return denied('AUTHORITY_UNVERIFIED');
        }

        let outcome: CredentialRotationResult;
        try {
            outcome = await execute(session, ephemeral);
        } catch {
            outcome = uncertain('RESTORATION_UNCERTAIN');
        }

        try {
            await session.close();
        } catch {
            return uncertain('LEASE_RELEASE_UNCERTAIN');
        }
        return outcome;
    } finally {
        // Also erase malformed or oversized input and any staging failure.
        if (secret instanceof Uint8Array) secret.fill(0);
        ephemeral?.fill(0);
    }
}
