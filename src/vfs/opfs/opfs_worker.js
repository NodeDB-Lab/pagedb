/**
 * OPFS Web Worker — pure JavaScript, no wasm dependency.
 *
 * Receives OpfsRequest messages from the main thread and responds with
 * OpfsResponse messages. Uses FileSystemSyncAccessHandle for all file I/O,
 * which is only available inside a dedicated worker context.
 *
 * Advisory locks are maintained in-memory (JS Map). They are process-level
 * guards; no cross-tab locking is implied.
 *
 * Message format (mirroring the Rust protocol.rs types):
 *   Request:  { id: u64, op: { type: string, ...fields } }
 *   Response: { id: u64, result: { type: string, ...fields } }
 */

"use strict";

// ── State ─────────────────────────────────────────────────────────────────────

/** @type {Map<number, FileSystemSyncAccessHandle>} */
const handles = new Map();
let nextHandleId = 1;

/** @type {Map<number, { path: string, kind: "exclusive"|"shared" }>} */
const locks = new Map();
let nextLockId = 1;

/** @type {Map<string, { kind: "exclusive"|"shared", count: number }>} */
const lockPaths = new Map();

// ── Helpers ───────────────────────────────────────────────────────────────────

function ok() {
    return { type: "ok" };
}

function errResult(reason, kind) {
    return { type: "err", reason: String(reason), kind: kind || "other" };
}

function classifyError(e) {
    const msg = String(e && e.message ? e.message : e);
    if (e && e.name === "NotFoundError") return "notFound";
    if (e && e.name === "TypeMismatchError") return "io";
    if (e && (e.name === "InvalidStateError" || e.name === "NoModificationAllowedError")) return "permissionDenied";
    if (msg.includes("not found") || msg.includes("NotFound")) return "notFound";
    if (msg.includes("already exists") || msg.includes("AlreadyExists")) return "alreadyExists";
    return "io";
}

/**
 * Walk/create a directory path under OPFS root.
 * @param {string} path - forward-slash separated relative path
 * @param {boolean} create - create directories that don't exist
 * @returns {Promise<FileSystemDirectoryHandle>}
 */
async function resolveDirHandle(path, create) {
    const root = await navigator.storage.getDirectory();
    if (!path || path === "/" || path === ".") return root;
    const parts = path.split("/").filter(Boolean);
    let dir = root;
    for (const part of parts) {
        dir = await dir.getDirectoryHandle(part, { create });
    }
    return dir;
}

/**
 * Resolve to the parent dir handle and the file name component.
 * @param {string} path
 * @returns {Promise<[FileSystemDirectoryHandle, string]>}
 */
async function resolveFilePath(path) {
    const parts = path.split("/").filter(Boolean);
    const name = parts.pop();
    const dirPath = parts.join("/");
    const dir = await resolveDirHandle(dirPath, false);
    return [dir, name];
}

// ── Op handlers ───────────────────────────────────────────────────────────────

async function opOpen({ path, create, create_new, read_only }) {
    try {
        const parts = path.split("/").filter(Boolean);
        const fileName = parts.pop();
        const dirPath = parts.join("/");

        // create parent dirs if needed
        const dir = await resolveDirHandle(dirPath, create);

        let fileHandle;
        if (create_new) {
            // createNew=true: fail if already exists
            try {
                await dir.getFileHandle(fileName, { create: false });
                // If we get here, file exists — that's an error
                return errResult("File already exists: " + path, "alreadyExists");
            } catch (notFound) {
                fileHandle = await dir.getFileHandle(fileName, { create: true });
            }
        } else {
            fileHandle = await dir.getFileHandle(fileName, { create: create });
        }

        const accessHandle = await fileHandle.createSyncAccessHandle();
        const handleId = nextHandleId++;
        handles.set(handleId, accessHandle);
        return { type: "opened", handle_id: handleId };
    } catch (e) {
        return errResult(e.message || String(e), classifyError(e));
    }
}

function opClose({ handle_id }) {
    const h = handles.get(handle_id);
    if (h) {
        try { h.close(); } catch (_) {}
        handles.delete(handle_id);
    }
    return ok();
}

function opRead({ handle_id, offset, len }) {
    const h = handles.get(handle_id);
    if (!h) return errResult("handle not found: " + handle_id, "notFound");
    try {
        const buf = new ArrayBuffer(len);
        const view = new Uint8Array(buf);
        const read = h.read(view, { at: Number(offset) });
        const bytes = Array.from(new Uint8Array(buf, 0, read));
        return { type: "data", bytes };
    } catch (e) {
        return errResult(e.message || String(e), classifyError(e));
    }
}

function opWrite({ handle_id, offset, data }) {
    const h = handles.get(handle_id);
    if (!h) return errResult("handle not found: " + handle_id, "notFound");
    try {
        const view = new Uint8Array(data);
        h.write(view, { at: Number(offset) });
        return ok();
    } catch (e) {
        return errResult(e.message || String(e), classifyError(e));
    }
}

function opFlush({ handle_id }) {
    const h = handles.get(handle_id);
    if (!h) return errResult("handle not found: " + handle_id, "notFound");
    try {
        h.flush();
        return ok();
    } catch (e) {
        return errResult(e.message || String(e), classifyError(e));
    }
}

function opGetSize({ handle_id }) {
    const h = handles.get(handle_id);
    if (!h) return errResult("handle not found: " + handle_id, "notFound");
    try {
        const len = h.getSize();
        return { type: "size", len };
    } catch (e) {
        return errResult(e.message || String(e), classifyError(e));
    }
}

function opTruncate({ handle_id, len }) {
    const h = handles.get(handle_id);
    if (!h) return errResult("handle not found: " + handle_id, "notFound");
    try {
        h.truncate(Number(len));
        return ok();
    } catch (e) {
        return errResult(e.message || String(e), classifyError(e));
    }
}

async function opRemove({ path }) {
    try {
        const [dir, name] = await resolveFilePath(path);
        await dir.removeEntry(name, { recursive: false });
        return ok();
    } catch (e) {
        // Not found on remove is treated as success (idempotent)
        if (e && e.name === "NotFoundError") return ok();
        return errResult(e.message || String(e), classifyError(e));
    }
}

async function opRename({ from, to }) {
    try {
        // OPFS does not have a native move/rename API.
        // Implement: read source, write to dest, remove source.
        const [fromDir, fromName] = await resolveFilePath(from);
        const [toDir, toName] = await resolveFilePath(to);

        const srcHandle = await fromDir.getFileHandle(fromName, { create: false });
        const srcAccess = await srcHandle.createSyncAccessHandle();
        const size = srcAccess.getSize();
        const buf = new ArrayBuffer(size);
        srcAccess.read(new Uint8Array(buf), { at: 0 });
        srcAccess.close();

        const dstHandle = await toDir.getFileHandle(toName, { create: true });
        const dstAccess = await dstHandle.createSyncAccessHandle();
        dstAccess.truncate(0);
        dstAccess.write(new Uint8Array(buf), { at: 0 });
        dstAccess.flush();
        dstAccess.close();

        await fromDir.removeEntry(fromName, { recursive: false });
        return ok();
    } catch (e) {
        return errResult(e.message || String(e), classifyError(e));
    }
}

async function opListDir({ path }) {
    try {
        const dir = await resolveDirHandle(path, false);
        const names = [];
        for await (const [name] of dir.entries()) {
            names.push(name);
        }
        return { type: "entries", names };
    } catch (e) {
        if (e && e.name === "NotFoundError") return { type: "entries", names: [] };
        return errResult(e.message || String(e), classifyError(e));
    }
}

async function opMkdirAll({ path }) {
    try {
        await resolveDirHandle(path, true);
        return ok();
    } catch (e) {
        return errResult(e.message || String(e), classifyError(e));
    }
}

function opLockExclusive({ path }) {
    const existing = lockPaths.get(path);
    if (existing) {
        return errResult("already locked: " + path, "permissionDenied");
    }
    const lockId = nextLockId++;
    locks.set(lockId, { path, kind: "exclusive" });
    lockPaths.set(path, { kind: "exclusive", count: 1 });
    return { type: "locked", lock_id: lockId };
}

function opLockShared({ path }) {
    const existing = lockPaths.get(path);
    if (existing && existing.kind === "exclusive") {
        return errResult("exclusively locked: " + path, "permissionDenied");
    }
    const lockId = nextLockId++;
    locks.set(lockId, { path, kind: "shared" });
    if (existing) {
        existing.count += 1;
    } else {
        lockPaths.set(path, { kind: "shared", count: 1 });
    }
    return { type: "locked", lock_id: lockId };
}

function opLockRelease({ lock_id }) {
    const entry = locks.get(lock_id);
    if (!entry) return ok(); // idempotent
    locks.delete(lock_id);
    const pathEntry = lockPaths.get(entry.path);
    if (pathEntry) {
        pathEntry.count -= 1;
        if (pathEntry.count <= 0) {
            lockPaths.delete(entry.path);
        }
    }
    return ok();
}

// ── Dispatch ──────────────────────────────────────────────────────────────────

self.onmessage = async function(event) {
    const { id, op } = event.data;
    let result;

    try {
        switch (op.type) {
            case "open":           result = await opOpen(op); break;
            case "close":          result = opClose(op); break;
            case "read":           result = opRead(op); break;
            case "write":          result = opWrite(op); break;
            case "flush":          result = opFlush(op); break;
            case "getSize":        result = opGetSize(op); break;
            case "truncate":       result = opTruncate(op); break;
            case "remove":         result = await opRemove(op); break;
            case "rename":         result = await opRename(op); break;
            case "listDir":        result = await opListDir(op); break;
            case "mkdirAll":       result = await opMkdirAll(op); break;
            case "lockExclusive":  result = opLockExclusive(op); break;
            case "lockShared":     result = opLockShared(op); break;
            case "lockRelease":    result = opLockRelease(op); break;
            default:
                result = errResult("unknown op: " + op.type, "other");
        }
    } catch (e) {
        result = errResult(e.message || String(e), "other");
    }

    self.postMessage({ id, result });
};
