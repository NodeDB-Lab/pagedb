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
        // A rename in flight or one a crash stopped owns this path until it ends.
        await finishInterruptedRename(path);
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
        if (!Number.isSafeInteger(read) || read < 0 || read > len) {
            return errResult("OPFS read returned an invalid byte count", "io");
        }
        const bytes = Array.from(new Uint8Array(buf, 0, read));
        return { type: "data", bytes, count: read };
    } catch (e) {
        return errResult(e.message || String(e), classifyError(e));
    }
}

function opWrite({ handle_id, offset, data }) {
    const h = handles.get(handle_id);
    if (!h) return errResult("handle not found: " + handle_id, "notFound");
    try {
        const view = new Uint8Array(data);
        const written = h.write(view, { at: Number(offset) });
        return { type: "written", count: written };
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
        await finishInterruptedRename(path);
        const [dir, name] = await resolveFilePath(path);
        await dir.removeEntry(name, { recursive: false });
        return ok();
    } catch (e) {
        // Not found on remove is treated as success (idempotent)
        if (e && e.name === "NotFoundError") return ok();
        return errResult(e.message || String(e), classifyError(e));
    }
}

// ── Rename ────────────────────────────────────────────────────────────────────
//
// This worker renames by copying, because a sync access handle offers no atomic
// replace. A copy over an existing file destroys it first, so a crash there leaves
// a partial destination. The source is then the only full copy.
//
// A journal beside the destination makes the copy crash-safe:
//
// 1. Write and flush `<to>.pagedb-rename`, naming the source. A complete journal
//    means the source is complete, and the destination can be partial.
// 2. Copy the source over the destination, then flush.
// 3. Remove the source.
// 4. Remove the journal.
//
// Any later open or listing of the destination finishes a rename a crash stopped.
// A source that is gone means the copy already completed. A journal that fails to
// parse stopped before its flush, so the destination was never touched.

const RENAME_JOURNAL_SUFFIX = ".pagedb-rename";
const COPY_CHUNK_BYTES = 1 << 20;

/** @type {Map<string, Promise<void>>} destination path → its rename in flight */
const renamesInFlight = new Map();

function normalizePath(path) {
    return path.split("/").filter(Boolean).join("/");
}

function joinPath(dirPath, name) {
    const dir = normalizePath(dirPath);
    return dir ? dir + "/" + name : name;
}

async function removeIfPresent(dir, name) {
    try {
        await dir.removeEntry(name, { recursive: false });
    } catch (e) {
        if (!e || e.name !== "NotFoundError") throw e;
    }
}

async function writeRenameJournal(dir, journalName, from) {
    const handle = await dir.getFileHandle(journalName, { create: true });
    const access = await handle.createSyncAccessHandle();
    try {
        const bytes = new TextEncoder().encode(JSON.stringify({ from }) + "\n");
        access.truncate(0);
        if (access.write(bytes, { at: 0 }) !== bytes.length) {
            throw new Error("OPFS short write of a rename journal");
        }
        access.flush();
    } finally {
        access.close();
    }
}

/** The source a journal names, or null when the journal is not complete. */
async function readRenameJournal(dir, journalName) {
    const handle = await dir.getFileHandle(journalName, { create: false });
    const access = await handle.createSyncAccessHandle();
    let text;
    try {
        const bytes = new Uint8Array(access.getSize());
        const read = access.read(bytes, { at: 0 });
        text = new TextDecoder().decode(bytes.subarray(0, read));
    } finally {
        access.close();
    }
    if (!text.endsWith("\n")) return null;
    try {
        const parsed = JSON.parse(text);
        return typeof parsed.from === "string" ? parsed.from : null;
    } catch (_) {
        return null;
    }
}

/**
 * Take both sync access handles of a copy. A failure here leaves the destination
 * as it was, which is what a handle another open holds looks like.
 */
async function openCopyHandles(fromDir, fromName, toDir, toName) {
    const srcHandle = await fromDir.getFileHandle(fromName, { create: false });
    const srcAccess = await srcHandle.createSyncAccessHandle();
    try {
        const dstHandle = await toDir.getFileHandle(toName, { create: true });
        const dstAccess = await dstHandle.createSyncAccessHandle();
        return { srcAccess, dstAccess };
    } catch (e) {
        srcAccess.close();
        throw e;
    }
}

/** Copy in chunks, make the destination durable, and release both handles. */
function copyAndClose({ srcAccess, dstAccess }) {
    try {
        const size = srcAccess.getSize();
        const chunk = new Uint8Array(Math.min(COPY_CHUNK_BYTES, Math.max(size, 1)));
        dstAccess.truncate(0);
        let at = 0;
        while (at < size) {
            const read = srcAccess.read(chunk, { at });
            if (read <= 0) throw new Error("OPFS short read while renaming");
            if (dstAccess.write(chunk.subarray(0, read), { at }) !== read) {
                throw new Error("OPFS short write while renaming");
            }
            at += read;
        }
        dstAccess.flush();
    } finally {
        dstAccess.close();
        srcAccess.close();
    }
}

async function runRename(from, to) {
    const [fromDir, fromName] = await resolveFilePath(from);
    const [toDir, toName] = await resolveFilePath(to);
    const journalName = toName + RENAME_JOURNAL_SUFFIX;
    await writeRenameJournal(toDir, journalName, from);
    let handles;
    try {
        handles = await openCopyHandles(fromDir, fromName, toDir, toName);
    } catch (e) {
        // Nothing moved, so no journal can finish this rename later.
        await removeIfPresent(toDir, journalName);
        throw e;
    }
    copyAndClose(handles);
    await removeIfPresent(fromDir, fromName);
    await removeIfPresent(toDir, journalName);
}

/**
 * Run `work` after everything already queued on this destination. Handlers run
 * concurrently across awaits, so this keeps an open from landing inside a copy.
 */
function serializeOnPath(key, work) {
    const prior = renamesInFlight.get(key);
    const next = (prior ? prior.catch(() => {}) : Promise.resolve()).then(work);
    renamesInFlight.set(key, next);
    const settle = () => {
        if (renamesInFlight.get(key) === next) renamesInFlight.delete(key);
    };
    next.then(settle, settle);
    return next;
}

/** Finish a rename of `to` that a crash stopped. A live rename finishes by itself. */
function finishInterruptedRename(to) {
    return serializeOnPath(normalizePath(to), () => repairRenameJournal(to));
}

async function repairRenameJournal(to) {
    let toDir;
    let toName;
    try {
        [toDir, toName] = await resolveFilePath(to);
    } catch (e) {
        if (e && e.name === "NotFoundError") return;
        throw e;
    }
    const journalName = toName + RENAME_JOURNAL_SUFFIX;
    let from;
    try {
        from = await readRenameJournal(toDir, journalName);
    } catch (e) {
        if (e && e.name === "NotFoundError") return;
        throw e;
    }
    if (from !== null) {
        let source = null;
        try {
            const [fromDir, fromName] = await resolveFilePath(from);
            await fromDir.getFileHandle(fromName, { create: false });
            source = [fromDir, fromName];
        } catch (e) {
            if (!e || e.name !== "NotFoundError") throw e;
        }
        if (source) {
            copyAndClose(await openCopyHandles(source[0], source[1], toDir, toName));
            await removeIfPresent(source[0], source[1]);
        }
    }
    await removeIfPresent(toDir, journalName);
}

async function opRename({ from, to }) {
    try {
        await serializeOnPath(normalizePath(to), async () => {
            await repairRenameJournal(to);
            await runRename(from, to);
        });
        return ok();
    } catch (e) {
        return errResult(e.message || String(e), classifyError(e));
    }
}

async function opListDir({ path }) {
    try {
        const dir = await resolveDirHandle(path, false);
        const names = [];
        const journals = [];
        for await (const [name] of dir.entries()) {
            if (name.endsWith(RENAME_JOURNAL_SUFFIX)) {
                journals.push(name.slice(0, -RENAME_JOURNAL_SUFFIX.length));
            } else {
                names.push(name);
            }
        }
        if (journals.length === 0) return { type: "entries", names };
        for (const target of journals) {
            await finishInterruptedRename(joinPath(path, target));
        }
        const repaired = [];
        for await (const [name] of dir.entries()) {
            if (!name.endsWith(RENAME_JOURNAL_SUFFIX)) repaired.push(name);
        }
        return { type: "entries", names: repaired };
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
