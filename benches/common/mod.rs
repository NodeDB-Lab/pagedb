//! Shared harness plumbing for the pagedb fluxbench targets.
//!
//! Included by each bench binary with `mod common;`. It is not a bench target
//! itself (Cargo only auto-discovers `benches/*.rs` and `benches/*/main.rs`).

use std::any::Any;
use std::cell::RefCell;

use fluxbench::TrackingAllocator;

/// Every bench binary tracks allocations, so the `alloc_bytes` / `alloc_count`
/// columns carry real numbers instead of silently reporting zero — and so the
/// figures stay comparable across targets. Lives here rather than in each bench
/// root to keep that uniform by construction.
#[global_allocator]
static GLOBAL: TrackingAllocator = TrackingAllocator;

thread_local! {
    /// One current-thread runtime per bench thread, reused across iterations so
    /// runtime construction never lands inside a measured region.
    static RT: tokio::runtime::Runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build bench runtime");

    /// Values handed over by [`park`], awaiting an untimed [`drain_parked`].
    static PARKED: RefCell<Vec<Box<dyn Any>>> = const { RefCell::new(Vec::new()) };
}

/// Run `f` with this thread's benchmark runtime.
pub fn with_rt<R>(f: impl FnOnce(&tokio::runtime::Runtime) -> R) -> R {
    RT.with(|rt| f(rt))
}

/// Block on `fut` using this thread's benchmark runtime.
pub fn block_on<F: Future>(fut: F) -> F::Output {
    with_rt(|rt| rt.block_on(fut))
}

/// Hand ownership of `value` to the harness instead of dropping it in place.
///
/// `Bencher::iter_with_setup` stops its timer *after* the routine's return
/// value is dropped, so anything the routine still owns — a `Db`, its buffer
/// pool, a whole in-memory file — is torn down inside the measured region and
/// charged to the operation under test, allocation counters included. Parking
/// it defers that teardown to the next [`drain_parked`], which callers run from
/// the untimed setup phase.
pub fn park<T: 'static>(value: T) {
    PARKED.with(|parked| parked.borrow_mut().push(Box::new(value)));
}

/// Drop everything [`park`]ed by earlier iterations. Call at the top of an
/// untimed setup closure, inside the runtime context the values were built in.
pub fn drain_parked() {
    let taken = PARKED.with(|parked| std::mem::take(&mut *parked.borrow_mut()));
    drop(taken);
}
