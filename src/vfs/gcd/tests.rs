//! A submitted `dispatch_io` write keeps running after its future drops, and its
//! handler holds the file's turn. These tests suspend the handler queue, so the
//! write stays in flight until the resume.

use std::time::Duration;

use dispatch2::{DispatchObject, DispatchQueue};
use tokio::time::timeout;

use crate::vfs::VfsFile;
use crate::vfs::gated::{bounded, cancel_when};
use crate::vfs::gcd::GcdFile;
use crate::vfs::write_order::WriteOrder;

const DROPPED: &[u8] = b"dropped-write";
const NEXT: &[u8] = b"next-write-xx";
const PATIENCE: Duration = Duration::from_millis(100);

fn file_on_queue(path: &std::path::Path, queue: &DispatchQueue) -> GcdFile {
    let fd = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .unwrap();
    let order = WriteOrder::for_file(&fd).unwrap();
    GcdFile::new(fd, true, queue.retain(), order).unwrap()
}

#[tokio::test(flavor = "current_thread")]
async fn a_write_through_another_handle_lands_after_a_dropped_write() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("file");
    let stalled = DispatchQueue::new("pagedb.gcd.stalled", None);
    let free = DispatchQueue::new("pagedb.gcd.free", None);
    let mut dropped_on = file_on_queue(&path, &stalled);
    let mut other = file_on_queue(&path, &free);

    stalled.suspend();
    cancel_when(dropped_on.write_at(0, DROPPED), tokio::task::yield_now()).await;
    let mut next = Box::pin(other.write_at(0, NEXT));
    let overtook = timeout(PATIENCE, &mut next).await.is_ok();
    stalled.resume();
    assert!(!overtook, "the next write overtook the dropped write");
    bounded(next).await.unwrap();
    bounded(other.sync()).await.unwrap();

    assert_eq!(std::fs::read(&path).unwrap(), NEXT);
}

#[tokio::test(flavor = "current_thread")]
async fn a_truncate_and_a_sync_wait_for_a_dropped_write() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("file");
    let stalled = DispatchQueue::new("pagedb.gcd.stalled", None);
    let mut file = file_on_queue(&path, &stalled);

    stalled.suspend();
    cancel_when(file.write_at(0, DROPPED), tokio::task::yield_now()).await;
    let truncate_overtook = timeout(PATIENCE, file.truncate(0)).await.is_ok();
    let sync_overtook = timeout(PATIENCE, file.sync()).await.is_ok();
    stalled.resume();
    assert!(
        !truncate_overtook,
        "the truncate overtook the dropped write"
    );
    assert!(!sync_overtook, "the sync overtook the dropped write");
    bounded(file.sync()).await.unwrap();

    assert_eq!(std::fs::read(&path).unwrap(), DROPPED);
}
