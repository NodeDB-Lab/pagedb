//! Mode-authorized recovery after authenticated header reconstruction.

use std::sync::atomic::Ordering;

use crate::Result;
use crate::errors::PagedbError;
use crate::pager::header::commit_header;
use crate::pager::structural_header::MainDbHeaderFields;
use crate::vfs::Vfs;

use super::super::core::Db;
use super::super::util::cleanup_stale_reader_pins;

pub(super) async fn recover_open_state<V: Vfs + Clone>(
    db: &Db<V>,
    kek: [u8; 32],
    fields: &MainDbHeaderFields,
) -> Result<()> {
    let capabilities = db.mode.open_capabilities();
    let pending_journal_id = crate::recovery::journal::decode_journal_id(
        fields.apply_journal_root_page_id,
        fields.apply_journal_root_version,
    );

    if pending_journal_id != [0; 16] {
        if !capabilities.applies_interrupted_apply() {
            return Err(crate::errors::PagedbError::Unsupported);
        }
        replay_and_clear_apply_journal(db, fields, pending_journal_id).await?;
    }

    if capabilities.runs_standalone_recovery() {
        match db.vfs.remove(&format!("{}.compact", db.main_db_path)).await {
            Ok(()) => {}
            Err(PagedbError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }

    let recovery_commit = db.latest_commit.load(Ordering::SeqCst);
    let hk = db.hk.read().clone();
    if capabilities.runs_standalone_recovery() {
        crate::recovery::repair_catalog(
            &*db.vfs,
            db.pager.clone(),
            &hk,
            db.realm_id,
            fields_catalog_root_page_id(fields),
            fields.next_page_id,
            db.page_size,
            db.file_id,
            recovery_commit,
        )
        .await?;
    } else {
        crate::recovery::verify_catalog(
            &*db.vfs,
            db.pager.clone(),
            &hk,
            db.realm_id,
            fields_catalog_root_page_id(fields),
            fields.next_page_id,
            db.page_size,
            db.file_id,
            recovery_commit,
        )
        .await?;
    }

    let watermark = {
        let state = db.writer.lock().await;
        db.load_rekey_watermark(&state).await?
    };
    if let Some(target_epoch) = watermark {
        if !capabilities.runs_standalone_recovery() {
            return Err(crate::errors::PagedbError::Unsupported);
        }
        db.rekey_db(kek, target_epoch).await?;
    }

    if capabilities.runs_standalone_recovery() {
        let mut state = db.writer.lock().await;
        let hk = db.hk.read().clone();
        cleanup_stale_reader_pins(
            &db.pager,
            &db.vfs,
            &db.main_db_path,
            &hk,
            db.realm_id,
            db.page_size,
            db.cipher_id,
            db.file_id,
            db.kek_salt,
            db.mk_epoch.load(Ordering::SeqCst),
            &mut state,
        )
        .await?;
        db.publish_snapshot(&state);
        drop(state);
    }
    Ok(())
}

async fn replay_and_clear_apply_journal<V: Vfs + Clone>(
    db: &Db<V>,
    fields: &MainDbHeaderFields,
    journal_id: [u8; 16],
) -> Result<()> {
    if crate::recovery::journal::replay_apply_journal(&db.pager, db.realm_id, journal_id)
        .await?
        .is_none()
    {
        return Ok(());
    }

    let mut cleared = fields.clone();
    cleared.seq = fields
        .seq
        .checked_add(1)
        .ok_or_else(|| PagedbError::arithmetic_overflow("apply-journal recovery sequence"))?;
    cleared.apply_journal_root_page_id = 0;
    cleared.apply_journal_root_version = 0;
    let hk = db.hk.read().clone();
    let mut state = db.writer.lock().await;
    let next_slot = commit_header(
        &*db.vfs,
        &db.main_db_path,
        &hk,
        &cleared,
        state.active_slot,
        db.page_size,
    )
    .await?;
    db.pager.remove_journal(journal_id).await?;
    state.active_slot = next_slot;
    state.seq = cleared.seq;
    db.publish_snapshot(&state);
    drop(state);

    for name in db.vfs.list_dir("applyjournal").await? {
        db.vfs.remove(&format!("applyjournal/{name}")).await?;
    }
    Ok(())
}

fn fields_catalog_root_page_id(fields: &MainDbHeaderFields) -> u64 {
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&fields.catalog_root[..8]);
    u64::from_le_bytes(bytes)
}
