//! Mode-authorized recovery after authenticated header reconstruction.

use crate::Result;
use crate::errors::PagedbError;
use crate::pager::structural_header::MainDbHeaderFields;
use crate::vfs::Vfs;

use super::super::core::Db;

pub(super) async fn recover_open_state<V: Vfs + Clone>(
    db: &Db<V>,
    kek: [u8; 32],
    fields: &MainDbHeaderFields,
) -> Result<()> {
    let capabilities = db.mode.open_capabilities();
    if fields.apply_journal_root_page_id != 0 || fields.apply_journal_root_version != 0 {
        if !capabilities.applies_interrupted_apply() {
            return Err(crate::errors::PagedbError::Unsupported);
        }
        db.retry_pending_apply_journal().await?;
    }

    if capabilities.runs_standalone_recovery() {
        match db.vfs.remove(&format!("{}.compact", db.main_db_path)).await {
            Ok(()) => {}
            Err(PagedbError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }

    let recovery_commit = db.latest_commit().0;
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

    Ok(())
}

fn fields_catalog_root_page_id(fields: &MainDbHeaderFields) -> u64 {
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&fields.catalog_root[..8]);
    u64::from_le_bytes(bytes)
}
