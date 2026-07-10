//! Mode-authorized recovery after authenticated header reconstruction.

use crate::Result;
use crate::crypto::SecretKey;
use crate::errors::PagedbError;
use crate::pager::structural_header::MainDbHeaderFields;
use crate::vfs::Vfs;

use super::super::core::Db;

pub(super) async fn recover_open_state<V: Vfs + Clone>(
    db: &Db<V>,
    primary_kek: &SecretKey,
    counterpart_kek: Option<&SecretKey>,
    fields: &MainDbHeaderFields,
) -> Result<()> {
    let capabilities = db.mode.open_capabilities();
    let rekey_in_flight = db
        .admit_rekey_recovery(primary_kek, counterpart_kek)
        .await?;

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

    if rekey_in_flight {
        if !capabilities.runs_standalone_recovery() {
            return Err(crate::errors::PagedbError::Unsupported);
        }
        db.resume_rekey_intent().await?;
    }

    let (catalog_root_page_id, next_page_id) = {
        let state = db.writer.lock().await;
        (state.catalog_root_page_id, state.next_page_id)
    };
    let recovery_commit = db.latest_commit().0;
    if capabilities.runs_standalone_recovery() {
        crate::recovery::repair_catalog(
            &*db.vfs,
            db.pager.clone(),
            db.realm_id,
            catalog_root_page_id,
            next_page_id,
            db.page_size,
            db.file_id,
            recovery_commit,
        )
        .await?;
    } else {
        crate::recovery::verify_catalog(
            &*db.vfs,
            db.pager.clone(),
            db.realm_id,
            catalog_root_page_id,
            next_page_id,
            db.page_size,
            db.file_id,
            recovery_commit,
        )
        .await?;
    }

    Ok(())
}
