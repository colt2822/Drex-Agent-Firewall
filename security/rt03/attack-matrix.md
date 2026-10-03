| Attack | Before | After | Blocked after | Detected before / after | Fail-closed |
|---|---|---|---|---|---|
| unlink_live | history changed | history intact | YES | NO / NO | N/A (filesystem prevention) |
| zero_truncate_live | mutation accepted; fixture survived | history intact | YES | NO / NO | N/A (filesystem prevention) |
| partial_truncate_live | mutation accepted; fixture survived | history intact | YES | NO / NO | N/A (filesystem prevention) |
| unlink_recreate_live | history changed | history intact | YES | NO / NO | N/A (filesystem prevention) |
| rename_empty_live | history changed | history intact | YES | NO / NO | N/A (filesystem prevention) |
| valid_empty_live | mutation accepted; fixture survived | history intact | YES | NO / NO | N/A (filesystem prevention) |
| rollback_live | mutation accepted; fixture survived | history intact | YES | NO / NO | N/A (filesystem prevention) |
| delete_rows_live | history changed | history intact | YES | NO / NO | N/A (filesystem prevention) |
| update_rows_live | history changed | history intact | YES | NO / NO | N/A (filesystem prevention) |
| update_decision_result_live | history changed | history intact | YES | NO / NO | N/A (filesystem prevention) |
| delete_block_live | history changed | history intact | YES | NO / NO | N/A (filesystem prevention) |
| wal_delete_live | mutation accepted; fixture survived | history intact | YES | NO / NO | N/A (filesystem prevention) |
| wal_truncate_live | history changed | history intact | YES | YES / NO | N/A (filesystem prevention) |
| wal_replace_live | mutation accepted; fixture survived | history intact | YES | NO / NO | N/A (filesystem prevention) |
| shm_remove_live | mutation accepted; fixture survived | history intact | YES | NO / NO | N/A (filesystem prevention) |
| db_symlink_live | history changed | history intact | YES | YES / NO | N/A (filesystem prevention) |
| parent_symlink_live | native denied | history intact | YES | NO / NO | N/A (filesystem prevention) |
| directory_replace_live | history changed | history intact | YES | YES / NO | N/A (filesystem prevention) |
| unwritable_live | history changed | history intact | YES | YES / NO | N/A (filesystem prevention) |
| rename_race_live | history changed | history intact | YES | NO / NO | N/A (filesystem prevention) |
| inode_replace_live | mutation accepted; fixture survived | history intact | YES | NO / NO | N/A (filesystem prevention) |
| zero_truncate_closed | history changed | history intact | YES | NO / NO | N/A (filesystem prevention) |
| partial_truncate_closed | history changed | history intact | YES | YES / NO | N/A (filesystem prevention) |
| valid_empty_closed | history changed | history intact | YES | NO / NO | N/A (filesystem prevention) |
| rollback_closed | history changed | history intact | YES | NO / NO | N/A (filesystem prevention) |
| inode_replace_closed | history changed | history intact | YES | NO / NO | N/A (filesystem prevention) |
| protected decision persistence failure | release read-only fixture blocked effect with NameError | read-only, SQLITE_FULL, missing IPC and payload-budget failures prevent effect | YES (effect) | YES (failure surfaced) | YES |
| session reuse after valid empty replacement | history lost silently; protected effect allowed | native replacement denied; historical record preserved on reopen; duplicate managed session ID rejected | YES | no independent rollback detector | N/A (replacement prevented) |
| IPC SQL / committed-result overwrite | no independent append boundary | requests rejected; snapshots and reporting rows intact | YES | YES (request rejected) | YES (no edit) |
| slow partial IPC frame | no broker in release | absolute deadline rejects frame; no event persisted | YES | YES (timeout) | YES |
