// Bounds mirrored from the collector. tests/test_publication.py checks each value against
// intelligence_hub/collect.py, intelligence_hub/mitigations.py and intelligence_hub/shards.py.

// FEED_MAX_BYTES and BRIEFS_MAX_BYTES in intelligence_hub/collect.py.
export const maximumFeedBytes = 8 * 1024 * 1024;
// The briefs bound was raised from 12 MiB to 24 MiB on 2026-11-11 with the owner's approval (WP-00).
export const maximumBriefsBytes = 24 * 1024 * 1024;
// Schema 6 and earlier carried every brief inline, so those files could reach 16 MiB.
export const maximumLegacyFeedBytes = 16 * 1024 * 1024;
// MAX_FEED_ROWS in the collector: the 8 MiB feed bound / 300 bytes per row.
export const maximumArticles = 27962;
// INDEX_FIELDS in intelligence_hub/mitigations.py.
export const indexFields = ["record_state", "source_status", "guidance_status", "required_action", "cvss_score", "cvss_version", "kev_date_added", "weaknesses"];
// INDEX_MAX_BYTES and V7_FILE_MAX_BYTES in intelligence_hub/shards.py.
export const maximumIndexBytes = 1 * 1024 * 1024;
export const maximumShardBytes = 4 * 1024 * 1024;
// How often an open, visible page asks whether data/v7/index.json changed, in milliseconds.
export const pollInterval = 600000;
// Rows per page in every list.
export const pageSize = 25;
