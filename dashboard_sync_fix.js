/**
 * CYBERDUDEBIVASH® SENTINEL APEX v25.0 — Dashboard Sync Fix
 * ============================================================
 * This patch fixes the "Last Sync" timestamp display issue.
 * 
 * PROBLEM: Dashboard was reading from data[data.length - 1].timestamp (last/oldest entry)
 * FIX: Read from data[0].timestamp (first/newest entry) or sync_marker.json
 * 
 * HOW TO APPLY:
 * 1. Open index.html
 * 2. Find the function that updates 'm-last-sync'
 * 3. Replace the timestamp calculation logic with this fixed version
 */

// ═══════════════════════════════════════════════════════════════════════════════
// FIXED LAST SYNC CALCULATION
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * OLD CODE (BUGGY) - around line 2285:
 * 
 *   const lastTs = data.length ? timeSince(data[data.length - 1].timestamp || data[0].timestamp) : '—';
 *   document.getElementById('m-last-sync').textContent = lastTs;
 * 
 * This reads from the LAST element which can be very old.
 */

/**
 * NEW CODE (FIXED):
 * 
 * Find and replace the section around line 2285-2292 with:
 */

// FIND THIS PATTERN IN index.html:
// const lastTs = data.length ? timeSince(data[data.length - 1].timestamp || data[0].timestamp) : '—';

// REPLACE WITH:
/*
// v25.0 FIX: Read newest entry (first in array) for Last Sync
const lastTs = data.length ? timeSince(data[0].timestamp) : '—';
*/

// ═══════════════════════════════════════════════════════════════════════════════
// FULL REPLACEMENT BLOCK
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Full replacement for the renderIntelGrid function's timestamp section.
 * 
 * Find this block (approximately lines 2285-2295):
 * 
 *   const lastTs = data.length ? timeSince(data[data.length - 1].timestamp || data[0].timestamp) : '—';
 *   ...
 *   document.getElementById('m-last-sync').textContent = lastTs;
 * 
 * Replace with the fixed version below:
 */

const FIXED_LAST_SYNC_CODE = `
// v25.0 FIX: Calculate Last Sync from newest entry (first in sorted array)
// Also try to fetch sync_marker.json for most accurate sync time
let lastTs = '—';
if (data.length) {
    // Sort by timestamp descending to ensure newest is first
    const sortedByTime = [...data].sort((a, b) => 
        new Date(b.timestamp || 0) - new Date(a.timestamp || 0)
    );
    lastTs = timeSince(sortedByTime[0].timestamp);
}

// Optional: Try to get more accurate sync time from sync_marker.json
fetch('data/sync_marker.json?' + Date.now())
    .then(r => r.ok ? r.json() : null)
    .then(marker => {
        if (marker && marker.last_sync) {
            const markerTs = timeSince(marker.last_sync);
            const el = document.getElementById('m-last-sync');
            if (el) el.textContent = markerTs;
        }
    })
    .catch(() => {}); // Silently ignore if sync_marker doesn't exist

document.getElementById('m-last-sync').textContent = lastTs;
`;

// ═══════════════════════════════════════════════════════════════════════════════
// AUTOMATED PATCH SCRIPT
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * This Node.js script can automatically patch index.html
 * 
 * Usage: node dashboard_sync_fix.js
 */

const fs = require('fs');
const path = require('path');

function patchIndexHtml() {
    const indexPath = path.join(__dirname, '..', 'index.html');
    
    if (!fs.existsSync(indexPath)) {
        console.error('❌ index.html not found at:', indexPath);
        process.exit(1);
    }
    
    let content = fs.readFileSync(indexPath, 'utf8');
    
    // Pattern to find the buggy Last Sync calculation
    const buggyPattern = /const lastTs = data\.length \? timeSince\(data\[data\.length - 1\]\.timestamp \|\| data\[0\]\.timestamp\) : '—';/g;
    
    // Fixed replacement
    const fixedCode = "const lastTs = data.length ? timeSince(data[0].timestamp) : '—'; // v25.0 FIX: Read newest entry";
    
    if (buggyPattern.test(content)) {
        content = content.replace(buggyPattern, fixedCode);
        fs.writeFileSync(indexPath, content);
        console.log('✅ index.html patched successfully!');
        console.log('   Fixed: Last Sync now reads from newest entry instead of oldest');
    } else {
        console.log('⚠️ Pattern not found - index.html may already be patched or has different code');
        console.log('   Manual review recommended');
    }
}

// Run if executed directly
if (require.main === module) {
    patchIndexHtml();
}

module.exports = { patchIndexHtml };

// ═══════════════════════════════════════════════════════════════════════════════
// MANUAL PATCH INSTRUCTIONS
// ═══════════════════════════════════════════════════════════════════════════════

console.log(`
╔═══════════════════════════════════════════════════════════════════════════════╗
║           SENTINEL APEX v25.0 — DASHBOARD SYNC FIX INSTRUCTIONS               ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║                                                                               ║
║  PROBLEM: "Last Sync" shows "3d ago" even when fresh data exists             ║
║                                                                               ║
║  ROOT CAUSE: Dashboard reads timestamp from oldest array entry               ║
║              instead of newest entry                                          ║
║                                                                               ║
║  FIX: In index.html, find line ~2285:                                        ║
║                                                                               ║
║  OLD (BUGGY):                                                                 ║
║    const lastTs = data.length ?                                              ║
║      timeSince(data[data.length - 1].timestamp || data[0].timestamp) : '—';  ║
║                                                                               ║
║  NEW (FIXED):                                                                 ║
║    const lastTs = data.length ? timeSince(data[0].timestamp) : '—';          ║
║                                                                               ║
║  ADDITIONAL FIX: Ensure feed_manifest.json is sorted newest-first            ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
`);
