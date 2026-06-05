/**
 * Trial Conversion Engine — SENTINEL APEX Revenue Operations
 * Version: 1.0.0 | Build: 2026-06-05
 *
 * PURPOSE: Track trial milestone completion, compute upgrade readiness scores,
 * detect stalled trials, and generate conversion action recommendations.
 */

'use strict';

const MILESTONE_POINTS = {
  'trial.activated':         10,
  'trial.login':             10,
  'trial.api.call':          20,
  'trial.report.download':   20,
  'trial.dashboard.view':    15,
  'trial.feed.access':       15,
  'trial.stix.export':       25,
  'trial.siem.connect':      30,
  'trial.alert.create':      20,
  'trial.upgrade.page_view':  5,
  'trial.upgrade.initiated': 50,
};

const UPGRADE_READINESS_THRESHOLD = 80;

const STALL_THRESHOLD_HOURS = 48; // no activity for 48h = stalled

const CONVERSION_ACTIONS = {
  'trial.activated': {
    next: 'trial.login',
    action: 'Send welcome email with 3-step quickstart guide',
    timing_hours: 1,
  },
  'trial.login': {
    next: 'trial.dashboard.view',
    action: 'Show in-app onboarding tour with first threat alert',
    timing_hours: 0,
  },
  'trial.dashboard.view': {
    next: 'trial.api.call',
    action: 'Send API quickstart email with sandbox credentials',
    timing_hours: 2,
  },
  'trial.api.call': {
    next: 'trial.report.download',
    action: 'Send weekly threat brief highlighting top 5 IOCs',
    timing_hours: 24,
  },
  'trial.report.download': {
    next: 'trial.siem.connect',
    action: 'Send SIEM integration guide for Splunk / QRadar / Sentinel',
    timing_hours: 4,
  },
  'trial.siem.connect': {
    next: 'trial.upgrade.initiated',
    action: 'Send upgrade proposal with ROI calculator pre-filled',
    timing_hours: 2,
  },
};

// ---------------------------------------------------------------------------
// 1. MILESTONE TRACKING
// ---------------------------------------------------------------------------

/**
 * computeTrialScore
 * Given array of event types completed, sum milestone points.
 */
function computeTrialScore(completedEvents) {
  let score = 0;
  const seen = new Set();
  for (const evt of completedEvents) {
    if (!seen.has(evt) && MILESTONE_POINTS[evt] !== undefined) {
      score += MILESTONE_POINTS[evt];
      seen.add(evt);
    }
  }
  return Math.min(100, score);
}

/**
 * getCompletedMilestones
 * Returns list of completed milestone names with points.
 */
function getCompletedMilestones(completedEvents) {
  const seen = new Set();
  const result = [];
  for (const evt of completedEvents) {
    if (!seen.has(evt) && MILESTONE_POINTS[evt] !== undefined) {
      result.push({ event: evt, points: MILESTONE_POINTS[evt] });
      seen.add(evt);
    }
  }
  return result;
}

/**
 * getMissingMilestones
 * Returns milestones not yet completed, sorted by points desc.
 */
function getMissingMilestones(completedEvents) {
  const completed = new Set(completedEvents);
  return Object.entries(MILESTONE_POINTS)
    .filter(([evt]) => !completed.has(evt))
    .sort(([, a], [, b]) => b - a)
    .map(([evt, pts]) => ({ event: evt, points: pts }));
}

// ---------------------------------------------------------------------------
// 2. UPGRADE READINESS
// ---------------------------------------------------------------------------

/**
 * assessUpgradeReadiness
 * Returns readiness score + recommended action.
 */
function assessUpgradeReadiness(trialEntry) {
  const events = trialEntry.completed_events || [];
  const score = computeTrialScore(events);
  const daysRemaining = _daysRemaining(trialEntry);
  const isStalled = _isStalled(trialEntry);

  const ready = score >= UPGRADE_READINESS_THRESHOLD;

  let recommendation = null;
  if (ready && daysRemaining <= 5) {
    recommendation = { priority: 'URGENT', action: 'Send upgrade offer with 10% first-month discount — trial ending soon.' };
  } else if (ready) {
    recommendation = { priority: 'HIGH', action: 'Trial user is highly engaged. Schedule upgrade call within 24h.' };
  } else if (isStalled) {
    recommendation = { priority: 'HIGH', action: 'Trial stalled. Send re-engagement email with platform highlight.' };
  } else if (score >= 50) {
    recommendation = { priority: 'MEDIUM', action: 'Progress upgrade journey: send SIEM integration guide.' };
  } else if (score >= 20) {
    recommendation = { priority: 'MEDIUM', action: 'Send API quickstart and top-5 threat brief.' };
  } else {
    recommendation = { priority: 'LOW', action: 'Send welcome sequence Day-2 email.' };
  }

  return {
    trial_id: trialEntry.trial_id,
    score,
    ready,
    days_remaining: daysRemaining,
    is_stalled: isStalled,
    completed_milestones: getCompletedMilestones(events),
    missing_milestones: getMissingMilestones(events),
    recommendation,
  };
}

// ---------------------------------------------------------------------------
// 3. STALL DETECTION
// ---------------------------------------------------------------------------

function _isStalled(trialEntry) {
  const lastActivity = trialEntry.last_activity_at;
  if (!lastActivity) return true;
  const hours = (Date.now() - new Date(lastActivity).getTime()) / 3_600_000;
  return hours > STALL_THRESHOLD_HOURS;
}

function _daysRemaining(trialEntry) {
  const activated = trialEntry.activated_at;
  const durationDays = trialEntry.duration_days || 14;
  if (!activated) return durationDays;
  const endDate = new Date(activated).getTime() + durationDays * 86_400_000;
  const remaining = (endDate - Date.now()) / 86_400_000;
  return Math.max(0, Math.round(remaining));
}

// ---------------------------------------------------------------------------
// 4. NEXT ACTION ENGINE
// ---------------------------------------------------------------------------

/**
 * getNextConversionAction
 * Determines the highest-priority next action for a trial user.
 */
function getNextConversionAction(completedEvents) {
  const completed = new Set(completedEvents);
  // Find the furthest completed milestone
  const ordered = [
    'trial.activated','trial.login','trial.dashboard.view',
    'trial.api.call','trial.report.download','trial.siem.connect',
    'trial.alert.create','trial.stix.export','trial.upgrade.initiated',
  ];

  let lastCompleted = null;
  for (const evt of ordered) {
    if (completed.has(evt)) lastCompleted = evt;
  }

  if (!lastCompleted) {
    return { event: 'trial.activated', action: CONVERSION_ACTIONS['trial.activated'] };
  }

  const config = CONVERSION_ACTIONS[lastCompleted];
  if (!config) return null;

  return {
    completed_last: lastCompleted,
    next_event: config.next,
    action: config.action,
    send_after_hours: config.timing_hours,
  };
}

// ---------------------------------------------------------------------------
// 5. BATCH PROCESSOR
// ---------------------------------------------------------------------------

/**
 * processBatchTrials
 * Takes array of trial entries, returns conversion assessments + stalled list.
 */
function processBatchTrials(trialEntries) {
  const assessments = [];
  const stalled = [];
  const urgent = [];

  for (const entry of trialEntries) {
    const assessment = assessUpgradeReadiness(entry);
    assessments.push(assessment);
    if (assessment.is_stalled) stalled.push(entry.trial_id);
    if (assessment.recommendation && assessment.recommendation.priority === 'URGENT') {
      urgent.push(entry.trial_id);
    }
  }

  const avgScore = assessments.length > 0
    ? (assessments.reduce((s, a) => s + a.score, 0) / assessments.length).toFixed(1)
    : 0;

  return {
    processed: assessments.length,
    ready_to_upgrade: assessments.filter(a => a.ready).length,
    stalled_trials: stalled,
    urgent_actions: urgent,
    average_engagement_score: avgScore,
    assessments,
  };
}

// ---------------------------------------------------------------------------
// 6. EXPORTS
// ---------------------------------------------------------------------------
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    computeTrialScore,
    getCompletedMilestones,
    getMissingMilestones,
    assessUpgradeReadiness,
    getNextConversionAction,
    processBatchTrials,
    MILESTONE_POINTS,
    UPGRADE_READINESS_THRESHOLD,
  };
}
