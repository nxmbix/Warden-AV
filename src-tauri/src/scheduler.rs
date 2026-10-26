//! Background loop for scheduled scans and automatic signature updates.

use crate::{start_scan_inner, update_signatures_inner, AppState};
use chrono::{DateTime, Datelike, Duration, Local, NaiveTime, TimeZone};
use std::sync::atomic::Ordering;
use tauri::{AppHandle, Manager};

use crate::settings::Schedule;

/// The most recent moment the schedule should have fired at, at or before `now`.
pub fn last_slot(s: &Schedule, now: DateTime<Local>) -> Option<DateTime<Local>> {
    let time = NaiveTime::parse_from_str(&s.time, "%H:%M").ok()?;
    for back in 0..8 {
        let day = now.date_naive() - Duration::days(back);
        if s.frequency == "weekly" && day.weekday().num_days_from_monday() != s.weekday {
            continue;
        }
        let slot = Local.from_local_datetime(&day.and_time(time)).earliest()?;
        if slot <= now {
            return Some(slot);
        }
    }
    None
}

pub fn next_slot(s: &Schedule, now: DateTime<Local>) -> Option<DateTime<Local>> {
    if !s.enabled {
        return None;
    }
    let time = NaiveTime::parse_from_str(&s.time, "%H:%M").ok()?;
    for ahead in 0..8 {
        let day = now.date_naive() + Duration::days(ahead);
        if s.frequency == "weekly" && day.weekday().num_days_from_monday() != s.weekday {
            continue;
        }
        let slot = Local.from_local_datetime(&day.and_time(time)).earliest()?;
        if slot > now {
            return Some(slot);
        }
    }
    None
}

fn is_due(s: &Schedule, now: DateTime<Local>) -> bool {
    if !s.enabled {
        return false;
    }
    let Some(slot) = last_slot(s, now) else { return false };
    match s.last_run.as_deref().and_then(|t| DateTime::parse_from_rfc3339(t).ok()) {
        Some(last) => last.with_timezone(&Local) < slot,
        None => false,
    }
}

pub fn spawn(app: AppHandle) {
    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_secs(15));
        loop {
            let state = app.state::<AppState>();
            let now = Local::now();

            let (due, kind) = {
                let mut settings = state.settings.lock();
                if settings.schedule.enabled && settings.schedule.last_run.is_none() {
                    settings.schedule.last_run = Some(now.to_rfc3339());
                    settings.save(&state.data_dir).ok();
                }
                (is_due(&settings.schedule, now), settings.schedule.scan_type.clone())
            };
            if due && state.scan_cancel.lock().is_none() {
                {
                    let mut settings = state.settings.lock();
                    settings.schedule.last_run = Some(now.to_rfc3339());
                    settings.save(&state.data_dir).ok();
                }
                let _ = start_scan_inner(&app, &kind, Vec::new(), true);
            }

            let update_due = {
                let s = state.settings.lock();
                s.updates.auto_update
                    && match s.updates.last_update.as_deref().and_then(|t| DateTime::parse_from_rfc3339(t).ok()) {
                        Some(last) => {
                            now.signed_duration_since(last.with_timezone(&Local))
                                > Duration::hours(s.updates.interval_hours.max(1) as i64)
                        }
                        None => true,
                    }
            };
            if update_due && !state.updating.load(Ordering::Relaxed) {
                let _ = update_signatures_inner(&app);
            }

            std::thread::sleep(std::time::Duration::from_secs(30));
        }
    });
}
