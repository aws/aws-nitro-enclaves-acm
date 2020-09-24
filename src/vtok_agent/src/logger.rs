// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
use std::fmt::Write;
use std::time::Instant;

use log;

use crate::config;
use crate::defs;

pub struct Logger {
    timebase: Instant,
    level: log::Level,
    enable_timestamp: bool,
}

impl Logger {
    pub fn new(log_config: Option<config::Log>) -> Self {
        let (level, enable_timestamp) = log_config
            .map(|log| {
                (
                    log.level.into(),
                    log.enable_timestamp.unwrap_or(defs::DEFAULT_LOG_TIMESTAMP),
                )
            })
            .unwrap_or((defs::DEFAULT_LOG_LEVEL, defs::DEFAULT_LOG_TIMESTAMP));
        Self {
            level,
            enable_timestamp,
            timebase: Instant::now(),
        }
    }

    fn fmt_now(&self) -> String {
        let diff = Instant::now().duration_since(self.timebase);
        let mut secs = diff.as_secs();
        let day = secs / (24 * 3600);
        secs %= 24 * 3600;
        let hour = secs / 3600;
        secs %= 3600;
        let min = secs / 60;
        secs %= 60;

        format!(
            "{:3}d {:02}:{:02}:{:02}.{:06}",
            day,
            hour,
            min,
            secs,
            diff.subsec_micros(),
        )
    }
}

impl log::Log for Logger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        // TODO: make log level configurable
        metadata.level() <= self.level
    }
    fn log(&self, record: &log::Record) {
        if self.enabled(record.metadata()) {
            let mut msg = String::new();
            if self.enable_timestamp {
                write!(msg, "[{}] ", self.fmt_now()).unwrap_or_default();
            }
            eprintln!("{}|{:6}| {}", msg, record.level(), record.args());
        }
    }
    fn flush(&self) {}
}
