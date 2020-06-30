use log::{Level, LevelFilter, Log, Metadata, Record};

pub struct Logger;

impl Logger {
    pub fn init() {
        let boxed_logger = Box::new(Self {});
        let res = log::set_boxed_logger(boxed_logger);
        match res {
            Ok(_) => log::set_max_level(LevelFilter::Trace),
            Err(_) => trace!("Logger already initialized"),
        }
    }
}

impl Log for Logger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= Level::Error
    }

    fn flush(&self) {}

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            eprintln!(
                "{:8} {}:{} {}",
                record.metadata().level(),
                record.file().unwrap(),
                record.line().unwrap(),
                record.args()
            );
        }
    }
}
