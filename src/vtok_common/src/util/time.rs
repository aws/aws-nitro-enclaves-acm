use libc;

/// Get a monotonic (i.e. always increasing) timestamp, in seconds.
pub fn monotonic_secs() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };

    let rc = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    if rc != 0 {
        panic!("clock_gettime() failed: {}", rc);
    }
    if ts.tv_sec < 0 {
        panic!("Got negative value for CLOCK_MONOTONIC: {}", ts.tv_sec);
    }

    ts.tv_sec as u64
}
