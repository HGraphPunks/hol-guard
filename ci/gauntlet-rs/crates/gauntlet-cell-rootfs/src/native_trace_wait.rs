//! Decode Linux wait statuses without conflating event stops with actual death.
//! Values follow Linux's ptrace/wait ABI; this parser grants no custody credit.
use crate::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Event {
    Fork,
    Vfork,
    Clone,
    Exec,
    VforkDone,
    Exiting,
    SeizeStop,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Wait {
    Exited(u8),
    Killed { signal: u8, core_dumped: bool },
    Delivery(u8),
    Event { event: Event, signal: u8 },
}

pub(crate) fn decode(raw: i32) -> Result<Wait> {
    let raw = u32::try_from(raw).map_err(|_| "negative Linux wait status")?;
    let low = raw & 0xff;
    if low == 0 {
        if raw & !0xff00 != 0 {
            return Err("invalid Linux normal exit status".into());
        }
        return Ok(Wait::Exited((raw >> 8) as u8));
    }
    if low != 0x7f {
        let signal = (low & 0x7f) as u8;
        if raw & !0xff != 0 || !(1..=64).contains(&signal) {
            return Err("invalid Linux signal exit status".into());
        }
        return Ok(Wait::Killed {
            signal,
            core_dumped: low & 0x80 != 0,
        });
    }
    let signal = ((raw >> 8) & 0xff) as u8;
    if !(1..=64).contains(&signal) || raw & 0xff00_0000 != 0 {
        return Err("invalid Linux ptrace stop signal".into());
    }
    let event = match raw >> 16 {
        0 => return Ok(Wait::Delivery(signal)),
        1 => Event::Fork,
        2 => Event::Vfork,
        3 => Event::Clone,
        4 => Event::Exec,
        5 => Event::VforkDone,
        6 => Event::Exiting,
        128 => Event::SeizeStop,
        _ => return Err("unsupported Linux ptrace event".into()),
    };
    if signal != 5 && !(event == Event::SeizeStop && matches!(signal, 19..=22)) {
        return Err("ptrace event has an unexpected stop signal".into());
    }
    Ok(Wait::Event { event, signal })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn early_exit_event_is_distinct_from_final_exit_or_signal_death() {
        assert_eq!(decode(0).unwrap(), Wait::Exited(0));
        assert_eq!(decode(255 << 8).unwrap(), Wait::Exited(255));
        assert_eq!(
            decode(6 << 16 | 5 << 8 | 0x7f).unwrap(),
            Wait::Event {
                event: Event::Exiting,
                signal: 5
            }
        );
        assert_eq!(
            decode(9).unwrap(),
            Wait::Killed {
                signal: 9,
                core_dumped: false
            }
        );
        assert_eq!(
            decode(0x86).unwrap(),
            Wait::Killed {
                signal: 6,
                core_dumped: true
            }
        );
    }

    #[test]
    fn forks_exec_and_seized_group_stops_keep_their_kernel_event_identity() {
        for (number, event) in [
            (1, Event::Fork),
            (2, Event::Vfork),
            (3, Event::Clone),
            (4, Event::Exec),
            (5, Event::VforkDone),
            (128, Event::SeizeStop),
        ] {
            assert_eq!(
                decode(number << 16 | 5 << 8 | 0x7f).unwrap(),
                Wait::Event { event, signal: 5 }
            );
        }
        assert_eq!(decode(19 << 8 | 0x7f).unwrap(), Wait::Delivery(19));
        assert_eq!(
            decode(128 << 16 | 19 << 8 | 0x7f).unwrap(),
            Wait::Event {
                event: Event::SeizeStop,
                signal: 19
            }
        );
        // An actual SIGTRAP delivery must not be swallowed as an exec event.
        assert_eq!(decode(5 << 8 | 0x7f).unwrap(), Wait::Delivery(5));
    }

    #[test]
    fn continued_unknown_syscall_and_malformed_statuses_are_not_exit_proof() {
        for raw in [
            -1,
            0xffff,
            0x80,
            65,
            1 << 24,
            0x7f,
            133 << 8 | 0x7f,
            7 << 16 | 5 << 8 | 0x7f,
            1 << 16 | 19 << 8 | 0x7f,
            128 << 16 | 17 << 8 | 0x7f,
        ] {
            assert!(decode(raw).is_err(), "{raw:#x}");
        }
    }
}
