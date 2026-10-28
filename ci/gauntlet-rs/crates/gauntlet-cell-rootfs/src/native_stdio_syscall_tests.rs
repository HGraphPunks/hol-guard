use super::*;

fn entry(number: u64, descriptor: u64, address: u64, length: u64) -> NativeSyscallEntry {
    NativeSyscallEntry {
        number,
        arguments: [descriptor, address, length, 0, 0, 0],
    }
}
fn entry_bytes(value: NativeSyscallEntry) -> Vec<u8> {
    let mut raw = vec![0; 80];
    raw[0] = 1;
    raw[4..8].copy_from_slice(&AUDIT_ARCH_AARCH64.to_le_bytes());
    raw[24..32].copy_from_slice(&value.number.to_le_bytes());
    for (index, argument) in value.arguments.iter().enumerate() {
        raw[32 + 8 * index..40 + 8 * index].copy_from_slice(&argument.to_le_bytes());
    }
    raw
}
fn exit_bytes(result: i64, error: u8) -> Vec<u8> {
    let mut raw = vec![0; 33];
    raw[0] = 2;
    raw[4..8].copy_from_slice(&AUDIT_ARCH_AARCH64.to_le_bytes());
    raw[24..32].copy_from_slice(&result.to_le_bytes());
    raw[32] = error;
    raw
}
fn iovecs(values: &[(u64, u64)]) -> Vec<u8> {
    values
        .iter()
        .flat_map(|(address, length)| {
            address
                .to_le_bytes()
                .into_iter()
                .chain(length.to_le_bytes())
        })
        .collect()
}

#[test]
fn syscall_information_keeps_exact_aarch64_entry_arguments_and_signed_exit() {
    let value = entry(63, 0, 0x1234_5678, 4096);
    assert_eq!(
        decode_native_syscall_info(&entry_bytes(value)).unwrap(),
        NativeSyscallStop::Entry(value)
    );
    assert_eq!(
        decode_native_syscall_info(&exit_bytes(-512, 1)).unwrap(),
        NativeSyscallStop::Exit {
            result: -512,
            is_error: true
        }
    );
    assert_eq!(
        decode_native_syscall_info(&exit_bytes(3, 0)).unwrap(),
        NativeSyscallStop::Exit {
            result: 3,
            is_error: false
        }
    );
}

#[test]
fn unknown_architecture_flags_stop_kind_extensions_and_truncation_refuse() {
    let good = entry_bytes(entry(63, 0, 4096, 4));
    for length in [0, 7, 23, 24, 79, 81, 88, 89] {
        let mut raw = good.clone();
        raw.resize(length, 0);
        assert!(decode_native_syscall_info(&raw).is_err(), "{length}");
    }
    for (offset, value) in [(0, 0), (0, 3), (0, 4), (1, 1), (2, 1), (3, 1), (4, 0)] {
        let mut raw = good.clone();
        raw[offset] = value;
        assert!(decode_native_syscall_info(&raw).is_err(), "{offset}");
    }
    assert!(decode_native_syscall_info(&exit_bytes(0, 2)).is_err());
    for length in [24, 32, 34, 88] {
        let mut raw = exit_bytes(0, 0);
        raw.resize(length, 0);
        assert!(decode_native_syscall_info(&raw).is_err());
    }
}

#[test]
fn only_stdin_reads_and_stdout_writes_select_buffers() {
    for (number, fd, direction, vector) in [
        (63, 0, NativeStdioDirection::Read, false),
        (64, 1, NativeStdioDirection::Write, false),
        (65, 0, NativeStdioDirection::Read, true),
        (66, 1, NativeStdioDirection::Write, true),
    ] {
        let transfer = native_stdio_transfer(entry(number, fd, 4096, 4))
            .unwrap()
            .unwrap();
        assert_eq!(transfer.direction, direction);
        assert_eq!(transfer.descriptor, u8::try_from(fd).unwrap());
        assert_eq!(
            matches!(transfer.buffers, NativeStdioBuffers::Vector { .. }),
            vector
        );
    }
    for (number, fd) in [
        (63, 9),
        (64, 2),
        (65, 8),
        (66, 2),
        (63, 1),
        (64, 0),
        (56, 0),
        (281, 1),
    ] {
        // These potentially private-file or unrelated buffers are not even
        // validated as candidate memory ranges.
        assert_eq!(
            native_stdio_transfer(entry(number, fd, u64::MAX, u64::MAX)).unwrap(),
            None
        );
    }
}

#[test]
fn scalar_ranges_allow_zero_length_but_reject_wrap_null_and_excess_data() {
    assert_eq!(
        native_stdio_transfer(entry(63, 0, 0, 0))
            .unwrap()
            .unwrap()
            .buffers,
        NativeStdioBuffers::Scalar(NativeMemoryRange {
            address: 0,
            length: 0
        })
    );
    assert!(native_stdio_transfer(entry(64, 1, 4096, MAX_NATIVE_STDIO_TRANSFER as u64)).is_ok());
    for (address, length) in [
        (0, 1),
        (u64::MAX, 1),
        (u64::MAX - 1, 2),
        (4096, MAX_NATIVE_STDIO_TRANSFER as u64 + 1),
        (4096, u64::MAX),
    ] {
        assert!(native_stdio_transfer(entry(63, 0, address, length)).is_err());
    }
}

#[test]
fn vector_tables_and_aggregate_lengths_have_independent_bounds() {
    let raw = iovecs(&[(4096, 3), (0, 0), (8192, 5)]);
    let decoded = decode_native_iovecs(&raw, 3).unwrap();
    assert_eq!(decoded.iter().map(|v| v.length).sum::<usize>(), 8);
    assert_eq!(
        decoded[1],
        NativeMemoryRange {
            address: 0,
            length: 0
        }
    );
    assert_eq!(decode_native_iovecs(&[], 0).unwrap(), Vec::new());
    assert!(decode_native_iovecs(&raw, 2).is_err());
    assert!(decode_native_iovecs(&raw[..raw.len() - 1], 3).is_err());
    assert!(decode_native_iovecs(&[], usize::MAX).is_err());
    assert!(decode_native_iovecs(
        &iovecs(&[(4096, MAX_NATIVE_STDIO_TRANSFER as u64), (8192, 1)]),
        2
    )
    .is_err());
    assert!(decode_native_iovecs(&iovecs(&[(u64::MAX, 1)]), 1).is_err());
    assert!(decode_native_iovecs(&iovecs(&[(0, 1)]), 1).is_err());
    assert!(native_stdio_transfer(entry(65, 0, 4096, 1025)).is_err());
    assert!(native_stdio_transfer(entry(65, 0, u64::MAX, 2)).is_err());
}

#[test]
fn completed_prefix_is_separate_from_requested_length_errno_and_restart() {
    assert_eq!(completed_native_stdio_bytes(3, false, 8).unwrap(), Some(3));
    assert_eq!(completed_native_stdio_bytes(0, false, 8).unwrap(), Some(0));
    assert_eq!(completed_native_stdio_bytes(-4, true, 8).unwrap(), None);
    assert_eq!(completed_native_stdio_bytes(-512, true, 8).unwrap(), None);
    for (result, error, requested) in [
        (9, false, 8),
        (-1, false, 8),
        (0, true, 8),
        (-4096, true, 8),
        (1, false, 0),
        (0, false, MAX_NATIVE_STDIO_TRANSFER + 1),
    ] {
        assert!(completed_native_stdio_bytes(result, error, requested).is_err());
    }
}

#[test]
fn entry_exit_pairing_cannot_duplicate_or_invent_completed_calls() {
    let value = entry(63, 0, 4096, 4);
    let mut sequence = NativeSyscallSequence::after_exec();
    assert_eq!(
        sequence.observe(NativeSyscallStop::Entry(value)).unwrap(),
        None
    );
    assert_eq!(
        sequence
            .observe(NativeSyscallStop::Exit {
                result: 3,
                is_error: false
            })
            .unwrap(),
        Some((value, 3, false))
    );
    assert!(sequence
        .observe(NativeSyscallStop::Exit {
            result: 3,
            is_error: false
        })
        .is_err());
    assert!(sequence.finish().is_err());
    let mut duplicate = NativeSyscallSequence::after_exec();
    duplicate.observe(NativeSyscallStop::Entry(value)).unwrap();
    assert!(duplicate.observe(NativeSyscallStop::Entry(value)).is_err());
    assert!(duplicate
        .observe(NativeSyscallStop::Exit {
            result: 4,
            is_error: false
        })
        .is_err());
    let mut sequence = NativeSyscallSequence::after_exec();
    assert_eq!(sequence.finish().unwrap(), None);
    assert!(sequence.observe(NativeSyscallStop::Entry(value)).is_err());
    assert!(sequence.finish().is_err());
}

#[test]
fn only_the_first_successful_exec_exit_can_lack_an_entry() {
    let mut sequence = NativeSyscallSequence::after_exec();
    assert_eq!(
        sequence
            .observe(NativeSyscallStop::Exit {
                result: 0,
                is_error: false
            })
            .unwrap(),
        None
    );
    assert!(sequence
        .observe(NativeSyscallStop::Exit {
            result: 0,
            is_error: false
        })
        .is_err());
    for (result, is_error) in [(1, false), (-1, true), (-1, false)] {
        assert!(NativeSyscallSequence::after_exec()
            .observe(NativeSyscallStop::Exit { result, is_error })
            .is_err());
    }
}

#[test]
fn death_returns_interrupted_state_without_completing_pending_io() {
    let value = entry(63, 0, 4096, 4);
    let mut sequence = NativeSyscallSequence::after_exec();
    sequence.observe(NativeSyscallStop::Entry(value)).unwrap();
    assert_eq!(sequence.finish().unwrap(), Some(value));
    assert!(sequence
        .observe(NativeSyscallStop::Exit {
            result: 4,
            is_error: false
        })
        .is_err());
}
