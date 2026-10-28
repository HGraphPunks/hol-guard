//! Size resident pools to the process's CPU allocation without losing the
//! reserved metadata lane or cancellation capacity for both active launches.

pub(crate) const CONTROL_WORKERS: usize = 1;
pub(crate) const MAX_ACTIVE_LAUNCHES: usize = 2;
const INTERACTIVE_RESERVE: usize = 2;
const MIN_EVALUATION: usize = CONTROL_WORKERS + MAX_ACTIVE_LAUNCHES + INTERACTIVE_RESERVE;

pub(crate) struct Budget {
    pub(crate) evaluation: usize,
    pub(crate) authentication: usize,
}

pub(crate) fn for_parallelism(parallelism: Option<usize>) -> Budget {
    match parallelism {
        Some(cpus) => Budget {
            evaluation: cpus.clamp(MIN_EVALUATION, 32),
            authentication: (cpus / 4).clamp(2, 8),
        },
        // An unavailable CPU count must not silently reduce the historical
        // fallback. A known small allocation is what permits smaller pools.
        None => Budget {
            evaluation: 16,
            authentication: 4,
        },
    }
}

fn current() -> Budget {
    for_parallelism(std::thread::available_parallelism().ok().map(|n| n.get()))
}

pub(crate) fn evaluation_workers() -> usize {
    current().evaluation
}

pub(crate) fn auth_workers() -> usize {
    current().authentication
}

pub(crate) fn evaluation_queue_capacity() -> usize {
    evaluation_workers().saturating_mul(2).clamp(32, 64)
}

pub(crate) fn auth_queue_capacity() -> usize {
    auth_workers().saturating_mul(8).clamp(32, 64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn small_allocations_leave_two_interactive_workers_beside_launches_and_metadata() {
        for cpus in [0, 1, 2, 4] {
            let budget = for_parallelism(Some(cpus));
            assert_eq!(budget.evaluation, 5);
            assert_eq!(budget.authentication, 2);
            assert_eq!(budget.evaluation - CONTROL_WORKERS - MAX_ACTIVE_LAUNCHES, 2);
        }
        for (cpus, evaluation, authentication) in
            [(8, 8, 2), (16, 16, 4), (32, 32, 8), (256, 32, 8)]
        {
            let budget = for_parallelism(Some(cpus));
            assert_eq!(
                (budget.evaluation, budget.authentication),
                (evaluation, authentication)
            );
        }
        let unknown = for_parallelism(None);
        assert_eq!((unknown.evaluation, unknown.authentication), (16, 4));
    }

    #[test]
    fn current_worker_and_queue_counts_stay_within_the_transport_bounds() {
        assert!((MIN_EVALUATION..=32).contains(&evaluation_workers()));
        assert!((2..=8).contains(&auth_workers()));
        assert!((32..=64).contains(&evaluation_queue_capacity()));
        assert!((32..=64).contains(&auth_queue_capacity()));
    }
}
