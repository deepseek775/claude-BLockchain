package pos

import "testing"

func TestSelectValidatorDeterministic(t *testing.T) {
	stakes := map[string]uint64{"a": 10, "b": 20, "c": 5}
	v1 := SelectValidator("deadbeef", 42, stakes)
	v2 := SelectValidator("deadbeef", 42, stakes)
	if v1 != v2 {
		t.Fatalf("expected deterministic selection, got %s then %s", v1, v2)
	}
	if v1 != "a" && v1 != "b" && v1 != "c" {
		t.Fatalf("selected unknown validator %q", v1)
	}
}

func TestSelectValidatorSkipsZeroStake(t *testing.T) {
	stakes := map[string]uint64{"a": 0, "b": 100}
	for h := uint64(0); h < 50; h++ {
		if got := SelectValidator("seed", h, stakes); got != "b" {
			t.Fatalf("height %d: expected only staker b, got %s", h, got)
		}
	}
}

func TestSelectValidatorEmpty(t *testing.T) {
	if got := SelectValidator("seed", 1, nil); got != "" {
		t.Fatalf("expected empty result for no stakers, got %q", got)
	}
	if got := SelectValidator("seed", 1, map[string]uint64{"a": 0}); got != "" {
		t.Fatalf("expected empty result when all stakes are zero, got %q", got)
	}
}

func TestSelectValidatorRoughlyProportional(t *testing.T) {
	stakes := map[string]uint64{"a": 90, "b": 10}
	counts := map[string]int{}
	const n = 2000
	for h := uint64(0); h < n; h++ {
		counts[SelectValidator("fixed-seed", h, stakes)]++
	}
	// Not a strict statistical test - just a sanity check that the
	// heavier staker wins meaningfully more often.
	if counts["a"] <= counts["b"] {
		t.Fatalf("expected staker a (90%% stake) to win more often than b (10%%): a=%d b=%d", counts["a"], counts["b"])
	}
}
