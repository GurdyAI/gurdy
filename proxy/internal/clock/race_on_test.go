//go:build race

package clock

// raceDetector reports whether this binary was built with -race. The timing
// assertion in TestObserveIsCheapEnoughToLeaveOn is meaningless when it is:
// the detector instruments every atomic access, which both inflates the cost
// and compresses the differences the test exists to detect.
const raceDetector = true
