//go:build !race

package clock

// raceDetector reports whether this binary was built with -race. See the
// //go:build race twin for why the timing assertion cares.
const raceDetector = false
