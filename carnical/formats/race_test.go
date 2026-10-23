// SPDX-License-Identifier: Apache-2.0

//go:build race

package formats

// raceDetector is true under -race, which makes every step several times slower.
const raceDetector = true
