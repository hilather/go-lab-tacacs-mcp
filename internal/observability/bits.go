package observability

import "math"

func floatToBits(v float64) uint64 { return math.Float64bits(v) }

func bitsToFloat(b uint64) float64 { return math.Float64frombits(b) }
