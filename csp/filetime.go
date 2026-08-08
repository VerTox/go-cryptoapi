//go:build linux

package csp

/*
#include "common.h"
*/
import "C"

import "time"

// fileTimeToTime converts a Win32 FILETIME (100-ns ticks since 1601-01-01 UTC)
// to a Go time.Time. Returns zero time for an all-zero FILETIME.
// FILETIME is an unsigned 64-bit count; the intermediate assembly is done in
// uint64 to avoid the high DWORD's MSB being interpreted as a sign bit.
func fileTimeToTime(ft C.FILETIME) time.Time {
	const ticksPerSecond = uint64(10_000_000)
	const epochDiffSeconds = int64(11644473600)

	ticks := (uint64(ft.dwHighDateTime) << 32) | uint64(ft.dwLowDateTime)
	if ticks == 0 {
		return time.Time{}
	}

	sec := int64(ticks/ticksPerSecond) - epochDiffSeconds
	nsec := int64((ticks % ticksPerSecond) * 100)

	return time.Unix(sec, nsec).UTC()
}
