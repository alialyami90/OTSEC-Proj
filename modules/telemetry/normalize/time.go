package normalize

import (
	"strconv"
	"time"

	"otsec.local/otsec/contracts/event"
)

// dateOrders maps a DATE_F value (S22 p. 7.31) to the order of year, month
// and day in a printed date, and the printed width of each part. Figure
// 10.16 shows MDY as 02/28/2007. That DMY and YMD print the same parts with
// the same '/' separator is an assumption no figure shows
// (documented-untested); a date that does not fit is kept with
// invalid-time, never guessed.
var dateOrders = map[string][]datePart{
	"MDY": {{'M', 2}, {'D', 2}, {'Y', 4}},
	"DMY": {{'D', 2}, {'M', 2}, {'Y', 4}},
	"YMD": {{'Y', 4}, {'M', 2}, {'D', 2}},
}

type datePart struct {
	field byte
	width int
}

// deviceTime builds C4 device_time from the printed DATE and TIME of a SER
// row. Nothing is guessed: an unknown date order is assumed MDY and flagged,
// an unknown offset states no UTC, and a value that cannot be decoded keeps
// its native text with invalid-time and no wall clock.
func deviceTime(date, tm string, in Input, timeSource string) event.DeviceTime {
	dt := event.DeviceTime{
		Native:         date + " " + tm,
		NativeEncoding: event.EncodingText,
		Format:         TimeFormat,
		Offset:         "unknown",
		OffsetBasis:    event.BasisNone,
		ResolutionNS:   1_000_000_000,
		Quality:        &event.TimeQuality{TimeSource: timeSource, Sync: event.SyncUnknown, AccuracyRelativeNS: ptr(accuracyRelativeNS), Scope: event.ScopeReport},
	}
	order := in.DateOrder
	if order == "" {
		order = "MDY"
		dt.Flags = append(dt.Flags, "date-format-assumed:MDY")
	}
	if in.Offset != "" {
		dt.Offset, dt.OffsetBasis = in.Offset, in.OffsetBasis
	}
	y, mo, d, okDate := parseDate(date, dateOrders[order])
	h, mi, s, frac, okTime := parseTime(tm)
	if okTime {
		dt.ResolutionNS = 1
		for i := len(frac); i < 9; i++ {
			dt.ResolutionNS *= 10
		}
	}
	valid := okDate && okTime && mo >= 1 && mo <= 12 && d >= 1 && d <= daysIn(y, mo) && h <= 23 && mi <= 59 && s <= 60
	if !valid {
		dt.Flags = append(dt.Flags, "invalid-time")
		return dt
	}
	setWall(&dt, y, mo, d, h, mi, s, frac)
	return dt
}

// setWall states dt's wall clock, and its UTC when dt.Offset is known, for
// a date and time already checked to be in range (seconds up to 60). A leap
// second is the last second of a UTC day: with a known offset its UTC minute
// must be 23:59, otherwise dt gets invalid-time; with an unknown offset any
// local minute could be (C4 accepts it). C4 states no UTC for it.
func setWall(dt *event.DeviceTime, y, mo, d, h, mi, s int, frac string) {
	wall := date4(y) + "-" + two(mo) + "-" + two(d) + "T" + two(h) + ":" + two(mi) + ":" + two(s)
	if frac != "" {
		wall += "." + frac
	}
	var off time.Duration
	if dt.Offset != "unknown" {
		hh, _ := strconv.Atoi(dt.Offset[1:3])
		mm, _ := strconv.Atoi(dt.Offset[4:6])
		off = time.Duration(hh)*time.Hour + time.Duration(mm)*time.Minute
		if dt.Offset[0] == '-' {
			off = -off
		}
	}
	if s == 60 {
		if dt.Offset != "unknown" {
			u := time.Date(y, time.Month(mo), d, h, mi, 59, 0, time.UTC).Add(-off)
			if u.Hour() != 23 || u.Minute() != 59 {
				dt.Flags = append(dt.Flags, "invalid-time")
				return
			}
		}
		dt.WallClock = wall
		return
	}
	dt.WallClock = wall
	if dt.Offset != "unknown" {
		u := time.Date(y, time.Month(mo), d, h, mi, s, 0, time.UTC).Add(-off)
		dt.UTC = u.Format("2006-01-02T15:04:05")
		if frac != "" {
			dt.UTC += "." + frac
		}
		dt.UTC += "Z"
	}
}

// parseDate reads a date of exactly the printed form: the parts in order,
// each of its width in ASCII digits, separated by '/'.
func parseDate(s string, parts []datePart) (y, m, d int, ok bool) {
	pos := 0
	for i, p := range parts {
		if i > 0 {
			if pos >= len(s) || s[pos] != '/' {
				return 0, 0, 0, false
			}
			pos++
		}
		v, ok := digits(s, pos, p.width)
		if !ok {
			return 0, 0, 0, false
		}
		pos += p.width
		switch p.field {
		case 'Y':
			y = v
		case 'M':
			m = v
		case 'D':
			d = v
		}
	}
	return y, m, d, pos == len(s)
}

// parseTime reads HH:MM:SS with an optional fraction of 1 to 9 digits.
func parseTime(s string) (h, m, sec int, frac string, ok bool) {
	var ok1, ok2, ok3 bool
	h, ok1 = digits(s, 0, 2)
	m, ok2 = digits(s, 3, 2)
	sec, ok3 = digits(s, 6, 2)
	if !ok1 || !ok2 || !ok3 || s[2] != ':' || s[5] != ':' {
		return 0, 0, 0, "", false
	}
	if len(s) == 8 {
		return h, m, sec, "", true
	}
	if s[8] != '.' || len(s) < 10 || len(s) > 18 {
		return 0, 0, 0, "", false
	}
	frac = s[9:]
	if _, ok := digits(frac, 0, len(frac)); !ok {
		return 0, 0, 0, "", false
	}
	return h, m, sec, frac, true
}

func digits(s string, at, n int) (int, bool) {
	if at < 0 || at+n > len(s) || n == 0 {
		return 0, false
	}
	v := 0
	for i := at; i < at+n; i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return 0, false
		}
		v = v*10 + int(c-'0')
	}
	return v, true
}

func daysIn(y, m int) int {
	return time.Date(y, time.Month(m)+1, 0, 0, 0, 0, 0, time.UTC).Day()
}

func two(v int) string {
	if v < 10 {
		return "0" + strconv.Itoa(v)
	}
	return strconv.Itoa(v)
}

func date4(v int) string {
	s := strconv.Itoa(v)
	for len(s) < 4 {
		s = "0" + s
	}
	return s
}

func ptr[T any](v T) *T { return &v }
