package main

import (
	"math"
	"reflect"
)

// Paging is uniform across tools: a paged result reports total, limit and
// offset, and next_offset when there is another page, so an agent never does
// the arithmetic (or stops a page early). Results with a server cursor report
// next_cursor instead.

// nextOffset is the offset of the page after one that started at offset and
// held n rows, or 0 when there is none.
func nextOffset(offset, n, total int64) int32 {
	next := offset + n
	if n <= 0 || next >= total || next > math.MaxInt32 {
		return 0
	}
	return int32(next) //nolint:gosec // bounded by the MaxInt32 check above
}

// fillNextOffset sets NextOffset on any output that reports Total, Limit and
// Offset, so a paged tool cannot forget it.
func fillNextOffset(out any) {
	v := reflect.ValueOf(out)
	if v.Kind() != reflect.Pointer || v.Elem().Kind() != reflect.Struct {
		return
	}
	s := v.Elem()
	total, limit, offset, next := s.FieldByName("Total"), s.FieldByName("Limit"), s.FieldByName("Offset"), s.FieldByName("NextOffset")
	if !total.IsValid() || !limit.IsValid() || !offset.IsValid() || !next.IsValid() || !next.CanSet() || next.Int() != 0 {
		return
	}
	if !isInt(total) || !isInt(limit) || !isInt(offset) || !isInt(next) {
		return
	}
	next.SetInt(int64(nextOffset(offset.Int(), limit.Int(), total.Int())))
}

func isInt(v reflect.Value) bool {
	switch v.Kind() { //nolint:exhaustive // only signed integers carry paging
	case reflect.Int, reflect.Int32, reflect.Int64:
		return true
	}
	return false
}
