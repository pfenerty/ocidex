package main

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"unicode"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Data from SBOMs, advisories and registries is written by third parties:
// a package description, an advisory summary, an image label or a tag name can
// say anything, including text aimed at the model reading it (ADR-0058 A8).
// Every tool result passes through sanitizeValue on its way out, so no tool can
// forget to. It does two things to every string:
//
//   - strips control and invisible formatting characters (bidi overrides,
//     zero-width joiners, tag characters), which hide text from a person
//     reviewing a transcript while the model still reads it;
//   - caps the length, so one field cannot fill the context window.
//
// It cannot make text harmless: a plain-language instruction survives. That is
// what the untrusted-data paragraph in the server instructions is for, and why
// data is only ever returned in named fields, never spliced into prose.

// maxStringRunes caps any single string in a tool result.
const maxStringRunes = 4096

// truncatedMark ends a string that was cut.
const truncatedMark = " …[truncated]"

// sanitizeString strips control and invisible formatting characters from s,
// keeping newlines and tabs, and caps its length.
func sanitizeString(s string) string {
	clean := true
	n := 0
	for _, r := range s {
		n++
		if dropRune(r) {
			clean = false
		}
	}
	if clean && n <= maxStringRunes {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	kept := 0
	for _, r := range s {
		if dropRune(r) {
			continue
		}
		if kept == maxStringRunes {
			b.WriteString(truncatedMark)
			break
		}
		b.WriteRune(r)
		kept++
	}
	return b.String()
}

// dropRune reports whether r is removed: control characters other than newline
// and tab, every format character (Cf: bidi controls, zero-width characters,
// tag characters), private-use characters, and the line and paragraph
// separators that some renderers treat as line breaks a reviewer cannot see.
func dropRune(r rune) bool {
	switch r {
	case '\n', '\t':
		return false
	case ' ', ' ':
		return true
	}
	return unicode.Is(unicode.Cc, r) || unicode.Is(unicode.Cf, r) || unicode.Is(unicode.Co, r)
}

// sanitizeValue sanitizes every string reachable from v, in place. v must be
// a pointer.
func sanitizeValue(v any) {
	walk(reflect.ValueOf(v))
}

func walk(v reflect.Value) {
	// Only the kinds that can hold a string need a case.
	//exhaustive:ignore
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface:
		if !v.IsNil() {
			walk(v.Elem())
		}
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			if v.Type().Field(i).IsExported() {
				walk(v.Field(i))
			}
		}
	case reflect.Slice, reflect.Array:
		for i := 0; i < v.Len(); i++ {
			walk(v.Index(i))
		}
	case reflect.Map:
		for _, k := range v.MapKeys() {
			val := v.MapIndex(k)
			if val.Kind() == reflect.String {
				v.SetMapIndex(k, reflect.ValueOf(sanitizeString(val.String())).Convert(val.Type()))
				continue
			}
			// Map values are not addressable: copy, walk, put back.
			cp := reflect.New(val.Type()).Elem()
			cp.Set(val)
			walk(cp)
			v.SetMapIndex(k, cp)
		}
	case reflect.String:
		if v.CanSet() {
			v.SetString(sanitizeString(v.String()))
		}
	default:
		// Numbers, booleans, channels and funcs carry no text.
	}
}

// addTool is mcp.AddTool with the untrusted-data pass applied to every result
// and error. Every tool registers through it; TestEveryToolIsRegisteredThroughAddTool
// fails on a direct mcp.AddTool call.
func addTool[In, Out any](srv *mcp.Server, t *mcp.Tool, h mcp.ToolHandlerFor[In, Out]) {
	mcp.AddTool(srv, t, func(ctx context.Context, req *mcp.CallToolRequest, in In) (*mcp.CallToolResult, Out, error) {
		res, out, err := h(ctx, req, in)
		if err != nil {
			return res, out, errors.New(sanitizeString(err.Error()))
		}
		sanitizeValue(&out)
		fillNextOffset(&out)
		if res != nil {
			for _, c := range res.Content {
				if tc, ok := c.(*mcp.TextContent); ok {
					tc.Text = sanitizeString(tc.Text)
				}
			}
		}
		return res, out, nil
	})
}
