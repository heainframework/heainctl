package ctl

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"
)

// View is how a list is shown as a table: the array (a top-level field
// name, "" for the answer itself or the first array of objects found) and
// the columns (dotted paths; empty = the item's scalar fields).
type View struct {
	Array string
	Cols  []string
	KV    bool // an object shown as "key: value" lines
}

func (v *View) render(w io.Writer, x any) bool {
	if v.KV {
		m, ok := x.(map[string]any)
		if !ok {
			return false
		}
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
		for _, k := range keys {
			fmt.Fprintf(tw, "%s:\t%s\n", k, cell(m[k]))
		}
		return tw.Flush() == nil
	}
	items, ok := v.items(x)
	if !ok {
		return false
	}
	cols := v.Cols
	if len(items) > 0 {
		var have []string
		for _, c := range cols {
			for _, it := range items {
				if _, ok := lookup(it, c); ok {
					have = append(have, c)
					break
				}
			}
		}
		cols = have
		if len(cols) == 0 {
			cols = scalarKeys(items[0])
		}
	}
	if len(cols) == 0 {
		cols = v.Cols
	}
	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	head := make([]string, len(cols))
	for i, c := range cols {
		head[i] = strings.ToUpper(strings.ReplaceAll(c, ".", "_"))
	}
	fmt.Fprintln(tw, strings.Join(head, "\t"))
	for _, it := range items {
		row := make([]string, len(cols))
		for i, c := range cols {
			val, _ := lookup(it, c)
			row[i] = cell(val)
		}
		fmt.Fprintln(tw, strings.Join(row, "\t"))
	}
	if err := tw.Flush(); err != nil {
		return false
	}
	if len(items) == 0 {
		fmt.Fprintln(w, "(none)")
	}
	return true
}

func (v *View) items(x any) ([]map[string]any, bool) {
	var arr []any
	switch t := x.(type) {
	case []any:
		arr = t
	case map[string]any:
		if v.Array != "" {
			a, ok := t[v.Array].([]any)
			if !ok {
				if t[v.Array] == nil {
					return nil, true // null list: none
				}
				return nil, false
			}
			arr = a
		} else {
			keys := make([]string, 0, len(t))
			for k := range t {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				if a, ok := t[k].([]any); ok {
					arr = a
					break
				}
			}
			if arr == nil {
				return nil, false
			}
		}
	default:
		return nil, false
	}
	out := make([]map[string]any, 0, len(arr))
	for _, e := range arr {
		m, ok := e.(map[string]any)
		if !ok {
			return nil, false
		}
		out = append(out, m)
	}
	return out, true
}

func lookup(m map[string]any, path string) (any, bool) {
	var cur any = m
	for _, p := range strings.Split(path, ".") {
		mm, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = mm[p]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}

func scalarKeys(m map[string]any) []string {
	var out []string
	for k, v := range m {
		switch v.(type) {
		case map[string]any, []any:
		default:
			out = append(out, k)
		}
	}
	sort.Strings(out)
	if len(out) > 8 {
		out = out[:8]
	}
	return out
}

func cell(v any) string {
	switch t := v.(type) {
	case nil:
		return "-"
	case string:
		if t == "" {
			return "-"
		}
		return strings.ReplaceAll(t, "\n", " ")
	case bool:
		if t {
			return "yes"
		}
		return "no"
	case float64:
		if t == float64(int64(t)) {
			return fmt.Sprintf("%d", int64(t))
		}
		return fmt.Sprintf("%g", t)
	case []any:
		parts := make([]string, 0, len(t))
		for _, e := range t {
			parts = append(parts, cell(e))
		}
		return strings.Join(parts, ",")
	default:
		b, _ := json.Marshal(t)
		s := string(b)
		if len(s) > 60 {
			s = s[:57] + "..."
		}
		return s
	}
}
