package main

import "testing"

func TestPathList(t *testing.T) {
	const dir = `C:\Program Files\Whalescale`
	for _, tc := range []struct{ in, want string }{
		{`C:\Windows\system32;C:\Windows`, `C:\Windows\system32;C:\Windows;` + dir},
		{`C:\Windows;`, `C:\Windows;` + dir},
		{``, dir},
	} {
		got, changed := pathWith(tc.in, dir)
		if got != tc.want || !changed {
			t.Errorf("pathWith(%q) = %q, %v", tc.in, got, changed)
		}
		// Adding twice changes nothing; removing restores the original.
		if again, changed := pathWith(got, dir); again != got || changed {
			t.Errorf("second pathWith(%q) = %q, %v", got, again, changed)
		}
		if back, changed := pathWithout(got, dir); !changed || (back != tc.in && back+";" != tc.in) {
			t.Errorf("pathWithout(%q) = %q, %v", got, back, changed)
		}
	}
	// Already there, spelled differently: left alone, and removable.
	in := `%SystemRoot%;c:\program files\whalescale\;C:\Tools`
	if got, changed := pathWith(in, dir); got != in || changed {
		t.Errorf("pathWith(%q) = %q, %v", in, got, changed)
	}
	if got, changed := pathWithout(in, dir); got != `%SystemRoot%;C:\Tools` || !changed {
		t.Errorf("pathWithout(%q) = %q, %v", in, got, changed)
	}
	if got, changed := pathWithout(`C:\Windows`, dir); got != `C:\Windows` || changed {
		t.Errorf("pathWithout without the entry = %q, %v", got, changed)
	}
}
