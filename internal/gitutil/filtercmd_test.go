package gitutil

import "testing"

func TestFilterCommand(t *testing.T) {
	tests := []struct {
		name    string
		exe     string
		windows bool
		want    string
	}{
		{
			name: "plain unix path needs no quoting",
			exe:  "/usr/local/bin/strucrypt",
			want: "/usr/local/bin/strucrypt clean %f",
		},
		{
			name:    "windows path is emitted with forward slashes",
			exe:     `C:\Users\dev\AppData\Local\Programs\strucrypt\strucrypt.exe`,
			windows: true,
			want:    "C:/Users/dev/AppData/Local/Programs/strucrypt/strucrypt.exe clean %f",
		},
		{
			name:    "a space forces quoting",
			exe:     `C:\Program Files\strucrypt\strucrypt.exe`,
			windows: true,
			want:    `"C:/Program Files/strucrypt/strucrypt.exe" clean %f`,
		},
		{
			// A Windows user name is the usual source of these.
			name:    "non-ascii forces quoting",
			exe:     `C:\Users\Jörg\strucrypt.exe`,
			windows: true,
			want:    `"C:/Users/Jörg/strucrypt.exe" clean %f`,
		},
		{
			name: "shell metacharacters are escaped inside the quotes",
			exe:  "/opt/str$ucrypt/strucrypt",
			want: `"/opt/str\$ucrypt/strucrypt" clean %f`,
		},
		{
			// A backslash is a legal Unix filename character, so it must
			// survive rather than be rewritten into a separator.
			name: "backslash in a unix path is escaped, not converted",
			exe:  `/opt/od\d/strucrypt`,
			want: `"/opt/od\\d/strucrypt" clean %f`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := filterCommand(tt.exe, "clean", tt.windows); got != tt.want {
				t.Errorf("filterCommand(%q, clean, windows=%v)\n got %s\nwant %s",
					tt.exe, tt.windows, got, tt.want)
			}
		})
	}
}
