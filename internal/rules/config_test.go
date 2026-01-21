package rules

import (
	"testing"

	"github.com/cilium/tetragon/api/v1/tetragon"
)

func TestRules_MatchProcessExec(t *testing.T) {
	makeProcessExec := func(namespace, container string, labels map[string]string, binary string) *tetragon.ProcessExec {
		return &tetragon.ProcessExec{
			Process: &tetragon.Process{
				Binary: binary,
				Pod: &tetragon.Pod{
					Namespace: namespace,
					PodLabels: labels,
					Container: &tetragon.Container{
						Name: container,
					},
				},
			},
		}
	}

	tests := []struct {
		name  string
		rules Rules
		pe    *tetragon.ProcessExec
		want  bool
	}{
		{
			name:  "no pod info => false",
			rules: Rules{{}},
			pe: &tetragon.ProcessExec{
				Process: &tetragon.Process{
					Binary: "/bin/sh",
				},
			},
			want: false,
		},
		{
			name: "namespace list defined but does not contain pod namespace => false",
			rules: Rules{
				{Namespaces: []string{"prod"}},
			},
			pe:   makeProcessExec("dev", "c1", map[string]string{"app": "x"}, "/bin/sh"),
			want: false,
		},
		{
			name: "container list defined but does not contain pod container => false",
			rules: Rules{
				{Containers: []string{"allowed"}},
			},
			pe:   makeProcessExec("ns", "other", map[string]string{"app": "x"}, "/bin/sh"),
			want: false,
		},
		{
			name: "labels defined but do not match => false",
			rules: Rules{
				{Labels: map[string]string{"app": "api", "tier": "backend"}},
			},
			pe:   makeProcessExec("ns", "c1", map[string]string{"app": "api", "tier": "frontend"}, "/bin/sh"),
			want: false,
		},
		{
			name: "binary is excluded => false",
			rules: Rules{
				{ExcludeBinaries: []string{"/bin/sh"}},
			},
			pe:   makeProcessExec("ns", "c1", map[string]string{"app": "x"}, "/bin/sh"),
			want: false,
		},
		{
			name: "empty criteria rule matches any pod exec => true",
			rules: Rules{
				{},
			},
			pe:   makeProcessExec("any", "any", map[string]string{"k": "v"}, "/usr/bin/curl"),
			want: true,
		},
		{
			name: "all criteria match => true",
			rules: Rules{
				{
					Namespaces:      []string{"ns-a", "ns-b"},
					Containers:      []string{"c1"},
					Labels:          map[string]string{"app": "api", "tier": "backend"},
					ExcludeBinaries: []string{"/bin/sh"},
				},
			},
			pe:   makeProcessExec("ns-b", "c1", map[string]string{"app": "api", "tier": "backend", "extra": "ok"}, "/usr/bin/curl"),
			want: true,
		},
		{
			name: "multiple rules: first fails, second matches => true",
			rules: Rules{
				{Namespaces: []string{"prod"}},
				{Containers: []string{"c1"}},
			},
			pe:   makeProcessExec("dev", "c1", map[string]string{"app": "x"}, "/usr/bin/curl"),
			want: true,
		},
		{
			name: "labels rule requires subset match (pod has extra labels) => true",
			rules: Rules{
				{Labels: map[string]string{"app": "api"}},
			},
			pe:   makeProcessExec("ns", "c1", map[string]string{"app": "api", "tier": "backend"}, "/usr/bin/curl"),
			want: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.rules.MatchProcessExec(tc.pe)
			if got != tc.want {
				t.Fatalf("MatchProcessExec() = %v, want %v", got, tc.want)
			}
		})
	}
}
