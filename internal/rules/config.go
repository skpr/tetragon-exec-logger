package rules

import (
	"fmt"
	"os"
	"slices"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"gopkg.in/yaml.v3"
)

// Config holds the configuration for process event rules.
type Config struct {
	// A list of process event rules.
	Rules Rules `yaml:"rules"`
}

// Rules list which are matched against process exec events.
type Rules []Rule

// MatchProcessExec checks if the given process exec event matches the rule.
func (r Rules) MatchProcessExec(pe *tetragon.ProcessExec) bool {
	// We only match process exec events with pod information.
	pod := pe.GetProcess().GetPod()
	if pod == nil {
		return false
	}

	matchLabels := func(ruleLabels, podLabels map[string]string) bool {
		for key, value := range ruleLabels {
			if podVal, ok := podLabels[key]; !ok || podVal != value {
				return false
			}
		}

		return true
	}

	for _, rule := range r {
		// It's not a match if the namespace IS NOT on the list and a list was defined.
		if !slices.Contains(rule.Namespaces, pod.Namespace) && len(rule.Namespaces) > 0 {
			continue
		}

		// It's not a match if the container IS NOT on the list and a list was defined.
		if !slices.Contains(rule.Containers, pe.Process.Pod.Container.Name) && len(rule.Containers) > 0 {
			continue
		}

		if !matchLabels(rule.Labels, pod.PodLabels) && len(rule.Labels) > 0 {
			continue
		}

		// It's not a match if the binary IS on the exclude list and a list was defined.
		if slices.Contains(rule.ExcludeBinaries, pe.Process.Binary) && len(rule.ExcludeBinaries) > 0 {
			continue
		}

		// If we reach here, the rule matches
		return true
	}

	return false
}

// Rule defines a set of criteria to match process exec events.
type Rule struct {
	// A list of namespaces to match. If empty then all namespaces.
	Namespaces []string `yaml:"namespaces"`
	// A list of containers to match. If empty then all containers.
	Containers []string `yaml:"containers"`
	// A list of labels to match. If empty then all labels.
	Labels map[string]string `yaml:"labels"`
	// A list of binaries to exclude. If empty then no binaries are excluded.
	ExcludeBinaries []string `yaml:"excludeBinaries"`
}

// LoadConfigFromFile loads the configuration from a file.
func LoadConfigFromFile(filePath string) (Config, error) {
	var config Config

	// Read YAML file from disk
	data, err := os.ReadFile(filePath)
	if err != nil {
		return config, fmt.Errorf("failed to read file: %w", err)
	}

	// Unmarshal YAML into struct
	if err := yaml.Unmarshal(data, &config); err != nil {
		return config, fmt.Errorf("failed to unmarshal yaml: %w", err)
	}

	return config, nil
}
