package utils

import (
	"fmt"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func TestCheckResourceConflict(t *testing.T) {
	tests := []struct {
		name      string
		existing  *corev1.ConfigMap
		expectErr bool
		errSubstr string
	}{
		{
			name: "resource with managed-by label - no conflict",
			existing: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "spire-server",
					Namespace: "test-ns",
					Labels: map[string]string{
						AppManagedByLabelKey: AppManagedByLabelValue,
					},
				},
			},
			expectErr: false,
		},
		{
			name: "resource with managed-by label and other labels - no conflict",
			existing: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "spire-server",
					Namespace: "test-ns",
					Labels: map[string]string{
						AppManagedByLabelKey:         AppManagedByLabelValue,
						"app.kubernetes.io/instance": "cluster",
						"custom-label":               "value",
					},
				},
			},
			expectErr: false,
		},
		{
			name: "resource with no labels - conflict",
			existing: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "spire-server",
					Namespace: "test-ns",
				},
			},
			expectErr: true,
			errSubstr: "test-ns/spire-server already exists but is not managed by the operator",
		},
		{
			name: "resource with different managed-by value - conflict",
			existing: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "spire-server",
					Namespace: "test-ns",
					Labels: map[string]string{
						AppManagedByLabelKey: "some-other-operator",
					},
				},
			},
			expectErr: true,
			errSubstr: "already exists but is not managed by the operator",
		},
		{
			name: "resource with labels but no managed-by - conflict",
			existing: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "spire-server",
					Namespace: "test-ns",
					Labels: map[string]string{
						"app.kubernetes.io/name": "spire-server",
					},
				},
			},
			expectErr: true,
			errSubstr: "already exists but is not managed by the operator",
		},
		{
			name: "cluster-scoped resource without label - conflict message has no namespace",
			existing: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name: "spire-server",
				},
			},
			expectErr: true,
			errSubstr: "resource spire-server already exists but is not managed by the operator",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CheckResourceConflict(tt.existing)
			if tt.expectErr {
				if err == nil {
					t.Errorf("expected error but got nil")
				} else if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Errorf("expected error to contain %q, got %q", tt.errSubstr, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("expected no error but got: %v", err)
				}
			}
		})
	}
}

func TestIsResourceConflictOnCreate(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "AlreadyExists error is a conflict",
			err:      kerrors.NewAlreadyExists(schema.GroupResource{Group: "", Resource: "configmaps"}, "spire-server"),
			expected: true,
		},
		{
			name:     "NotFound error is not a conflict",
			err:      kerrors.NewNotFound(schema.GroupResource{Group: "", Resource: "configmaps"}, "spire-server"),
			expected: false,
		},
		{
			name:     "generic error is not a conflict",
			err:      fmt.Errorf("connection refused"),
			expected: false,
		},
		{
			name:     "nil error is not a conflict",
			err:      nil,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsResourceConflictOnCreate(tt.err)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}
