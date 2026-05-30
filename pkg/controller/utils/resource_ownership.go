package utils

import (
	"fmt"

	"github.com/go-logr/logr"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// ConditionRecorder is satisfied by status.Manager and allows HandleCreateConflict
// to record conditions without importing the status package.
type ConditionRecorder interface {
	AddCondition(conditionType, reason, message string, status metav1.ConditionStatus)
}

// CheckResourceConflict verifies that an existing resource is managed by the operator
// by checking the managed-by label. Returns an error if the resource exists but does not
// have the operator's managed-by label, indicating a naming conflict with a pre-existing resource.
func CheckResourceConflict(existing client.Object) error {
	labels := existing.GetLabels()
	if labels != nil && labels[AppManagedByLabelKey] == AppManagedByLabelValue {
		return nil
	}
	return ResourceConflictError(existing.GetNamespace(), existing.GetName())
}

// HandleCreateConflict checks if a Create error is an AlreadyExists conflict and, if so,
// logs the error, records a ResourceConflict condition, and returns the conflict error.
// Returns nil if the error is not an AlreadyExists conflict.
func HandleCreateConflict(err error, obj client.Object, log logr.Logger, recorder ConditionRecorder, conditionType string) error {
	if !kerrors.IsAlreadyExists(err) {
		return nil
	}
	conflictErr := ResourceConflictError(obj.GetNamespace(), obj.GetName())
	log.Error(conflictErr, "resource conflict detected")
	recorder.AddCondition(conditionType, "ResourceConflict",
		conflictErr.Error(), metav1.ConditionFalse)
	return conflictErr
}

// IsResourceConflictOnCreate checks if a Create error is an AlreadyExists error,
// which indicates a naming conflict with a pre-existing resource not visible in
// the operator's label-filtered cache.
func IsResourceConflictOnCreate(err error) bool {
	return kerrors.IsAlreadyExists(err)
}

// ResourceConflictError returns a formatted error for a resource conflict.
func ResourceConflictError(namespace, name string) error {
	if namespace != "" {
		return fmt.Errorf("resource %s/%s already exists but is not managed by the operator", namespace, name)
	}
	return fmt.Errorf("resource %s already exists but is not managed by the operator", name)
}
