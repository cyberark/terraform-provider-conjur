package provider

import (
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// ValidateBranch validates that a branch path is properly formatted with no empty segments.
func ValidateBranch(branch types.String, diagnostics *diag.Diagnostics, fieldName string) {
	if diagnostics == nil {
		return
	}

	branchValue := branch.ValueString()

	normalized := strings.Trim(branchValue, "/")
	if normalized != "" {
		parts := strings.Split(normalized, "/")
		for _, part := range parts {
			if part == "" {
				diagnostics.AddError(
					"Invalid branch",
					fmt.Sprintf("%s branch cannot contain empty segments (double slashes or trailing slashes are not allowed).", fieldName),
				)
				break
			}
		}
	} else {
		diagnostics.AddError(
			"Invalid branch",
			fmt.Sprintf("%s branch cannot be empty.", fieldName),
		)
	}
}

// ValidateNonEmpty validates that a string value is not empty or whitespace-only.
// Unknown values are skipped because they may not be resolved during ValidateConfig..
func ValidateNonEmpty(val types.String, diagnostics *diag.Diagnostics, fieldName string) {
	if diagnostics == nil {
		return
	}

	if val.IsUnknown() {
		return
	}

	if strings.TrimSpace(val.ValueString()) == "" {
		diagnostics.AddError(
			"Invalid value",
			fmt.Sprintf("%s cannot be empty.", fieldName),
		)
	}
}

// ValidateContainedIn validates that a string value is one of the allowed values.
// The comparison is case-insensitive and trims whitespace.
// If allowEmpty is true, empty values are allowed (useful for optional fields).
func ValidateContainedIn(val types.String, diagnostics *diag.Diagnostics, fieldName string, allowedVals []string, allowEmpty bool) {
	if diagnostics == nil {
		return
	}

	valStr := strings.TrimSpace(val.ValueString())
	if valStr == "" {
		if allowEmpty {
			return // Empty value is allowed
		}
		diagnostics.AddError(
			"Invalid value",
			fmt.Sprintf("%s cannot be empty.", fieldName),
		)
		return
	}

	valLower := strings.ToLower(valStr)
	allowedMap := make(map[string]bool)
	for _, v := range allowedVals {
		allowedMap[strings.ToLower(v)] = true
	}

	if !allowedMap[valLower] {
		diagnostics.AddError(
			"Invalid value",
			fmt.Sprintf("%s must be one of: %s. Got: %q", fieldName, strings.Join(allowedVals, ", "), val.ValueString()),
		)
	}
}

// ValidatePrivileges validates that privileges are valid and at least one is provided.
// Valid privileges: read, update, execute, create
func ValidatePrivileges(privileges types.List, diagnostics *diag.Diagnostics, fieldName string) {
	if diagnostics == nil {
		return
	}

	validPrivileges := []string{"read", "update", "execute", "create"}
	validPrivilegeMap := make(map[string]bool)
	for _, p := range validPrivileges {
		validPrivilegeMap[p] = true
	}

	if privileges.IsNull() || privileges.IsUnknown() {
		diagnostics.AddError(
			"Invalid privileges",
			fmt.Sprintf("%s cannot be empty.", fieldName),
		)
		return
	}

	elements := privileges.Elements()
	if len(elements) == 0 {
		diagnostics.AddError(
			"Invalid privileges",
			fmt.Sprintf("At least one privilege must be specified in %s.", fieldName),
		)
		return
	}

	for i, elem := range elements {
		priv := strings.ToLower(strings.TrimSpace(elem.(types.String).ValueString()))
		if !validPrivilegeMap[priv] {
			diagnostics.AddError(
				"Invalid privilege",
				fmt.Sprintf("%s[%d] must be one of: %s. Got: %q", fieldName, i, strings.Join(validPrivileges, ", "), elem.(types.String).ValueString()),
			)
		}
	}
}
