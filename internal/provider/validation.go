package provider

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// normalizeBranch is the single source of truth for turning a configured
// branch into the form sent to Conjur APIs: stray whitespace (e.g. from an
// interpolated variable) and leading/trailing slashes are stripped so the
// value actually sent always matches what ValidateBranch accepted.
func normalizeBranch(branch string) string {
	return strings.Trim(strings.TrimSpace(branch), "/")
}

// ValidateBranch validates that a branch path is properly formatted with no empty segments.
func ValidateBranch(branch types.String, diagnostics *diag.Diagnostics, fieldName string) {
	if diagnostics == nil {
		return
	}

	branchValue := branch.ValueString()

	normalized := normalizeBranch(branchValue)
	if normalized != "" {
		parts := strings.Split(normalized, "/")
		if slices.Contains(parts, "") {
			diagnostics.AddError(
				"Invalid branch",
				fmt.Sprintf("%s branch cannot contain empty segments (double slashes or trailing slashes are not allowed).", fieldName),
			)
		}
	} else {
		diagnostics.AddError(
			"Invalid branch",
			fmt.Sprintf("%s branch cannot be empty.", fieldName),
		)
	}
}

// ValidateNonBlank validates that a string value which is present is not blank
// (empty or whitespace-only). Unknown values are skipped because they may not be
// resolved during ValidateConfig. Null values are skipped because presence
// checks belong at the schema level via the "Required" attribute.
func ValidateNonBlank(val types.String, diagnostics *diag.Diagnostics, fieldName string) {
	if diagnostics == nil {
		return
	}

	if val.IsUnknown() || val.IsNull() {
		return
	}

	if strings.TrimSpace(val.ValueString()) == "" {
		diagnostics.AddError(
			"Invalid value",
			fmt.Sprintf("%s cannot be empty.", fieldName),
		)
	}
}

// ValidateNoSurroundingWhitespace validates that a string value which is present has no leading or
// trailing whitespace. Unknown and null values are skipped for the same reasons as in ValidateNonBlank,
// and blank values are left to ValidateNonBlank so they aren't reported twice.
func ValidateNoSurroundingWhitespace(val types.String, diagnostics *diag.Diagnostics, fieldName string) {
	if diagnostics == nil || val.IsUnknown() || val.IsNull() {
		return
	}
	s := val.ValueString()
	if trimmed := strings.TrimSpace(s); trimmed != "" && trimmed != s {
		diagnostics.AddError("Invalid value", fmt.Sprintf("%s must not have leading or trailing whitespace. Got: %q", fieldName, s))
	}
}

// hasDotSegment reports whether any "/"-separated segment of s is "." or "..".
func hasDotSegment(s string) bool {
	return slices.ContainsFunc(strings.Split(s, "/"), func(seg string) bool { return seg == "." || seg == ".." })
}

// groupBranchProblem returns why a normalized branch can't be used by conjur_group, or "" if it can.
// ':' separates account, kind and id in a Conjur resource ID, so a branch containing it resolves to a
// different policy than the one the group is loaded into.
func groupBranchProblem(branch string) string {
	switch {
	case strings.Contains(branch, ":"):
		return "must not contain ':'"
	case hasDotSegment(branch):
		return "must not contain '.' or '..' path segments"
	}
	return ""
}

// ValidateGroupBranch applies conjur_group's branch rules on top of ValidateBranch. Unknown and null
// values are skipped.
func ValidateGroupBranch(branch types.String, diagnostics *diag.Diagnostics, fieldName string) {
	if diagnostics == nil || branch.IsUnknown() || branch.IsNull() {
		return
	}
	if problem := groupBranchProblem(normalizeBranch(branch.ValueString())); problem != "" {
		diagnostics.AddError("Invalid branch", fmt.Sprintf("%s %s. Got: %q", fieldName, problem, branch.ValueString()))
	}
}

// groupImportIDProblem returns why the branch and name split from a conjur_group import ID can't be
// imported, or "" if they can. It enforces the same rules ValidateConfig applies to the configured
// values, so an imported group can't end up in state under an identifier its config would reject.
func groupImportIDProblem(branch, name string) string {
	switch {
	case branch == "" || name == "":
		return "branch and name must not be empty"
	case branch != strings.TrimSpace(branch) || name != strings.TrimSpace(name):
		return "branch and name must not have leading or trailing whitespace"
	case slices.Contains(strings.Split(branch, "/"), ""):
		return "branch must not contain empty segments"
	case hasDotSegment(name):
		return "name must not be '.' or '..'"
	}
	if problem := groupBranchProblem(branch); problem != "" {
		return "branch " + problem
	}
	return ""
}

// ownerRoleKinds are the kinds that can own a Conjur resource, matched case-insensitively like conjurpolicy.KindString.
var ownerRoleKinds = []string{"user", "host", "group", "layer", "policy"}

// ValidateOwner validates that an owner which is present has a non-blank id and a role kind.
// Unknown sub-values are skipped because they may not be resolved during ValidateConfig.
func ValidateOwner(owner types.Object, diagnostics *diag.Diagnostics, attrPath path.Path) {
	if diagnostics == nil || owner.IsNull() || owner.IsUnknown() {
		return
	}
	kind, _ := owner.Attributes()["kind"].(types.String)
	id, _ := owner.Attributes()["id"].(types.String)

	if !kind.IsUnknown() {
		if strings.TrimSpace(kind.ValueString()) == "" {
			diagnostics.AddAttributeError(attrPath.AtName("kind"), "Invalid owner", "owner.kind is required when owner is set.")
		} else if !slices.Contains(ownerRoleKinds, strings.ToLower(kind.ValueString())) {
			diagnostics.AddAttributeError(attrPath.AtName("kind"), "Invalid owner", fmt.Sprintf("owner.kind must be one of: %s. Got: %q", strings.Join(ownerRoleKinds, ", "), kind.ValueString()))
		}
	}
	if !id.IsUnknown() && strings.TrimSpace(id.ValueString()) == "" {
		diagnostics.AddAttributeError(attrPath.AtName("id"), "Invalid owner", "owner.id is required when owner is set.")
	}
}

// noDotSegmentsValidator rejects a string that has a "." or ".." segment when split on "/".
type noDotSegmentsValidator struct{}

func (v noDotSegmentsValidator) Description(_ context.Context) string {
	return "must not contain '.' or '..' path segments"
}

func (v noDotSegmentsValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v noDotSegmentsValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	if hasDotSegment(req.ConfigValue.ValueString()) {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid value", fmt.Sprintf("%q must not contain '.' or '..' path segments.", req.ConfigValue.ValueString()))
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

// ValidateIntInRange validates that an int32 value falls within [min, max] (inclusive).
// Unknown and null values are skipped because they may not be resolved during ValidateConfig.
func ValidateIntInRange(val types.Int32, diagnostics *diag.Diagnostics, fieldName string, min, max int32) {
	if diagnostics == nil {
		return
	}
	if val.IsUnknown() || val.IsNull() {
		return
	}
	v := val.ValueInt32()
	if v < min || v > max {
		diagnostics.AddError("Invalid value", fmt.Sprintf("%s must be between %d and %d (inclusive). Got: %d", fieldName, min, max, v))
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
