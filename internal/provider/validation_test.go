package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
)

func TestValidateBranch(t *testing.T) {
	tests := []struct {
		name       string
		branch     string
		fieldName  string
		wantError  bool
		errorCount int
	}{
		{
			name:      "valid absolute path",
			branch:    "/data/apps/myapp",
			fieldName: "branch",
			wantError: false,
		},
		{
			name:      "valid root path",
			branch:    "/data",
			fieldName: "branch",
			wantError: false,
		},
		{
			name:      "double slash",
			branch:    "/data//apps/myapp",
			fieldName: "branch",
			wantError: true,
		},
		{
			name:      "trailing slash",
			branch:    "/data/apps/myapp/",
			fieldName: "branch",
			wantError: false,
		},
		{
			name:      "empty string",
			branch:    "",
			fieldName: "branch",
			wantError: true,
		},
		{
			name:      "only slash",
			branch:    "/",
			fieldName: "branch",
			wantError: true,
		},
		{
			name:      "whitespace only",
			branch:    "   ",
			fieldName: "branch",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var diags diag.Diagnostics
			ValidateBranch(types.StringValue(tt.branch), &diags, tt.fieldName)

			if tt.wantError {
				assert.True(t, diags.HasError(), "Expected at least one error")
			} else {
				assert.Equal(t, 0, diags.ErrorsCount(), "Expected no errors, got: %v", diags.Errors())
			}
		})
	}
}

func TestValidateNonBlank(t *testing.T) {
	tests := []struct {
		name      string
		value     types.String
		fieldName string
		wantError bool
	}{
		{
			name:      "valid value",
			value:     types.StringValue("my-resource"),
			fieldName: "name",
			wantError: false,
		},
		{
			name:      "empty string",
			value:     types.StringValue(""),
			fieldName: "name",
			wantError: true,
		},
		{
			name:      "whitespace only",
			value:     types.StringValue("   "),
			fieldName: "name",
			wantError: true,
		},
		{
			name:      "tab only",
			value:     types.StringValue("\t"),
			fieldName: "name",
			wantError: true,
		},
		{
			name:      "newline only",
			value:     types.StringValue("\n"),
			fieldName: "name",
			wantError: true,
		},
		{
			name:      "null value is skipped (presence is the schema's job)",
			value:     types.StringNull(),
			fieldName: "name",
			wantError: false,
		},
		{
			name:      "unknown value is skipped (not yet resolved)",
			value:     types.StringUnknown(),
			fieldName: "name",
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var diags diag.Diagnostics
			ValidateNonBlank(tt.value, &diags, tt.fieldName)

			if tt.wantError {
				assert.Greater(t, diags.ErrorsCount(), 0, "Expected at least one error")
			} else {
				assert.Equal(t, 0, diags.ErrorsCount(), "Expected no errors, got: %v", diags.Errors())
			}
		})
	}
}

func TestValidateContainedIn(t *testing.T) {
	tests := []struct {
		name       string
		value      string
		allowed    []string
		allowEmpty bool
		wantError  bool
	}{
		{
			name:       "valid value",
			value:      "user",
			allowed:    []string{"user", "host", "group"},
			allowEmpty: false,
			wantError:  false,
		},
		{
			name:       "case insensitive",
			value:      "USER",
			allowed:    []string{"user", "host", "group"},
			allowEmpty: false,
			wantError:  false,
		},
		{
			name:       "whitespace trimmed",
			value:      "  user  ",
			allowed:    []string{"user", "host", "group"},
			allowEmpty: false,
			wantError:  false,
		},
		{
			name:       "invalid value",
			value:      "invalid",
			allowed:    []string{"user", "host", "group"},
			allowEmpty: false,
			wantError:  true,
		},
		{
			name:       "empty not allowed",
			value:      "",
			allowed:    []string{"user", "host", "group"},
			allowEmpty: false,
			wantError:  true,
		},
		{
			name:       "empty allowed",
			value:      "",
			allowed:    []string{"user", "host", "group"},
			allowEmpty: true,
			wantError:  false,
		},
		{
			name:       "whitespace only not allowed",
			value:      "   ",
			allowed:    []string{"user", "host", "group"},
			allowEmpty: false,
			wantError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var diags diag.Diagnostics
			ValidateContainedIn(types.StringValue(tt.value), &diags, "field", tt.allowed, tt.allowEmpty)

			if tt.wantError {
				assert.Greater(t, diags.ErrorsCount(), 0, "Expected at least one error")
			} else {
				assert.Equal(t, 0, diags.ErrorsCount(), "Expected no errors, got: %v", diags.Errors())
			}
		})
	}
}

func TestValidateIntInRange(t *testing.T) {
	tests := []struct {
		name      string
		value     types.Int32
		min       int32
		max       int32
		wantError bool
	}{
		{name: "value at minimum", value: types.Int32Value(1), min: 1, max: 10, wantError: false},
		{name: "value at maximum", value: types.Int32Value(10), min: 1, max: 10, wantError: false},
		{name: "value in range", value: types.Int32Value(5), min: 1, max: 10, wantError: false},
		{name: "value below minimum", value: types.Int32Value(0), min: 1, max: 10, wantError: true},
		{name: "value above maximum", value: types.Int32Value(11), min: 1, max: 10, wantError: true},
		{name: "null value skipped", value: types.Int32Null(), min: 1, max: 10, wantError: false},
		{name: "unknown value skipped", value: types.Int32Unknown(), min: 1, max: 10, wantError: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var diags diag.Diagnostics
			ValidateIntInRange(tt.value, &diags, "field", tt.min, tt.max)

			if tt.wantError {
				assert.Greater(t, diags.ErrorsCount(), 0, "Expected at least one error")
			} else {
				assert.Equal(t, 0, diags.ErrorsCount(), "Expected no errors, got: %v", diags.Errors())
			}
		})
	}
}

func TestValidateGroupBranch_SkipsUnknownAndNull(t *testing.T) {
	for _, v := range []types.String{types.StringUnknown(), types.StringNull()} {
		var diags diag.Diagnostics
		ValidateGroupBranch(v, &diags, "branch")
		ValidateNoSurroundingWhitespace(v, &diags, "branch")
		assert.False(t, diags.HasError(), "%+v", diags)
	}
}
