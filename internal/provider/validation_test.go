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

func TestValidateNonEmpty(t *testing.T) {
	tests := []struct {
		name      string
		value     string
		fieldName string
		wantError bool
	}{
		{
			name:      "valid value",
			value:     "my-resource",
			fieldName: "name",
			wantError: false,
		},
		{
			name:      "empty string",
			value:     "",
			fieldName: "name",
			wantError: true,
		},
		{
			name:      "whitespace only",
			value:     "   ",
			fieldName: "name",
			wantError: true,
		},
		{
			name:      "tab only",
			value:     "\t",
			fieldName: "name",
			wantError: true,
		},
		{
			name:      "newline only",
			value:     "\n",
			fieldName: "name",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var diags diag.Diagnostics
			ValidateNonEmpty(types.StringValue(tt.value), &diags, tt.fieldName)

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
