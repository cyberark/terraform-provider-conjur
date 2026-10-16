package provider

import (
	"net/http"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDoSWARequest_SuccessMatchesWant(t *testing.T) {
	var diags diag.Diagnostics

	ok := doSWARequest("creating trust domain", http.StatusCreated, nil, &diags, http.StatusCreated)

	assert.True(t, ok)
	assert.False(t, diags.HasError())
}

func TestDoSWARequest_SuccessMatchesOneOfMultipleWant(t *testing.T) {
	var diags diag.Diagnostics

	ok := doSWARequest("deleting trust domain", http.StatusNotFound, nil, &diags, http.StatusNoContent, http.StatusNotFound)

	assert.True(t, ok)
	assert.False(t, diags.HasError())
}

func TestDoSWARequest_MismatchAddsError(t *testing.T) {
	var diags diag.Diagnostics

	ok := doSWARequest("creating trust domain", http.StatusConflict, []byte("name already in use"), &diags, http.StatusCreated)

	assert.False(t, ok)
	require.True(t, diags.HasError())
	assertDiagContains(t, diags, "Error creating trust domain")
	assertDiagContains(t, diags, "API returned status 409")
	assertDiagContains(t, diags, "name already in use")
}

func TestDoSWARequest_MismatchAgainstMultipleWant(t *testing.T) {
	var diags diag.Diagnostics

	ok := doSWARequest("deleting trust domain", http.StatusInternalServerError, nil, &diags, http.StatusNoContent, http.StatusNotFound)

	assert.False(t, ok)
	require.True(t, diags.HasError())
	assertDiagContains(t, diags, "Error deleting trust domain")
	assertDiagContains(t, diags, "API returned status 500")
}
