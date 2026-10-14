package provider

import (
	"context"
	"net/http"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
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

func TestModelFromObject_NullReturnsNil(t *testing.T) {
	var diags diag.Diagnostics

	model := modelFromObject[JWTConfigModel](context.Background(), types.ObjectNull(jwtAttrTypes), &diags)

	assert.Nil(t, model)
	assert.False(t, diags.HasError())
}

func TestModelFromObject_UnknownReturnsNil(t *testing.T) {
	var diags diag.Diagnostics

	model := modelFromObject[JWTConfigModel](context.Background(), types.ObjectUnknown(jwtAttrTypes), &diags)

	assert.Nil(t, model)
	assert.False(t, diags.HasError())
}

func TestModelFromObject_KnownDeserializesFields(t *testing.T) {
	ctx := context.Background()
	var diags diag.Diagnostics

	obj, objDiags := types.ObjectValueFrom(ctx, jwtAttrTypes, &JWTConfigModel{
		SignatureAlgorithm: types.StringValue("RS512"),
		SigningKeyType:     types.StringValue("RSA_4096"),
		SigningKeyTTL:      types.Int64Value(86400),
		TokenTTL:           types.Int64Value(300),
	})
	require.False(t, objDiags.HasError())

	model := modelFromObject[JWTConfigModel](ctx, obj, &diags)

	require.NotNil(t, model)
	assert.False(t, diags.HasError())
	assert.Equal(t, "RS512", model.SignatureAlgorithm.ValueString())
	assert.Equal(t, "RSA_4096", model.SigningKeyType.ValueString())
	assert.Equal(t, int64(86400), model.SigningKeyTTL.ValueInt64())
	assert.Equal(t, int64(300), model.TokenTTL.ValueInt64())
}

func TestApplyOptionalModel_NullSkipsApplyWithoutError(t *testing.T) {
	var diags diag.Diagnostics
	applied := false

	ok := applyOptionalModel(context.Background(), types.ObjectNull(jwtAttrTypes), &diags, func(*JWTConfigModel) {
		applied = true
	})

	assert.True(t, ok)
	assert.False(t, applied)
	assert.False(t, diags.HasError())
}

func TestApplyOptionalModel_KnownRunsApply(t *testing.T) {
	ctx := context.Background()
	var diags diag.Diagnostics

	obj, objDiags := types.ObjectValueFrom(ctx, jwtAttrTypes, &JWTConfigModel{
		SignatureAlgorithm: types.StringValue("RS512"),
		SigningKeyType:     types.StringValue("RSA_4096"),
		SigningKeyTTL:      types.Int64Value(86400),
		TokenTTL:           types.Int64Value(300),
	})
	require.False(t, objDiags.HasError())

	var applied *JWTConfigModel
	ok := applyOptionalModel(ctx, obj, &diags, func(jwtCfg *JWTConfigModel) {
		applied = jwtCfg
	})

	assert.True(t, ok)
	require.NotNil(t, applied)
	assert.Equal(t, "RS512", applied.SignatureAlgorithm.ValueString())
	assert.False(t, diags.HasError())
}

func TestOptionalStringListValue_NilReturnsNull(t *testing.T) {
	listValue, diags := optionalStringListValue(context.Background(), nil)

	assert.False(t, diags.HasError())
	assert.True(t, listValue.IsNull())
}

// A non-nil pointer to an empty slice must also normalize to null: the
// corresponding schema attributes (e.g. workload_registration_policies) are
// Optional but not Computed, so the provider is not allowed to write back a
// known-but-empty list when the config omitted the attribute (planned null) -
// doing so trips Terraform's "provider produced inconsistent result" check.
func TestOptionalStringListValue_EmptyNonNilSliceReturnsNull(t *testing.T) {
	empty := []string{}

	listValue, diags := optionalStringListValue(context.Background(), &empty)

	assert.False(t, diags.HasError())
	assert.True(t, listValue.IsNull())
}

func TestOptionalStringListValue_PopulatedSliceReturnsList(t *testing.T) {
	values := []string{"a", "b"}

	listValue, diags := optionalStringListValue(context.Background(), &values)

	assert.False(t, diags.HasError())
	assert.False(t, listValue.IsNull())
	var got []string
	require.False(t, listValue.ElementsAs(context.Background(), &got, false).HasError())
	assert.Equal(t, values, got)
}

func TestApplyOptionalModel_DecodeErrorSkipsApplyAndReturnsFalse(t *testing.T) {
	ctx := context.Background()
	var diags diag.Diagnostics
	applied := false

	// This object has a different shape than JWTConfigModel, so decoding it
	// as a JWTConfigModel fails and adds a diagnostic.
	obj, objDiags := types.ObjectValueFrom(ctx,
		map[string]attr.Type{"workload_ttl": types.Int64Type},
		struct {
			WorkloadTTL types.Int64 `tfsdk:"workload_ttl"`
		}{WorkloadTTL: types.Int64Value(3600)})
	require.False(t, objDiags.HasError())

	ok := applyOptionalModel(ctx, obj, &diags, func(*JWTConfigModel) {
		applied = true
	})

	assert.False(t, ok)
	assert.False(t, applied)
	assert.True(t, diags.HasError())
}

func TestIsSet(t *testing.T) {
	assert.True(t, isSet(types.StringValue("")))
	assert.True(t, isSet(types.Int64Value(0)))
	assert.False(t, isSet(types.StringNull()))
	assert.False(t, isSet(types.Int64Unknown()))
}

func TestInt32PtrFromInt64(t *testing.T) {
	assert.Nil(t, int32PtrFromInt64(types.Int64Null()))
	assert.Nil(t, int32PtrFromInt64(types.Int64Unknown()))

	got := int32PtrFromInt64(types.Int64Value(3600))
	require.NotNil(t, got)
	assert.Equal(t, int32(3600), *got)

	// A configured zero is a real value, not "unset".
	got = int32PtrFromInt64(types.Int64Value(0))
	require.NotNil(t, got)
	assert.Equal(t, int32(0), *got)
}

func TestFloat64Ptr(t *testing.T) {
	assert.Nil(t, float64Ptr(types.Float64Null()))
	assert.Nil(t, float64Ptr(types.Float64Unknown()))

	got := float64Ptr(types.Float64Value(0.75))
	require.NotNil(t, got)
	assert.Equal(t, 0.75, *got)
}

func TestChangedPtr(t *testing.T) {
	one, two := 1, 2
	sameAsOne := 1

	assert.Nil(t, changedPtr[int](nil, nil), "unset plan is omitted")
	assert.Nil(t, changedPtr(nil, &one), "unset plan is omitted even with prior state")
	assert.Nil(t, changedPtr(&one, &sameAsOne), "unchanged value is omitted")
	assert.Same(t, &two, changedPtr(&two, &one), "changed value is kept")
	assert.Same(t, &one, changedPtr(&one, nil), "value with no prior state is kept")
}
