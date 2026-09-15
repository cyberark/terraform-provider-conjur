package provider

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/cyberark/conjur-api-go/conjurapi"
	"github.com/cyberark/conjur-api-go/conjurapi/response"
	"github.com/cyberark/terraform-provider-conjur/internal/conjur/api/mocks"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

var policyBackendConfig = conjurapi.Config{Account: "conjur"}
var saasBackendConfig = conjurapi.Config{Account: "conjur", Environment: conjurapi.EnvironmentSaaS}

func TestGroupResource_Create(t *testing.T) {
	tests := []struct {
		name          string
		data          GroupResourceModel
		setupMock     func(*mocks.MockClientV2)
		expectedError bool
		errorContains string
	}{
		{
			name: "successful group creation with minimal fields",
			data: GroupResourceModel{
				Name:   types.StringValue("developers"),
				Branch: types.StringValue("data/test"),
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("GetConfig").Return(policyBackendConfig)
				mockV2.On("LoadPolicy", conjurapi.PolicyModePatch, "data/test", mock.MatchedBy(func(policy io.Reader) bool {
					buf := new(strings.Builder)
					_, _ = io.Copy(buf, policy)
					content := buf.String()
					return contains(content, "group") && contains(content, "developers")
				})).Return(&conjurapi.PolicyResponse{}, nil)
			},
			expectedError: false,
		},
		{
			name: "API error during creation",
			data: GroupResourceModel{
				Name:   types.StringValue("error-group"),
				Branch: types.StringValue("data/test"),
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("GetConfig").Return(policyBackendConfig)
				mockV2.On("LoadPolicy", conjurapi.PolicyModePatch, "data/test", mock.Anything).Return(
					nil, fmt.Errorf("permission denied"))
			},
			expectedError: true,
			errorContains: "Could not apply group policy",
		},
		{
			name: "creation with owner",
			data: GroupResourceModel{
				Name:   types.StringValue("admins"),
				Branch: types.StringValue("data/production"),
				Owner: ownerToObject(&conjurapi.Owner{
					Kind: "user",
					Id:   "admin",
				}),
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("GetConfig").Return(policyBackendConfig)
				mockV2.On("LoadPolicy", conjurapi.PolicyModePatch, "data/production", mock.MatchedBy(func(policy io.Reader) bool {
					buf := new(strings.Builder)
					_, _ = io.Copy(buf, policy)
					content := buf.String()
					return contains(content, "group") && contains(content, "admins") && contains(content, "owner")
				})).Return(&conjurapi.PolicyResponse{}, nil)
			},
			expectedError: false,
		},
		{
			name: "creation with annotations",
			data: GroupResourceModel{
				Name:        types.StringValue("platform-team"),
				Branch:      types.StringValue("data/teams"),
				Annotations: map[string]string{"env": "prod", "department": "engineering"},
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("GetConfig").Return(policyBackendConfig)
				mockV2.On("LoadPolicy", conjurapi.PolicyModePatch, "data/teams", mock.MatchedBy(func(policy io.Reader) bool {
					buf := new(strings.Builder)
					_, _ = io.Copy(buf, policy)
					content := buf.String()
					return contains(content, "group") && contains(content, "platform-team")
				})).Return(&conjurapi.PolicyResponse{}, nil)
			},
			expectedError: false,
		},
		{
			name: "creation with owner and annotations",
			data: GroupResourceModel{
				Name:   types.StringValue("security-team"),
				Branch: types.StringValue("data/groups"),
				Owner: ownerToObject(&conjurapi.Owner{
					Kind: "group",
					Id:   "managers",
				}),
				Annotations: map[string]string{"team": "security", "level": "critical"},
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("GetConfig").Return(policyBackendConfig)
				mockV2.On("LoadPolicy", conjurapi.PolicyModePatch, "data/groups", mock.Anything).Return(&conjurapi.PolicyResponse{}, nil)
			},
			expectedError: false,
		},
		{
			name: "successful SaaS group creation",
			data: GroupResourceModel{
				Name:        types.StringValue("developers"),
				Branch:      types.StringValue("data/test"),
				Annotations: map[string]string{"env": "prod"},
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("GetConfig").Return(saasBackendConfig)
				// conjurapi.Group has no Owner field: ValidateConfig is what
				// stops an owner from reaching Create on SaaS.
				mockV2.On("CreateGroup", mock.MatchedBy(func(g conjurapi.Group) bool {
					return g.Name == "developers" && g.Branch == "data/test" &&
						g.Annotations["env"] == "prod"
				})).Return(&conjurapi.Group{
					Name:        "developers",
					Branch:      "data/test",
					Annotations: map[string]string{"env": "prod"},
				}, nil)
			},
			expectedError: false,
		},
		{
			name: "SaaS API error during creation",
			data: GroupResourceModel{
				Name:   types.StringValue("error-group"),
				Branch: types.StringValue("data/test"),
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("GetConfig").Return(saasBackendConfig)
				mockV2.On("CreateGroup", mock.Anything).Return(nil, fmt.Errorf("permission denied"))
			},
			expectedError: true,
			errorContains: "Unable to create group",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockV2 := mocks.NewMockClientV2(t)
			tt.setupMock(mockV2)

			r := &GroupResource{
				client: mockV2,
			}

			req := resource.CreateRequest{
				Plan: tfsdk.Plan{
					Raw:    tftypes.NewValue(tftypes.Object{}, nil),
					Schema: getGroupTestSchema(),
				},
			}
			resp := &resource.CreateResponse{
				State: tfsdk.State{
					Raw:    tftypes.NewValue(tftypes.Object{}, nil),
					Schema: getGroupTestSchema(),
				},
			}

			ctx := context.Background()
			if tt.data.Owner.IsNull() {
				// A zero-value types.Object (the struct literal default) has no
				// attribute types, which req.Plan.Set silently fails to encode;
				// normalize to a proper null so Set actually populates req.Plan.Raw.
				tt.data.Owner = types.ObjectNull(groupOwnerAttrTypes)
			}
			req.Plan.Set(ctx, &tt.data)

			r.Create(ctx, req, resp)

			assertDiagOutcome(t, resp.Diagnostics, tt.expectedError, tt.errorContains)
			mockV2.AssertExpectations(t)
		})
	}
}

func TestGroupResource_Read(t *testing.T) {
	tests := []struct {
		name          string
		data          GroupResourceModel
		setupMock     func(*mocks.MockClientV2)
		expectedError bool
		shouldRemove  bool
		errorContains string
	}{
		{
			name: "group exists",
			data: GroupResourceModel{
				Name:   types.StringValue("developers"),
				Branch: types.StringValue("data/test"),
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("GetConfig").Return(policyBackendConfig)
				mockV2.On("RoleExists", "conjur:group:data/test/developers").Return(true, nil)
			},
			expectedError: false,
			shouldRemove:  false,
		},
		{
			name: "group not found - removes from state",
			data: GroupResourceModel{
				Name:   types.StringValue("missing-group"),
				Branch: types.StringValue("data/test"),
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("GetConfig").Return(policyBackendConfig)
				mockV2.On("RoleExists", "conjur:group:data/test/missing-group").Return(false, nil)
			},
			expectedError: false,
			shouldRemove:  true,
		},
		{
			name: "API error checking existence",
			data: GroupResourceModel{
				Name:   types.StringValue("error-group"),
				Branch: types.StringValue("data/test"),
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("GetConfig").Return(policyBackendConfig)
				mockV2.On("RoleExists", "conjur:group:data/test/error-group").
					Return(false, fmt.Errorf("connection error"))
			},
			expectedError: true,
			errorContains: "Unable to check if group",
		},
		{
			name: "nested branch group exists",
			data: GroupResourceModel{
				Name:   types.StringValue("admins"),
				Branch: types.StringValue("data/production/teams"),
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("GetConfig").Return(policyBackendConfig)
				mockV2.On("RoleExists", "conjur:group:data/production/teams/admins").Return(true, nil)
			},
			expectedError: false,
			shouldRemove:  false,
		},
		{
			name: "group with owner exists",
			data: GroupResourceModel{
				Name:   types.StringValue("security"),
				Branch: types.StringValue("data/groups"),
				Owner: ownerToObject(&conjurapi.Owner{
					Kind: "user",
					Id:   "admin",
				}),
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("GetConfig").Return(policyBackendConfig)
				mockV2.On("RoleExists", "conjur:group:data/groups/security").Return(true, nil)
			},
			expectedError: false,
			shouldRemove:  false,
		},
		{
			name: "SaaS group exists",
			data: GroupResourceModel{
				Name:   types.StringValue("developers"),
				Branch: types.StringValue("data/test"),
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("GetConfig").Return(saasBackendConfig)
				mockV2.On("ReadGroup", "data/test/developers").Return(&conjurapi.Group{
					Name:        "developers",
					Branch:      "data/test",
					Annotations: map[string]string{"env": "prod"},
				}, nil)
			},
			expectedError: false,
			shouldRemove:  false,
		},
		{
			name: "SaaS group not found - removes from state",
			data: GroupResourceModel{
				Name:   types.StringValue("missing-group"),
				Branch: types.StringValue("data/test"),
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("GetConfig").Return(saasBackendConfig)
				mockV2.On("ReadGroup", "data/test/missing-group").Return(nil, &response.ConjurError{Code: http.StatusNotFound, Message: "404 Not Found"})
			},
			expectedError: false,
			shouldRemove:  true,
		},
		{
			name: "SaaS API error reading group",
			data: GroupResourceModel{
				Name:   types.StringValue("error-group"),
				Branch: types.StringValue("data/test"),
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("GetConfig").Return(saasBackendConfig)
				mockV2.On("ReadGroup", "data/test/error-group").Return(nil, fmt.Errorf("connection error"))
			},
			expectedError: true,
			errorContains: "Unable to read group",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockV2 := mocks.NewMockClientV2(t)
			tt.setupMock(mockV2)

			r := &GroupResource{
				client: mockV2,
			}

			req := resource.ReadRequest{
				State: tfsdk.State{
					Raw:    tftypes.NewValue(tftypes.Object{}, nil),
					Schema: getGroupTestSchema(),
				},
			}
			resp := &resource.ReadResponse{
				State: tfsdk.State{
					Raw:    tftypes.NewValue(tftypes.Object{}, nil),
					Schema: getGroupTestSchema(),
				},
			}

			ctx := context.Background()
			if tt.data.Owner.IsNull() {
				tt.data.Owner = types.ObjectNull(groupOwnerAttrTypes)
			}
			req.State.Set(ctx, &tt.data)

			r.Read(ctx, req, resp)

			assertDiagOutcome(t, resp.Diagnostics, tt.expectedError, tt.errorContains)
			if !tt.expectedError {
				if tt.shouldRemove {
					// State should be removed when group doesn't exist
					var result GroupResourceModel
					diag := resp.State.Get(ctx, &result)
					assert.True(t, diag.HasError() || result.Name.IsNull())
				} else {
					// State should still exist
					var result GroupResourceModel
					resp.State.Get(ctx, &result)
					assert.False(t, result.Name.IsNull())
					assert.Equal(t, tt.data.Name.ValueString(), result.Name.ValueString())
					assert.Equal(t, tt.data.Branch.ValueString(), result.Branch.ValueString())
				}
			}
			mockV2.AssertExpectations(t)
		})
	}
}

// TestGroupResource_SaaSAnnotationsState covers the annotations written to
// state on SaaS. Create must keep the planned value whatever the server
// echoes, since annotations is not Computed and any difference fails the
// apply operation. Read must pick up real drift but treat nil and {} as equivalent, so
// a server that omits or empties the field doesn't produce a spurious diff.
func TestGroupResource_SaaSAnnotationsState(t *testing.T) {
	tests := []struct {
		name     string
		read     bool
		prior    map[string]string
		server   map[string]string
		expected map[string]string
	}{
		{name: "create with null plan, server echoes {}", prior: nil, server: map[string]string{}, expected: nil},
		{name: "create with {} plan, server omits annotations", prior: map[string]string{}, server: nil, expected: map[string]string{}},
		{name: "create, server adds a key", prior: map[string]string{"env": "prod"}, server: map[string]string{"env": "prod", "extra": "x"}, expected: map[string]string{"env": "prod"}},
		{name: "read with null state, server returns {}", read: true, prior: nil, server: map[string]string{}, expected: nil},
		{name: "read with {} state, server omits annotations", read: true, prior: map[string]string{}, server: nil, expected: map[string]string{}},
		{name: "read, server value changed", read: true, prior: map[string]string{"env": "prod"}, server: map[string]string{"env": "dev"}, expected: map[string]string{"env": "dev"}},
		{name: "read, server cleared all keys", read: true, prior: map[string]string{"env": "prod"}, server: nil, expected: nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockV2 := mocks.NewMockClientV2(t)
			mockV2.On("GetConfig").Return(saasBackendConfig)
			serverGroup := &conjurapi.Group{Name: "developers", Branch: "data/test", Annotations: tt.server}
			if tt.read {
				mockV2.On("ReadGroup", "data/test/developers").Return(serverGroup, nil)
			} else {
				mockV2.On("CreateGroup", mock.Anything).Return(serverGroup, nil)
			}

			r := &GroupResource{client: mockV2}
			ctx := context.Background()
			data := GroupResourceModel{Name: types.StringValue("developers"), Branch: types.StringValue("data/test"), Owner: types.ObjectNull(groupOwnerAttrTypes), Annotations: tt.prior}
			state := tfsdk.State{Raw: tftypes.NewValue(tftypes.Object{}, nil), Schema: getGroupTestSchema()}

			if tt.read {
				req := resource.ReadRequest{State: tfsdk.State{Raw: tftypes.NewValue(tftypes.Object{}, nil), Schema: getGroupTestSchema()}}
				req.State.Set(ctx, &data)
				resp := &resource.ReadResponse{State: state}
				r.Read(ctx, req, resp)
				require.False(t, resp.Diagnostics.HasError(), "%+v", resp.Diagnostics)
				state = resp.State
			} else {
				req := resource.CreateRequest{Plan: tfsdk.Plan{Raw: tftypes.NewValue(tftypes.Object{}, nil), Schema: getGroupTestSchema()}}
				req.Plan.Set(ctx, &data)
				resp := &resource.CreateResponse{State: state}
				r.Create(ctx, req, resp)
				require.False(t, resp.Diagnostics.HasError(), "%+v", resp.Diagnostics)
				state = resp.State
			}

			var result GroupResourceModel
			require.False(t, state.Get(ctx, &result).HasError())
			assert.Equal(t, tt.expected, result.Annotations)
			mockV2.AssertExpectations(t)
		})
	}
}

// TestGroupResource_Update_PolicyBackend covers the defensive error: on
// Self-Hosted/OSS every attribute forces replace, so Update is never planned
// and must error without touching the V2 annotations endpoints.
func TestGroupResource_Update_PolicyBackend(t *testing.T) {
	mockV2 := mocks.NewMockClientV2(t)
	mockV2.On("GetConfig").Return(policyBackendConfig)
	r := &GroupResource{client: mockV2}

	ctx := context.Background()
	prior := GroupResourceModel{Name: types.StringValue("developers"), Branch: types.StringValue("data/test"), Owner: types.ObjectNull(groupOwnerAttrTypes), Annotations: map[string]string{"a": "1"}}
	planned := GroupResourceModel{Name: types.StringValue("developers"), Branch: types.StringValue("data/test"), Owner: types.ObjectNull(groupOwnerAttrTypes), Annotations: map[string]string{"b": "2"}}
	req := resource.UpdateRequest{Plan: newPlanWithSchema(getGroupTestSchema()), State: newStateWithSchema(getGroupTestSchema())}
	require.False(t, req.Plan.Set(ctx, &planned).HasError())
	require.False(t, req.State.Set(ctx, &prior).HasError())
	resp := &resource.UpdateResponse{State: newStateWithSchema(getGroupTestSchema())}

	r.Update(ctx, req, resp)

	assertDiagOutcome(t, resp.Diagnostics, true, "Update Not Supported")
	mockV2.AssertNotCalled(t, "DeleteGroupAnnotation", mock.Anything, mock.Anything)
	mockV2.AssertNotCalled(t, "UpdateGroup", mock.Anything)
}

type groupAnnotationDelete struct {
	key string
	err error
}

// TestGroupResource_Update covers in-place annotations updates on SaaS:
// removed keys are deleted individually (sorted, all before the PATCH), the
// merging PATCH carries the full planned set and only runs when a key was
// added or changed, and on failure state is the prior state minus the keys
// already removed. Only the calls listed in deletes/patch are registered on
// the strict mock, so any other call fails the test.
func TestGroupResource_Update(t *testing.T) {
	ownerAdmins := ownerToObject(&conjurapi.Owner{Kind: "group", Id: "admins"})
	ownerManagers := ownerToObject(&conjurapi.Owner{Kind: "group", Id: "managers"})
	notFound := &response.ConjurError{Code: http.StatusNotFound, Message: "404 Not Found"}

	tests := []struct {
		name            string
		branch          string
		stateOwner      types.Object
		planOwner       types.Object
		state           map[string]string
		plan            map[string]string
		deletes         []groupAnnotationDelete
		patch           bool
		patchErr        error
		wantAnnotations map[string]string
		wantError       string
		wantWarning     string
	}{
		{name: "key added", state: map[string]string{"a": "1"}, plan: map[string]string{"a": "1", "b": "2"}, patch: true, wantAnnotations: map[string]string{"a": "1", "b": "2"}},
		{name: "value changed", state: map[string]string{"a": "1"}, plan: map[string]string{"a": "2"}, patch: true, wantAnnotations: map[string]string{"a": "2"}},
		{name: "one key removed, rest unchanged", state: map[string]string{"a": "1", "b": "2"}, plan: map[string]string{"a": "1"}, deletes: []groupAnnotationDelete{{key: "b"}}, wantAnnotations: map[string]string{"a": "1"}},
		{name: "all keys removed, null plan", state: map[string]string{"a": "1", "b": "2"}, plan: nil, deletes: []groupAnnotationDelete{{key: "a"}, {key: "b"}}, wantAnnotations: nil},
		{name: "all keys removed, {} plan", state: map[string]string{"a": "1", "b": "2"}, plan: map[string]string{}, deletes: []groupAnnotationDelete{{key: "a"}, {key: "b"}}, wantAnnotations: map[string]string{}},
		{name: "add, change and remove - deletes before PATCH", state: map[string]string{"a": "1", "b": "2", "c": "3", "e": "5"}, plan: map[string]string{"a": "1", "b": "20", "d": "4"}, deletes: []groupAnnotationDelete{{key: "c"}, {key: "e"}}, patch: true, wantAnnotations: map[string]string{"a": "1", "b": "20", "d": "4"}},
		{name: "null to {} makes no calls", state: nil, plan: map[string]string{}, wantAnnotations: map[string]string{}},
		{name: "owner-only change makes no calls", stateOwner: ownerAdmins, planOwner: ownerManagers, state: map[string]string{"a": "1"}, plan: map[string]string{"a": "1"}, wantAnnotations: map[string]string{"a": "1"}},
		{name: "single 404 is success with warning, PATCH still runs", state: map[string]string{"a": "1", "b": "2"}, plan: map[string]string{"a": "10"}, deletes: []groupAnnotationDelete{{key: "b", err: notFound}}, patch: true, wantAnnotations: map[string]string{"a": "10"}, wantWarning: `"b". They may`},
		{name: "multiple 404s produce one sorted warning", state: map[string]string{"a": "1", "b": "2", "c": "3"}, plan: nil, deletes: []groupAnnotationDelete{{key: "a", err: notFound}, {key: "b"}, {key: "c", err: notFound}}, wantAnnotations: nil, wantWarning: `"a", "c". They may`},
		{name: "second of three deletes fails", state: map[string]string{"a": "1", "b": "2", "c": "3", "d": "4"}, plan: map[string]string{"d": "4"}, deletes: []groupAnnotationDelete{{key: "a"}, {key: "b", err: fmt.Errorf("permission denied")}}, wantAnnotations: map[string]string{"b": "2", "c": "3", "d": "4"}, wantError: `Unable to remove annotation "b" from group "data/test/developers"`},
		{name: "404 then failure", state: map[string]string{"a": "1", "b": "2", "c": "3"}, plan: map[string]string{"c": "3"}, deletes: []groupAnnotationDelete{{key: "a", err: notFound}, {key: "b", err: fmt.Errorf("permission denied")}}, wantAnnotations: map[string]string{"b": "2", "c": "3"}, wantError: `Unable to remove annotation "b"`, wantWarning: `"a". They may`},
		{name: "PATCH fails after deletes", state: map[string]string{"a": "1", "b": "2", "c": "3"}, plan: map[string]string{"a": "10", "d": "4"}, deletes: []groupAnnotationDelete{{key: "b"}, {key: "c"}}, patch: true, patchErr: fmt.Errorf("permission denied"), wantAnnotations: map[string]string{"a": "1"}, wantError: `Unable to update annotations of group "data/test/developers"`},
		{name: "PATCH fails without deletes", state: map[string]string{"a": "1"}, plan: map[string]string{"a": "2"}, patch: true, patchErr: fmt.Errorf("permission denied"), wantAnnotations: map[string]string{"a": "1"}, wantError: "Unable to update annotations"},
		{name: "partial failure keeps prior owner", stateOwner: ownerAdmins, planOwner: ownerManagers, state: map[string]string{"a": "1"}, plan: map[string]string{"a": "2"}, patch: true, patchErr: fmt.Errorf("permission denied"), wantAnnotations: map[string]string{"a": "1"}, wantError: "Unable to update annotations"},
		{name: "branch with leading and trailing slashes is trimmed", branch: "/data/test/", state: map[string]string{"a": "1", "b": "2"}, plan: map[string]string{"b": "3"}, deletes: []groupAnnotationDelete{{key: "a"}}, patch: true, wantAnnotations: map[string]string{"b": "3"}},
		{name: "keys with slashes, spaces and unicode passed unchanged", state: map[string]string{"a/b": "1", "with space": "2", "ünï": "3"}, plan: map[string]string{"ünï": "4", "x/y z": "5"}, deletes: []groupAnnotationDelete{{key: "a/b"}, {key: "with space"}}, patch: true, wantAnnotations: map[string]string{"ünï": "4", "x/y z": "5"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.branch == "" {
				tt.branch = "data/test"
			}
			if tt.stateOwner.IsNull() {
				tt.stateOwner = types.ObjectNull(groupOwnerAttrTypes)
			}
			if tt.planOwner.IsNull() {
				tt.planOwner = types.ObjectNull(groupOwnerAttrTypes)
			}

			var calls, wantCalls []string
			mockV2 := mocks.NewMockClientV2(t)
			mockV2.On("GetConfig").Return(saasBackendConfig)
			for _, d := range tt.deletes {
				wantCalls = append(wantCalls, "delete "+d.key)
				mockV2.On("DeleteGroupAnnotation", "data/test/developers", d.key).Run(func(args mock.Arguments) { calls = append(calls, "delete "+args.String(1)) }).Return(d.err).Once()
			}
			if tt.patch {
				wantCalls = append(wantCalls, "patch")
				mockV2.On("UpdateGroup", conjurapi.Group{Name: "developers", Branch: "data/test", Annotations: tt.plan}).Run(func(mock.Arguments) { calls = append(calls, "patch") }).Return(&conjurapi.Group{}, tt.patchErr).Once()
			}
			r := &GroupResource{client: mockV2}

			ctx := context.Background()
			prior := GroupResourceModel{Name: types.StringValue("developers"), Branch: types.StringValue(tt.branch), Owner: tt.stateOwner, Annotations: tt.state}
			planned := GroupResourceModel{Name: types.StringValue("developers"), Branch: types.StringValue(tt.branch), Owner: tt.planOwner, Annotations: tt.plan}
			req := resource.UpdateRequest{Plan: newPlanWithSchema(getGroupTestSchema()), State: newStateWithSchema(getGroupTestSchema())}
			require.False(t, req.Plan.Set(ctx, &planned).HasError())
			require.False(t, req.State.Set(ctx, &prior).HasError())
			resp := &resource.UpdateResponse{State: req.State}

			r.Update(ctx, req, resp)

			assertDiagOutcome(t, resp.Diagnostics, tt.wantError != "", tt.wantError)
			if tt.wantWarning == "" {
				assert.Empty(t, resp.Diagnostics.Warnings())
			} else if assert.Len(t, resp.Diagnostics.Warnings(), 1) {
				assertWarningContains(t, resp.Diagnostics, tt.wantWarning)
			}
			assert.Equal(t, wantCalls, calls)

			var result GroupResourceModel
			require.False(t, resp.State.Get(ctx, &result).HasError())
			assert.Equal(t, tt.wantAnnotations, result.Annotations)
			wantOwner := tt.planOwner
			if tt.wantError != "" {
				wantOwner = tt.stateOwner
			}
			assert.True(t, wantOwner.Equal(result.Owner), "owner: got %v, want %v", result.Owner, wantOwner)
			assert.Equal(t, tt.branch, result.Branch.ValueString())
			mockV2.AssertExpectations(t)
		})
	}
}

func TestAnnotationKeysToRemove(t *testing.T) {
	tests := []struct {
		name  string
		state map[string]string
		plan  map[string]string
		want  []string
	}{
		{name: "both nil", state: nil, plan: nil, want: nil},
		{name: "nil state", state: nil, plan: map[string]string{"a": "1"}, want: nil},
		{name: "empty state", state: map[string]string{}, plan: map[string]string{"a": "1"}, want: nil},
		{name: "nil plan removes all, sorted", state: map[string]string{"c": "3", "a": "1", "b": "2"}, plan: nil, want: []string{"a", "b", "c"}},
		{name: "empty plan removes all", state: map[string]string{"a": "1"}, plan: map[string]string{}, want: []string{"a"}},
		{name: "no overlap", state: map[string]string{"z": "1", "y": "2"}, plan: map[string]string{"a": "1"}, want: []string{"y", "z"}},
		{name: "full overlap, values changed", state: map[string]string{"a": "1", "b": "2"}, plan: map[string]string{"a": "10", "b": "20"}, want: nil},
		{name: "partial overlap", state: map[string]string{"a": "1", "b": "2", "c": "3"}, plan: map[string]string{"b": "2"}, want: []string{"a", "c"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, annotationKeysToRemove(tt.state, tt.plan))
		})
	}
}

func TestAnnotationsNeedPatch(t *testing.T) {
	tests := []struct {
		name  string
		state map[string]string
		plan  map[string]string
		want  bool
	}{
		{name: "both nil", state: nil, plan: nil, want: false},
		{name: "nil to empty", state: nil, plan: map[string]string{}, want: false},
		{name: "empty to nil", state: map[string]string{}, plan: nil, want: false},
		{name: "unchanged", state: map[string]string{"a": "1"}, plan: map[string]string{"a": "1"}, want: false},
		{name: "removal only", state: map[string]string{"a": "1", "b": "2"}, plan: map[string]string{"a": "1"}, want: false},
		{name: "all removed", state: map[string]string{"a": "1"}, plan: nil, want: false},
		{name: "key added to nil state", state: nil, plan: map[string]string{"a": "1"}, want: true},
		{name: "key added", state: map[string]string{"a": "1"}, plan: map[string]string{"a": "1", "b": "2"}, want: true},
		{name: "value changed", state: map[string]string{"a": "1"}, plan: map[string]string{"a": "2"}, want: true},
		{name: "value changed to empty string", state: map[string]string{"a": "1"}, plan: map[string]string{"a": ""}, want: true},
		{name: "no overlap", state: map[string]string{"a": "1"}, plan: map[string]string{"b": "1"}, want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, annotationsNeedPatch(tt.state, tt.plan))
		})
	}
}

func TestGroupResource_Delete(t *testing.T) {
	tests := []struct {
		name          string
		data          GroupResourceModel
		setupMock     func(*mocks.MockClientV2)
		expectedError bool
		errorContains string
	}{
		{
			name: "successful deletion",
			data: GroupResourceModel{
				Name:   types.StringValue("developers"),
				Branch: types.StringValue("data/test"),
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("GetConfig").Return(policyBackendConfig)
				mockV2.On("LoadPolicy", conjurapi.PolicyModePatch, "data/test", mock.MatchedBy(func(policy io.Reader) bool {
					buf := new(strings.Builder)
					_, _ = io.Copy(buf, policy)
					content := buf.String()
					return contains(content, "!delete") && contains(content, "developers")
				})).Return(&conjurapi.PolicyResponse{}, nil)
			},
			expectedError: false,
		},
		{
			name: "API error during deletion",
			data: GroupResourceModel{
				Name:   types.StringValue("error-group"),
				Branch: types.StringValue("data/test"),
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("GetConfig").Return(policyBackendConfig)
				mockV2.On("LoadPolicy", conjurapi.PolicyModePatch, "data/test", mock.Anything).Return(
					nil, fmt.Errorf("permission denied"))
			},
			expectedError: true,
			errorContains: "Could not apply group deletion policy",
		},
		{
			name: "deletion from nested branch",
			data: GroupResourceModel{
				Name:   types.StringValue("admins"),
				Branch: types.StringValue("data/production/teams"),
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("GetConfig").Return(policyBackendConfig)
				mockV2.On("LoadPolicy", conjurapi.PolicyModePatch, "data/production/teams", mock.MatchedBy(func(policy io.Reader) bool {
					buf := new(strings.Builder)
					_, _ = io.Copy(buf, policy)
					content := buf.String()
					return contains(content, "!delete") && contains(content, "admins")
				})).Return(&conjurapi.PolicyResponse{}, nil)
			},
			expectedError: false,
		},
		{
			name: "404 not found error",
			data: GroupResourceModel{
				Name:   types.StringValue("nonexistent-group"),
				Branch: types.StringValue("data/test"),
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("GetConfig").Return(policyBackendConfig)
				mockV2.On("LoadPolicy", conjurapi.PolicyModePatch, "data/test", mock.Anything).Return(
					nil, fmt.Errorf("404 Not Found"))
			},
			expectedError: true,
			errorContains: "Could not apply group deletion policy",
		},
		{
			name: "deletion of group with annotations",
			data: GroupResourceModel{
				Name:        types.StringValue("platform-team"),
				Branch:      types.StringValue("data/teams"),
				Annotations: map[string]string{"env": "prod"},
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("GetConfig").Return(policyBackendConfig)
				mockV2.On("LoadPolicy", conjurapi.PolicyModePatch, "data/teams", mock.Anything).Return(&conjurapi.PolicyResponse{}, nil)
			},
			expectedError: false,
		},
		{
			name: "successful SaaS deletion",
			data: GroupResourceModel{
				Name:   types.StringValue("developers"),
				Branch: types.StringValue("data/test"),
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("GetConfig").Return(saasBackendConfig)
				mockV2.On("DeleteGroup", "data/test/developers").Return(nil)
			},
			expectedError: false,
		},
		{
			name: "SaaS API error during deletion",
			data: GroupResourceModel{
				Name:   types.StringValue("error-group"),
				Branch: types.StringValue("data/test"),
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("GetConfig").Return(saasBackendConfig)
				mockV2.On("DeleteGroup", "data/test/error-group").Return(fmt.Errorf("permission denied"))
			},
			expectedError: true,
			errorContains: "Unable to delete group",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockV2 := mocks.NewMockClientV2(t)
			tt.setupMock(mockV2)

			r := &GroupResource{
				client: mockV2,
			}

			req := resource.DeleteRequest{
				State: tfsdk.State{
					Raw:    tftypes.NewValue(tftypes.Object{}, nil),
					Schema: getGroupTestSchema(),
				},
			}
			resp := &resource.DeleteResponse{
				State: tfsdk.State{
					Raw:    tftypes.NewValue(tftypes.Object{}, nil),
					Schema: getGroupTestSchema(),
				},
			}

			ctx := context.Background()
			if tt.data.Owner.IsNull() {
				tt.data.Owner = types.ObjectNull(groupOwnerAttrTypes)
			}
			req.State.Set(ctx, &tt.data)

			r.Delete(ctx, req, resp)

			assertDiagOutcome(t, resp.Diagnostics, tt.expectedError, tt.errorContains)
			mockV2.AssertExpectations(t)
		})
	}
}

func TestGroupResource_ImportState(t *testing.T) {
	t.Run("SaaS import succeeds", func(t *testing.T) {
		mockV2 := mocks.NewMockClientV2(t)
		mockV2.On("GetConfig").Return(saasBackendConfig)

		r := &GroupResource{client: mockV2}

		req := resource.ImportStateRequest{ID: "data/test/developers"}
		resp := &resource.ImportStateResponse{
			State: tfsdk.State{
				Raw:    tftypes.NewValue(tftypes.Object{}, nil),
				Schema: getGroupTestSchema(),
			},
		}

		ctx := context.Background()
		r.ImportState(ctx, req, resp)

		require.False(t, resp.Diagnostics.HasError(), "%+v", resp.Diagnostics)

		var branch, name types.String
		resp.Diagnostics.Append(resp.State.GetAttribute(ctx, path.Root("branch"), &branch)...)
		resp.Diagnostics.Append(resp.State.GetAttribute(ctx, path.Root("name"), &name)...)
		assert.Equal(t, "data/test", branch.ValueString())
		assert.Equal(t, "developers", name.ValueString())
	})

	t.Run("SaaS import rejects malformed identifier", func(t *testing.T) {
		mockV2 := mocks.NewMockClientV2(t)
		mockV2.On("GetConfig").Return(saasBackendConfig)

		r := &GroupResource{client: mockV2}

		req := resource.ImportStateRequest{ID: "developers"}
		resp := &resource.ImportStateResponse{
			State: tfsdk.State{
				Raw:    tftypes.NewValue(tftypes.Object{}, nil),
				Schema: getGroupTestSchema(),
			},
		}

		r.ImportState(context.Background(), req, resp)

		assert.True(t, resp.Diagnostics.HasError())
	})

	t.Run("policy backend refuses import", func(t *testing.T) {
		mockV2 := mocks.NewMockClientV2(t)
		mockV2.On("GetConfig").Return(policyBackendConfig)

		r := &GroupResource{client: mockV2}

		req := resource.ImportStateRequest{ID: "data/test/developers"}
		resp := &resource.ImportStateResponse{
			State: tfsdk.State{
				Raw:    tftypes.NewValue(tftypes.Object{}, nil),
				Schema: getGroupTestSchema(),
			},
		}

		r.ImportState(context.Background(), req, resp)

		assert.True(t, resp.Diagnostics.HasError())
		found := false
		for _, diag := range resp.Diagnostics.Errors() {
			if contains(diag.Summary(), "Import Not Supported") {
				found = true
			}
		}
		assert.True(t, found)
	})
}

func getGroupTestSchema() schema.Schema {
	r := &GroupResource{}
	var schemaResp resource.SchemaResponse
	r.Schema(context.Background(), resource.SchemaRequest{}, &schemaResp)
	return schemaResp.Schema
}

func TestGroupResource_NameValidators(t *testing.T) {
	validators := getGroupTestSchema().Attributes["name"].(schema.StringAttribute).Validators

	cases := []struct {
		name        string
		value       string
		expectError bool
	}{
		{name: "valid name", value: "admins", expectError: false},
		{name: "name with slash", value: "teams/admins", expectError: true},
		{name: "name with trailing slash", value: "admins/", expectError: true},
		{name: "only slash in name", value: "/", expectError: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var hasError bool
			for _, v := range validators {
				resp := &validator.StringResponse{}
				v.ValidateString(context.Background(), validator.StringRequest{Path: path.Root("name"), ConfigValue: types.StringValue(tc.value)}, resp)
				if resp.Diagnostics.HasError() {
					hasError = true
				}
			}
			assert.Equal(t, tc.expectError, hasError)
		})
	}
}

// TestGroupResource_ValidateConfig_OwnerOnSaaS covers the guardrail for a
// field the V2 Group model doesn't have: owner set on SaaS gets a *warning*,
// not an error. Erroring would block every plan for a pre-existing
// conjur_group that already has owner set (created via policy, before this
// backend existed) until the customer edited their HCL - exactly the
// disruptive-upgrade outcome R2 exists to avoid.
func TestGroupResource_ValidateConfig_OwnerOnSaaS(t *testing.T) {
	tests := []struct {
		name          string
		cfg           conjurapi.Config
		owner         types.Object
		expectWarning bool
	}{
		{
			name:          "SaaS with owner set - warned, not rejected",
			cfg:           saasBackendConfig,
			owner:         ownerToObject(&conjurapi.Owner{Kind: "user", Id: "admin"}),
			expectWarning: true,
		},
		{
			name:          "SaaS with no owner - no warning",
			cfg:           saasBackendConfig,
			owner:         types.ObjectNull(groupOwnerAttrTypes),
			expectWarning: false,
		},
		{
			name:          "policy backend with owner set - no warning",
			cfg:           policyBackendConfig,
			owner:         ownerToObject(&conjurapi.Owner{Kind: "user", Id: "admin"}),
			expectWarning: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockV2 := mocks.NewMockClientV2(t)
			mockV2.On("GetConfig").Return(tt.cfg)

			r := &GroupResource{client: mockV2}

			data := GroupResourceModel{
				Name:   types.StringValue("developers"),
				Branch: types.StringValue("data/test"),
				Owner:  tt.owner,
			}

			// tfsdk.Config has no Set method (a practitioner's config is
			// read-only from the provider's perspective) - build the Raw
			// tftypes.Value via a Plan, which does support Set, and reuse it,
			// matching resource_host_unit_test.go's ValidateConfig tests.
			s := getGroupTestSchema()
			plan := newPlanWithSchema(s)
			ctx := context.Background()
			plan.Set(ctx, &data)

			req := resource.ValidateConfigRequest{
				Config: tfsdk.Config{
					Raw:    plan.Raw,
					Schema: s,
				},
			}
			resp := &resource.ValidateConfigResponse{}

			r.ValidateConfig(ctx, req, resp)

			require.False(t, resp.Diagnostics.HasError(), "%+v", resp.Diagnostics)
			found := false
			for _, diag := range resp.Diagnostics.Warnings() {
				if contains(diag.Summary(), "Owner Ignored") {
					found = true
				}
			}
			assert.Equal(t, tt.expectWarning, found, "%+v", resp.Diagnostics)
		})
	}
}

// TestGroupResource_ModifyPlan covers owner's and annotations' RequiresReplace
// behavior, which lives in ModifyPlan rather than attribute plan modifiers so
// it can read the backend from THIS Configured instance and stay correct under
// provider aliases pointing at different environments. On SaaS neither must
// force a replacement: annotations changes are applied in place by Update, and
// owner is inert. Off SaaS (and with no client, which can't be assumed to be
// SaaS), any change - including null vs {} and unknown values - forces a
// replacement of the changed attribute(s), matching the old attribute-level
// RequiresReplace.
//
// Plans are built as raw tftypes values because GroupResourceModel can't hold
// unknown annotations. GetConfig is only registered when something changed, so
// the strict mock fails the test if isSaaS() is consulted for an unchanged plan.
func TestGroupResource_ModifyPlan(t *testing.T) {
	ctx := context.Background()
	ownerAdmins := ownerToObject(&conjurapi.Owner{Kind: "group", Id: "admins"})
	ownerManagers := ownerToObject(&conjurapi.Owner{Kind: "group", Id: "managers"})
	ownerNull := types.ObjectNull(groupOwnerAttrTypes)

	annType := tftypes.Map{ElementType: tftypes.String}
	annNull := tftypes.NewValue(annType, nil)
	annUnknown := tftypes.NewValue(annType, tftypes.UnknownValue)
	ann := func(kv ...string) tftypes.Value {
		elems := map[string]tftypes.Value{}
		for i := 0; i < len(kv); i += 2 {
			elems[kv[i]] = tftypes.NewValue(tftypes.String, kv[i+1])
		}
		return tftypes.NewValue(annType, elems)
	}
	annOneUnknown := tftypes.NewValue(annType, map[string]tftypes.Value{"a": tftypes.NewValue(tftypes.String, "1"), "b": tftypes.NewValue(tftypes.String, tftypes.UnknownValue)})

	replaceOwner := path.Paths{path.Root("owner")}
	replaceAnnotations := path.Paths{path.Root("annotations")}
	replaceBoth := path.Paths{path.Root("owner"), path.Root("annotations")}

	type modifyPlanCase struct {
		name        string
		stateOwner  types.Object
		planOwner   types.Object
		stateAnn    tftypes.Value
		planAnn     tftypes.Value
		unchanged   bool
		wantReplace path.Paths
	}
	// shared cases are run on both SaaS (never replace) and Self-Hosted (replace wantReplace).
	shared := []modifyPlanCase{
		{name: "owner and annotations unchanged (never set)", stateOwner: ownerNull, planOwner: ownerNull, stateAnn: annNull, planAnn: annNull, unchanged: true},
		{name: "owner unchanged (already set)", stateOwner: ownerAdmins, planOwner: ownerAdmins, stateAnn: annNull, planAnn: annNull, unchanged: true},
		{name: "annotations unchanged", stateOwner: ownerNull, planOwner: ownerNull, stateAnn: ann("a", "1"), planAnn: ann("a", "1"), unchanged: true},
		{name: "owner newly added", stateOwner: ownerNull, planOwner: ownerAdmins, stateAnn: annNull, planAnn: annNull, wantReplace: replaceOwner},
		{name: "owner changed", stateOwner: ownerAdmins, planOwner: ownerManagers, stateAnn: annNull, planAnn: annNull, wantReplace: replaceOwner},
		{name: "owner removed from config", stateOwner: ownerAdmins, planOwner: ownerNull, stateAnn: annNull, planAnn: annNull, wantReplace: replaceOwner},
		{name: "annotation key added", stateOwner: ownerNull, planOwner: ownerNull, stateAnn: ann("a", "1"), planAnn: ann("a", "1", "b", "2"), wantReplace: replaceAnnotations},
		{name: "annotation value changed", stateOwner: ownerNull, planOwner: ownerNull, stateAnn: ann("a", "1"), planAnn: ann("a", "2"), wantReplace: replaceAnnotations},
		{name: "annotation key removed", stateOwner: ownerNull, planOwner: ownerNull, stateAnn: ann("a", "1", "b", "2"), planAnn: ann("a", "1"), wantReplace: replaceAnnotations},
		{name: "all annotations removed", stateOwner: ownerNull, planOwner: ownerNull, stateAnn: ann("a", "1"), planAnn: annNull, wantReplace: replaceAnnotations},
		{name: "annotations null to {}", stateOwner: ownerNull, planOwner: ownerNull, stateAnn: annNull, planAnn: ann(), wantReplace: replaceAnnotations},
		{name: "annotations {} to null", stateOwner: ownerNull, planOwner: ownerNull, stateAnn: ann(), planAnn: annNull, wantReplace: replaceAnnotations},
		{name: "annotations map unknown", stateOwner: ownerNull, planOwner: ownerNull, stateAnn: ann("a", "1"), planAnn: annUnknown, wantReplace: replaceAnnotations},
		{name: "one annotation element unknown", stateOwner: ownerNull, planOwner: ownerNull, stateAnn: ann("a", "1"), planAnn: annOneUnknown, wantReplace: replaceAnnotations},
		{name: "owner and annotations both changed", stateOwner: ownerAdmins, planOwner: ownerManagers, stateAnn: ann("a", "1"), planAnn: ann("a", "2"), wantReplace: replaceBoth},
	}

	type modifyPlanRun struct {
		modifyPlanCase
		backend string
	}
	tests := []modifyPlanRun{
		{backend: "nil client", modifyPlanCase: modifyPlanCase{name: "annotations changed", stateOwner: ownerNull, planOwner: ownerNull, stateAnn: ann("a", "1"), planAnn: ann("a", "2"), wantReplace: replaceAnnotations}},
	}
	for _, c := range shared {
		saasCase := c
		saasCase.wantReplace = nil
		tests = append(tests, modifyPlanRun{modifyPlanCase: saasCase, backend: "SaaS"}, modifyPlanRun{modifyPlanCase: c, backend: "Self-Hosted/OSS"})
	}

	objType := getGroupTestSchema().Type().TerraformType(ctx)
	groupValue := func(t *testing.T, owner types.Object, annotations tftypes.Value) tftypes.Value {
		ownerValue, err := owner.ToTerraformValue(ctx)
		require.NoError(t, err)
		return tftypes.NewValue(objType, map[string]tftypes.Value{
			"name":        tftypes.NewValue(tftypes.String, "developers"),
			"branch":      tftypes.NewValue(tftypes.String, "data/test"),
			"owner":       ownerValue,
			"annotations": annotations,
		})
	}

	for _, tt := range tests {
		t.Run(tt.backend+", "+tt.name, func(t *testing.T) {
			r := &GroupResource{}
			if tt.backend != "nil client" {
				mockV2 := mocks.NewMockClientV2(t)
				if !tt.unchanged {
					cfg := policyBackendConfig
					if tt.backend == "SaaS" {
						cfg = saasBackendConfig
					}
					mockV2.On("GetConfig").Return(cfg)
				}
				r.client = mockV2
			}

			req := resource.ModifyPlanRequest{
				State: tfsdk.State{Raw: groupValue(t, tt.stateOwner, tt.stateAnn), Schema: getGroupTestSchema()},
				Plan:  tfsdk.Plan{Raw: groupValue(t, tt.planOwner, tt.planAnn), Schema: getGroupTestSchema()},
			}
			var resp resource.ModifyPlanResponse
			r.ModifyPlan(ctx, req, &resp)

			require.False(t, resp.Diagnostics.HasError(), "%+v", resp.Diagnostics)
			if len(tt.wantReplace) > 0 {
				assert.Equal(t, tt.wantReplace, resp.RequiresReplace)
			} else {
				assert.Empty(t, resp.RequiresReplace)
			}
		})
	}
}

// TestGroupResource_AnnotationsSchema covers annotations' schema: it must have
// no plan modifiers (replacement is decided per backend in ModifyPlan), and
// its validator must reject an empty key, which the per-key delete endpoint
// can't address.
func TestGroupResource_AnnotationsSchema(t *testing.T) {
	attribute := getGroupTestSchema().Attributes["annotations"].(schema.MapAttribute)
	assert.Empty(t, attribute.PlanModifiers)

	cases := []struct {
		name        string
		value       map[string]attr.Value
		expectError bool
	}{
		{name: "normal key", value: map[string]attr.Value{"env": types.StringValue("prod")}, expectError: false},
		{name: "empty value", value: map[string]attr.Value{"env": types.StringValue("")}, expectError: false},
		{name: "empty key", value: map[string]attr.Value{"": types.StringValue("prod")}, expectError: true},
		{name: "empty key among normal keys", value: map[string]attr.Value{"env": types.StringValue("prod"), "": types.StringValue("x")}, expectError: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var hasError bool
			for _, v := range attribute.Validators {
				resp := &validator.MapResponse{}
				v.ValidateMap(context.Background(), validator.MapRequest{Path: path.Root("annotations"), ConfigValue: types.MapValueMust(types.StringType, tc.value)}, resp)
				if resp.Diagnostics.HasError() {
					hasError = true
				}
			}
			assert.Equal(t, tc.expectError, hasError)
		})
	}
}

// TestGroupResource_ValidateConfig_UnknownAnnotations covers annotations that
// can't be known until apply (e.g. set from another resource's attribute):
// ValidateConfig must not fail decoding them on either backend.
func TestGroupResource_ValidateConfig_UnknownAnnotations(t *testing.T) {
	ctx := context.Background()
	annType := tftypes.Map{ElementType: tftypes.String}
	s := getGroupTestSchema()
	objType := s.Type().TerraformType(ctx)

	annotations := map[string]tftypes.Value{
		"map unknown":     tftypes.NewValue(annType, tftypes.UnknownValue),
		"element unknown": tftypes.NewValue(annType, map[string]tftypes.Value{"a": tftypes.NewValue(tftypes.String, "1"), "b": tftypes.NewValue(tftypes.String, tftypes.UnknownValue)}),
	}

	backends := map[string]conjurapi.Config{"SaaS": saasBackendConfig, "Self-Hosted/OSS": policyBackendConfig}
	for backend, cfg := range backends {
		for name, ann := range annotations {
			t.Run(backend+", "+name, func(t *testing.T) {
				mockV2 := mocks.NewMockClientV2(t)
				mockV2.On("GetConfig").Return(cfg).Maybe()
				r := &GroupResource{client: mockV2}

				raw := tftypes.NewValue(objType, map[string]tftypes.Value{
					"name":        tftypes.NewValue(tftypes.String, "developers"),
					"branch":      tftypes.NewValue(tftypes.String, "data/test"),
					"owner":       tftypes.NewValue(objType.(tftypes.Object).AttributeTypes["owner"], nil),
					"annotations": ann,
				})
				req := resource.ValidateConfigRequest{Config: tfsdk.Config{Raw: raw, Schema: s}}
				resp := &resource.ValidateConfigResponse{}

				r.ValidateConfig(ctx, req, resp)

				require.False(t, resp.Diagnostics.HasError(), "%+v", resp.Diagnostics)
			})
		}
	}
}
