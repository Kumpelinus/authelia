package handlers

import (
	"encoding/json"
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valyala/fasthttp"
	"go.uber.org/mock/gomock"

	"github.com/authelia/authelia/v4/internal/authentication"
	"github.com/authelia/authelia/v4/internal/authorization"
	"github.com/authelia/authelia/v4/internal/middlewares"
	"github.com/authelia/authelia/v4/internal/mocks"
	"github.com/authelia/authelia/v4/internal/session"
)

func TestAdminResetPasswordPOST(t *testing.T) {
	testCases := []struct {
		name           string
		requestBody    bodyAdminResetPasswordRequest
		setupMocks     func(*mocks.MockUserProvider, *mocks.MockStorage, *mocks.MockNotifier)
		userSession    session.UserSession
		expectedStatus int
		expectedError  bool
		expectedFields []string
	}{
		{
			name: "ShouldSucceedWithValidRequest",
			requestBody: bodyAdminResetPasswordRequest{
				Username: "john",
			},
			setupMocks: func(mockUserProvider *mocks.MockUserProvider, mockStorage *mocks.MockStorage, mockNotifier *mocks.MockNotifier) {
				mockUserProvider.
					EXPECT().
					GetDetails("john").
					Return(&authentication.UserDetails{
						Username:    "john",
						DisplayName: "John Doe",
						Emails:      []string{"john@example.com"},
					}, nil)

				mockStorage.
					EXPECT().
					SaveIdentityVerification(gomock.Any(), gomock.Any()).
					Return(nil)

				mockNotifier.
					EXPECT().
					Send(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(nil)
			},
			userSession: session.UserSession{
				Username: "admin",
				Groups:   []string{"admins"},
			},
			expectedStatus: fasthttp.StatusCreated,
			expectedError:  false,
			expectedFields: []string{"token", "link", "expires_at", "jti"},
		},
		{
			name: "ShouldSucceedWithSilentMode",
			requestBody: bodyAdminResetPasswordRequest{
				Username: "john",
				Silent:   &[]bool{true}[0],
			},
			setupMocks: func(mockUserProvider *mocks.MockUserProvider, mockStorage *mocks.MockStorage, mockNotifier *mocks.MockNotifier) {
				mockUserProvider.
					EXPECT().
					GetDetails("john").
					Return(&authentication.UserDetails{
						Username:    "john",
						DisplayName: "John Doe",
						Emails:      []string{"john@example.com"},
					}, nil)

				mockStorage.
					EXPECT().
					SaveIdentityVerification(gomock.Any(), gomock.Any()).
					Return(nil)

				// No notification should be sent in silent mode
			},
			userSession: session.UserSession{
				Username: "admin",
				Groups:   []string{"admins"},
			},
			expectedStatus: fasthttp.StatusCreated,
			expectedError:  false,
			expectedFields: []string{"token", "link", "expires_at", "jti"},
		},
		{
			name: "ShouldFailWhenUserNotFound",
			requestBody: bodyAdminResetPasswordRequest{
				Username: "nonexistent",
			},
			setupMocks: func(mockUserProvider *mocks.MockUserProvider, mockStorage *mocks.MockStorage, mockNotifier *mocks.MockNotifier) {
				mockUserProvider.
					EXPECT().
					GetDetails("nonexistent").
					Return(nil, fmt.Errorf("user not found"))
			},
			userSession: session.UserSession{
				Username: "admin",
				Groups:   []string{"admins"},
			},
			expectedStatus: fasthttp.StatusOK,
			expectedError:  true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mock := mocks.NewMockAutheliaCtx(t)
			defer mock.Close()

			mock.Ctx.Configuration.IdentityValidation.ResetPassword.JWTExpiration = time.Hour * 24
			mock.Ctx.Configuration.IdentityValidation.ResetPassword.JWTSecret = "test-secret"
			mock.Ctx.Configuration.IdentityValidation.ResetPassword.JWTAlgorithm = "HS256"

			// Prepare request body
			bodyBytes, err := json.Marshal(tc.requestBody)
			require.NoError(t, err)
			mock.Ctx.Request.SetBody(bodyBytes)

			// Set up session
			require.NoError(t, mock.Ctx.SaveSession(tc.userSession))

			// Set up mocks
			tc.setupMocks(mock.UserProviderMock, mock.StorageMock, mock.NotifierMock)

			// Execute the handler
			AdminResetPasswordPOST(mock.Ctx)

			// Check status code
			assert.Equal(t, tc.expectedStatus, mock.Ctx.Response.StatusCode())

			if tc.expectedError {
				// Should be an error response
				assert.Contains(t, string(mock.Ctx.Response.Body()), "status")
			} else {
				// Should be a successful response with expected fields
				var response bodyAdminResetPasswordResponse
				err := json.Unmarshal(mock.Ctx.Response.Body(), &response)
				require.NoError(t, err)

				for _, field := range tc.expectedFields {
					switch field {
					case "token":
						assert.NotEmpty(t, response.Token)
						// Verify the JWT token is valid
						token, err := jwt.Parse(response.Token, func(token *jwt.Token) (interface{}, error) {
							return []byte("test-secret"), nil
						})
						assert.NoError(t, err)
						assert.True(t, token.Valid)
					case "link":
						assert.NotEmpty(t, response.Link)
						// Verify the link contains the token
						linkURL, err := url.Parse(response.Link)
						assert.NoError(t, err)
						assert.Equal(t, response.Token, linkURL.Query().Get("token"))
					case "expires_at":
						assert.NotEmpty(t, response.ExpiresAt)
						// Verify it's a valid RFC3339 timestamp
						_, err := time.Parse(time.RFC3339, response.ExpiresAt)
						assert.NoError(t, err)
					case "jti":
						assert.NotEmpty(t, response.JTI)
						// Verify it's a valid UUID
						_, err := uuid.Parse(response.JTI)
						assert.NoError(t, err)
					}
				}
			}
		})
	}
}

func TestRequireAdminsGroupMiddleware(t *testing.T) {
	testCases := []struct {
		name           string
		userSession    session.UserSession
		expectedStatus int
		shouldCallNext bool
	}{
		{
			name: "ShouldAllowAdminUser",
			userSession: session.UserSession{
				Username:                   "admin",
				Groups:                     []string{"admins", "users"},
				FirstFactorAuthnTimestamp:  time.Now().Unix(),
				SecondFactorAuthnTimestamp: time.Now().Unix(),
				AuthenticationMethodRefs: authorization.AuthenticationMethodsReferences{
					UsernameAndPassword: true, // Knowledge factor
					TOTP:               true, // Possession factor for 2FA
				},
			},
			expectedStatus: fasthttp.StatusOK,
			shouldCallNext: true,
		},
		{
			name: "ShouldDenyNonAdminUser",
			userSession: session.UserSession{
				Username:                   "user",
				Groups:                     []string{"users"},
				FirstFactorAuthnTimestamp:  time.Now().Unix(),
				SecondFactorAuthnTimestamp: time.Now().Unix(),
				AuthenticationMethodRefs: authorization.AuthenticationMethodsReferences{
					UsernameAndPassword: true, // Knowledge factor
					TOTP:               true, // Possession factor for 2FA
				},
			},
			expectedStatus: fasthttp.StatusForbidden,
			shouldCallNext: false,
		},
		{
			name: "ShouldDenyUserWithoutTwoFactor",
			userSession: session.UserSession{
				Username:                  "admin",
				Groups:                    []string{"admins"},
				FirstFactorAuthnTimestamp: time.Now().Unix(),
				AuthenticationMethodRefs: authorization.AuthenticationMethodsReferences{
					UsernameAndPassword: true, // Only knowledge factor, no possession factor
				},
			},
			expectedStatus: fasthttp.StatusForbidden,
			shouldCallNext: false,
		},
		{
			name: "ShouldDenyUnauthenticatedUser",
			userSession: session.UserSession{
				Username: "",
				Groups:   []string{},
			},
			expectedStatus: fasthttp.StatusForbidden,
			shouldCallNext: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mock := mocks.NewMockAutheliaCtx(t)
			defer mock.Close()

			mock.Ctx.Configuration.WebAuthn.EnablePasskey2FA = false

			// Set up session - first get the existing session, then modify it
			userSession, err := mock.Ctx.GetSession()
			require.NoError(t, err)
			
			// Set the session fields
			userSession.Username = tc.userSession.Username
			userSession.Groups = tc.userSession.Groups
			userSession.FirstFactorAuthnTimestamp = tc.userSession.FirstFactorAuthnTimestamp
			userSession.SecondFactorAuthnTimestamp = tc.userSession.SecondFactorAuthnTimestamp
			userSession.AuthenticationMethodRefs = tc.userSession.AuthenticationMethodRefs

			require.NoError(t, mock.Ctx.SaveSession(userSession))

			nextCalled := false
			next := func(ctx *middlewares.AutheliaCtx) {
				nextCalled = true
				ctx.SetStatusCode(fasthttp.StatusOK)
			}

			// Execute the middleware
			middleware := middlewares.RequireAdminsGroup(next)
			middleware(mock.Ctx)

			// Check status code
			assert.Equal(t, tc.expectedStatus, mock.Ctx.Response.StatusCode())
			assert.Equal(t, tc.shouldCallNext, nextCalled)
		})
	}
}