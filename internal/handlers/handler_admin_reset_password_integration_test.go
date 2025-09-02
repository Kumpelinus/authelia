package handlers

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/authelia/authelia/v4/internal/authentication"
	"github.com/authelia/authelia/v4/internal/authorization"
	"github.com/authelia/authelia/v4/internal/middlewares"
	"github.com/authelia/authelia/v4/internal/mocks"
	"github.com/authelia/authelia/v4/internal/session"
)

func TestAdminResetPasswordIntegration(t *testing.T) {
	testCases := []struct {
		name           string
		silentMode     bool
		expectNotified bool
	}{
		{
			name:           "ShouldGenerateTokenAndBeConsumableByIdentityFinish",
			silentMode:     false,
			expectNotified: true,
		},
		{
			name:           "ShouldGenerateTokenAndBeConsumableByIdentityFinishSilentMode",
			silentMode:     true,
			expectNotified: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mock := mocks.NewMockAutheliaCtx(t)
			defer mock.Close()

			// Configure the mock
			mock.Ctx.Configuration.IdentityValidation.ResetPassword.JWTExpiration = time.Hour * 24
			mock.Ctx.Configuration.IdentityValidation.ResetPassword.JWTSecret = "test-secret"
			mock.Ctx.Configuration.IdentityValidation.ResetPassword.JWTAlgorithm = "HS256"

			// Set up admin session
			adminSession, err := mock.Ctx.GetSession()
			require.NoError(t, err)

			adminSession.Username = "admin"
			adminSession.Groups = []string{"admins"}
			adminSession.FirstFactorAuthnTimestamp = time.Now().Unix()
			adminSession.SecondFactorAuthnTimestamp = time.Now().Unix()
			adminSession.AuthenticationMethodRefs = authorization.AuthenticationMethodsReferences{
				UsernameAndPassword: true,
				TOTP:               true,
			}

			require.NoError(t, mock.Ctx.SaveSession(adminSession))

			// Prepare admin reset password request
			requestBody := bodyAdminResetPasswordRequest{
				Username: "john",
				Silent:   &tc.silentMode,
			}

			bodyBytes, err := json.Marshal(requestBody)
			require.NoError(t, err)
			mock.Ctx.Request.SetBody(bodyBytes)

			// Set up mocks for admin reset password
			mock.UserProviderMock.
				EXPECT().
				GetDetails("john").
				Return(&authentication.UserDetails{
					Username:    "john",
					DisplayName: "John Doe",
					Emails:      []string{"john@example.com"},
				}, nil)

			mock.StorageMock.
				EXPECT().
				SaveIdentityVerification(gomock.Any(), gomock.Any()).
				Return(nil)

			if tc.expectNotified {
				mock.NotifierMock.
					EXPECT().
					Send(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(nil)
			}

			// Execute admin reset password handler
			AdminResetPasswordPOST(mock.Ctx)

			// Verify response
			assert.Equal(t, 201, mock.Ctx.Response.StatusCode())

			var adminResponse bodyAdminResetPasswordResponse
			err = json.Unmarshal(mock.Ctx.Response.Body(), &adminResponse)
			require.NoError(t, err)
			require.NotEmpty(t, adminResponse.Token)

			// Now test that the token can be consumed by the identity finish endpoint
			mock.Ctx.Request.Reset()
			mock.Ctx.Response.Reset()

			// Set up session for identity verification finish
			userSession := session.NewDefaultUserSession()
			require.NoError(t, mock.Ctx.SaveSession(userSession))

			// Prepare identity verification finish request body
			finishBody := middlewares.IdentityVerificationFinishBody{
				Token: adminResponse.Token,
			}

			finishBodyBytes, err := json.Marshal(finishBody)
			require.NoError(t, err)
			mock.Ctx.Request.SetBody(finishBodyBytes)

			// Set up mocks for identity verification finish
			mock.StorageMock.
				EXPECT().
				FindIdentityVerification(gomock.Any(), gomock.Any()).
				Return(true, nil)

			mock.StorageMock.
				EXPECT().
				ConsumeIdentityVerification(gomock.Any(), gomock.Any(), gomock.Any()).
				Return(nil)

			// Execute identity verification finish handler
			ResetPasswordIdentityFinish(mock.Ctx)

			// Verify that the token was successfully consumed
			assert.Equal(t, 200, mock.Ctx.Response.StatusCode())

			// Verify that the session now has the password reset username set
			finalSession, err := mock.Ctx.GetSession()
			require.NoError(t, err)
			assert.NotNil(t, finalSession.PasswordResetUsername)
			assert.Equal(t, "john", *finalSession.PasswordResetUsername)
		})
	}
}