export const auth_schema = {
  oidc_config: {
    response: {
      200: {
        type: "object",
        properties: {
          issuer: { type: "string" },
          authorization_endpoint: { type: "string" },
          token_endpoint: { type: "string" },
          userinfo_endpoint: { type: "string" },
          jwks_uri: { type: "string" },
          response_types_supported: { type: "array" },
          subject_types_supported: { type: "array" },
          id_token_signing_alg_values_supported: { type: "array" },
          scopes_supported: { type: "array" },
          token_endpoint_auth_methods_supported: { type: "array" },
          claims_supported: { type: "array" },
          code_challenge_methods_supported: { type: "array" },
          grant_types_supported: { type: "array" }
        }
      }
    }
  },
  consent_view: {
    query: {
      type: "object",
      properties: {
        client_id: {
          type: "string",
          description: "Client id",
          minLength: 36,
          maxLength: 36,
          errorMessage: { minLength: "invalid_client_id", maxLength: "invalid_client_id" }
        },
        response_type: {
          type: "string",
          enum: ["code", "token"],
          minLength: 1,
          errorMessage: { enum: "invalid_response_type", minLength: "invalid_response_type" }
        },
        code_challenge: {
          type: "string",
          minLength: 1,
          errorMessage: { minLength: "missing_code_challenge" }
        }
      },
      required: ["client_id", "response_type", "code_challenge"],
      errorMessage: {
        type: "object",
        required: {
          client_id: "invalid_client_id",
          response_type: "invalid_response_type",
          code_challenge: "missing_code_challenge"
        }
      }
    }
  },
  token: {
    response: {
      200: {
        type: "object",
        properties: {
          access_token: { type: "string" },
          refresh_token: { type: "string" },
          id_token: { type: "string" },
          token_type: { type: "string" },
          expires_in: { type: "integer" },
          scope: { type: "string" }
        }
      }
    },
    body: {
      type: "object",
      properties: {
        grant_type: { type: "string", enum: ["authorization_code", "refresh_token"], minLength: 1, errorMessage: { enum: "invalid_grant_type", minLength: "missing_grant_type" } },
      },
      required: ["grant_type"],
      allOf: [
        {
          if: {
            properties: {
              grant_type: { const: "authorization_code" }
            }
          },
          then: {
            properties: {
              code: { type: "string", minLength: 1, errorMessage: { minLength: "missing_auth_code" } },
              redirect_uri: { type: "string", minLength: 1, errorMessage: { minLength: "missing_redirect_uri" } },
              code_verifier: { type: "string", minLength: 1, errorMessage: { minLength: "missing_code_verifier" } }
            },
            required: ["code", "redirect_uri", "code_verifier"],
            errorMessage: {
              type: "object",
              required: {
                code: "missing_auth_code",
                redirect_uri: "missing_redirect_uri",
                code_verifier: "missing_code_verifier"
              }
            }
          }
        },
        {
          if: {
            properties: { grant_type: { const: "refresh_token" } }
          },
          then: {
            properties: { refresh_token: { type: "string", minLength: 1, errorMessage: { minLength: "missing_refresh_token" } } },
            required: ["refresh_token"],
            errorMessage: {
              type: "object",
              required: {
                refresh_token: "missing_refresh_token"
              }
            }
          }
        }
      ],
      errorMessage: {
        type: "object",
        required: {
          grant_type: "missing_grant_type"
        }
      }
    }
  }
};
