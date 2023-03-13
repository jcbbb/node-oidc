export const auth_schema = {
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
  }
}
