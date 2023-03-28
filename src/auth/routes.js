import {
  handle_signup_view,
  handle_login_view,
  handle_consent_view,
  handle_error_view,
  handle_signup,
  handle_login,
  handle_consent,
  handle_token,
  handle_get_jwks,
  handle_oidc_config,
  handle_userinfo
} from "./handlers.js";
import { auth_schema } from "./schema.js";

export let auth_routes = (fastify, _, done) => {
  fastify.route({
    method: "GET",
    url: "/users/new",
    handler: handle_signup_view,
  });
  fastify.route({
    method: "POST",
    url: "/users",
    handler: handle_signup,
  });
  fastify.route({
    method: "GET",
    url: "/sessions/new",
    handler: handle_login_view,
  });
  fastify.route({
    method: "POST",
    url: "/sessions",
    handler: handle_login,
  });
  fastify.route({
    method: "GET",
    url: "/oauth/authorize",
    handler: handle_consent_view,
    schema: auth_schema.consent_view,
    attachValidation: true,
  });
  fastify.route({
    method: "POST",
    url: "/oauth/authorize",
    handler: handle_consent,
  });
  fastify.route({
    method: "GET",
    url: "/oauth/error",
    handler: handle_error_view,
  });
  fastify.route({
    method: "POST",
    url: "/oauth/token",
    handler: handle_token,
    schema: auth_schema.token,
  });
  fastify.route({
    method: "GET",
    url: "/oauth/jwks",
    handler: handle_get_jwks,
  });
  fastify.route({
    method: "GET",
    url: "/userinfo",
    handler: handle_userinfo,
  });
  fastify.route({
    method: "GET",
    url: "/.well-known/openid-configuration",
    handler: handle_oidc_config,
    schema: auth_schema.oidc_config
  });

  done();
};
