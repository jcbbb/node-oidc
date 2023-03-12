import { handle_signup_view, handle_login_view, handle_consent_view, handle_error_view, handle_signup, handle_login } from "./handlers.js";

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
    method: "GET",
    url: "/sessions",
    handler: handle_login,
  });

  fastify.route({
    method: "GET",
    url: "/oauth/authorize",
    handler: handle_consent_view,
  });

  fastify.route({
    method: "GET",
    url: "/oauth/error",
    handler: handle_error_view,
  });

  done();
};
