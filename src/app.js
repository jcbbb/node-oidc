import fastify from "fastify";
import config from "./config/index.js";
import view from "@fastify/view";
import path from "path";
import fstatic from "@fastify/static";
import flash from "@fastify/flash";
import fsession from "@fastify/secure-session";
import formbody from "@fastify/formbody";
import ajv_errors from "ajv-errors";
import { auth_routes } from "./auth/routes.js";
import { i18next_plugin } from "./utils/i18n.js";
import { eta } from "./utils/eta.js";
import { ValidationError } from "./utils/errors.js";

export async function start() {
  let app = fastify({
    maxParamLength: 1000,
    logger: true,
    trustProxy: true,
    ajv: {
      customOptions: { allErrors: true, messages: true, useDefaults: true },
      plugins: [ajv_errors],
    },
  });

  try {
    app.register(i18next_plugin);

    app.register(fsession, {
      secret: config.session_cookie_secret,
      cookieName: config.session_cookie_name,
      cookie: {
        httpOnly: true,
        secure: config.node_env === "production" || config.node_env === "staging",
        sameSite: "lax",
        path: "/",
        maxAge: 31556926,
      },
    });

    app.register(flash);
    app.register(formbody);
    app.register(view, {
      engine: {
        eta,
      },
      root: path.join(process.cwd(), "src/views"),
      viewExt: "html",
      propertyName: "render",
    });

    app.register(fstatic, {
      root: path.join(process.cwd(), "src/public"),
      prefix: "/public",
      decorateReply: false,
      setHeaders: (res) => {
        res.setHeader("Service-Worker-Allowed", "/");
      },
    });

    app.register(auth_routes);
    app.setErrorHandler((err, req, reply) => {
      let t = req.t;
      if (err.validation) {
        reply.code(422).send(new ValidationError({ errors: err.validation }).build(t));
        return reply;
      }
      return err;
    });

    await app.listen({ port: config.port });
  } catch (err) {
    app.log.error(err);
    process.exit(1);
  }
}
