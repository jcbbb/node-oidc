import fastify from "fastify";
import config from "./config/index.js";
import view from "@fastify/view";
import path from "path";
import fstatic from "@fastify/static";
import flash from "@fastify/flash";
import fsession from "@fastify/secure-session";
import formbody from "@fastify/formbody";
import i18n_http_middleware from "i18next-http-middleware";
import { auth_routes } from "./auth/routes.js";
import { i18next } from "./utils/i18n.js";
import { eta } from "./utils/eta.js";

export async function start() {
  let app = fastify({
    maxParamLength: 1000,
    logger: true,
    trustProxy: true,
  });

  try {
    app.register(i18n_http_middleware.plugin, {
      i18next,
    });

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

    app.get("/", (req, reply) => {
      console.log(req.session);
    })

    app.register(fstatic, {
      root: path.join(process.cwd(), "src/public"),
      prefix: "/public",
      decorateReply: false,
      setHeaders: (res) => {
        res.setHeader("Service-Worker-Allowed", "/");
      },
    });

    app.register(auth_routes)

    await app.listen({ port: config.port });
  } catch (err) {
    app.log.error(err);
    process.exit(1);
  }
}
