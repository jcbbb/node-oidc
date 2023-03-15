import i18next from "i18next";
import i18n_http_middleware from "i18next-http-middleware";
import i18n_backend from "i18next-fs-backend";
import fp from "fastify-plugin";

i18next
  .use(i18n_backend)
  .use(i18n_http_middleware.LanguageDetector)
  .init({
    preload: ["ru", "en"],
    ns: [
      "common",
      "signup",
      "login",
      "errors",
    ],
    fallbackLng: "ru",
    backend: {
      loadPath: process.cwd() + "/src/public/locales/{{lng}}/{{ns}}.json",
      addPath: process.cwd() + "/src/public/locales/{{lng}}/{{ns}}.missing.json",
    },
    saveMissing: true,
    cleanCode: true,
    lowerCaseLng: true,
    detection: {
      order: ["querystring", "cookie", "header"],
      lookupQueryString: "lng",
      lookupCookie: 'i18next',
      lookupHeader: "accept-language",
      lookupSession: 'lng',
      lookupPath: 'lng'
    }
  });

let i18next_plugin = fp((instance, opts, next) => {
  let handle = i18n_http_middleware.handle(i18next, opts);
  instance.addHook("preValidation", (req, reply, next) => handle(req, reply, next));
  next();
});

export { i18next, i18next_plugin };
