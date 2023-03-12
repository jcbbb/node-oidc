import {
  PORT,
  PORT_DEV,
  PORT_STAGING,
  NODE_ENV,
  POSTGRES_URI,
  POSTGRES_URI_DEV,
  POSTGRES_URI_STAGING,
  SESSION_COOKIE_NAME,
  SESSION_COOKIE_NAME_STAGING,
  SESSION_COOKIE_NAME_DEV,
  SESSION_COOKIE_SECRET
} from "./secrets.js";

export let configs = {
  production: {
    port: PORT,
    node_env: NODE_ENV,
    postgres_uri: POSTGRES_URI,
    session_cookie_name: SESSION_COOKIE_NAME,
    session_cookie_secret: SESSION_COOKIE_SECRET
  },
  development: {
    port: PORT_DEV,
    node_env: NODE_ENV,
    postgres_uri: POSTGRES_URI_DEV,
    session_cookie_name: SESSION_COOKIE_NAME_DEV,
    session_cookie_secret: SESSION_COOKIE_SECRET
  },
  staging: {
    port: PORT_STAGING,
    node_env: NODE_ENV,
    postgres_uri: POSTGRES_URI_STAGING,
    session_cookie_name: SESSION_COOKIE_NAME_STAGING,
    session_cookie_secret: SESSION_COOKIE_SECRET
  },
};
