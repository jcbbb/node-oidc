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
  SESSION_COOKIE_SECRET,
  JWKS_FILE_NAME,
  ACCESS_TOKEN_EXP,
  ID_TOKEN_EXP,
  ISSUER,
  ISSUER_DEV,
  ISSUER_STAGING
} from "./secrets.js";

export let configs = {
  production: {
    port: PORT,
    node_env: NODE_ENV,
    postgres_uri: POSTGRES_URI,
    session_cookie_name: SESSION_COOKIE_NAME,
    session_cookie_secret: SESSION_COOKIE_SECRET,
    jwks_file_name: JWKS_FILE_NAME,
    issuer: ISSUER,
    access_token_exp: ACCESS_TOKEN_EXP,
    id_token_exp: ID_TOKEN_EXP
  },
  development: {
    port: PORT_DEV,
    node_env: NODE_ENV,
    postgres_uri: POSTGRES_URI_DEV,
    session_cookie_name: SESSION_COOKIE_NAME_DEV,
    session_cookie_secret: SESSION_COOKIE_SECRET,
    jwks_file_name: JWKS_FILE_NAME,
    issuer: ISSUER_DEV,
    access_token_exp: ACCESS_TOKEN_EXP,
    id_token_exp: ID_TOKEN_EXP
  },
  staging: {
    port: PORT_STAGING,
    node_env: NODE_ENV,
    postgres_uri: POSTGRES_URI_STAGING,
    session_cookie_name: SESSION_COOKIE_NAME_STAGING,
    session_cookie_secret: SESSION_COOKIE_SECRET,
    jwks_file_name: JWKS_FILE_NAME,
    issuer: ISSUER_STAGING,
    access_token_exp: ACCESS_TOKEN_EXP,
    id_token_exp: ID_TOKEN_EXP
  },
};
