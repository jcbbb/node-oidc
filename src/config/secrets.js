import dotenv from "dotenv";

dotenv.config();

export let PORT = parseInt(process.env.PORT, 10);
export let PORT_DEV = parseInt(process.env.PORT_DEV, 10);
export let PORT_STAGING = parseInt(process.env.PORT_STAGING, 10);
export let ACCESS_TOKEN_EXP = parseInt(process.env.ACCESS_TOKEN_EXP, 10);
export let ID_TOKEN_EXP = parseInt(process.env.ID_TOKEN_EXP, 10);

export let {
  NODE_ENV = "development",
  POSTGRES_URI,
  POSTGRES_URI_DEV,
  POSTGRES_URI_STAGING,
  SESSION_COOKIE_NAME,
  SESSION_COOKIE_NAME_STAGING,
  SESSION_COOKIE_NAME_DEV,
  SESSION_COOKIE_SECRET,
  JWKS_FILE_NAME,
  ISSUER,
  ISSUER_DEV,
  ISSUER_STAGING,
  ORIGIN,
  ORIGIN_DEV,
  ORIGIN_STAGING
} = process.env;
