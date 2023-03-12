import dotenv from "dotenv";

dotenv.config();

let PORT = parseInt(process.env.PORT, 10);
let PORT_DEV = parseInt(process.env.PORT_DEV, 10);
let PORT_STAGING = parseInt(process.env.PORT_STAGING, 10);

export { PORT, PORT_DEV, PORT_STAGING };
export let {
  NODE_ENV = "development",
  POSTGRES_URI,
  POSTGRES_URI_DEV,
  POSTGRES_URI_STAGING,
  SESSION_COOKIE_NAME,
  SESSION_COOKIE_NAME_STAGING,
  SESSION_COOKIE_NAME_DEV,
  SESSION_COOKIE_SECRET
} = process.env;
