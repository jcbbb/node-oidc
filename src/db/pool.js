import pkg from "pg";
import config from "../config/index.js";

let { Pool } = pkg;

export let pool = new Pool({ connectionString: config.postgres_uri });

pool.on("error", (err) => {
  console.error('Unexpected error on idle client', err);
  process.exit(-1);
});
