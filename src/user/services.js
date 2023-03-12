import { pool } from "../db/pool.js";
import { option } from "../utils/index.js";
import { hash } from "argon2";
import { createHash } from "crypto";
import { ConflictError, InternalError } from "../utils/errors.js";

export async function insert_user({ email, phone, password, first_name, last_name, picture } = {}) {
  let email_hash = createHash("md5").update(email).digest("hex");
  if (!picture) {
    picture = "https://gravatar.com/avatar/" + email_hash + "?d=retro"
  }

  password = await hash(password);

  let [result, err] = await option(pool.query("insert into users (email, phone, password, first_name, last_name, picture) values (nullif($1, ''), nullif($2, ''), $3, $4, $5, $6) returning id", [email, phone, password, first_name, last_name, picture]))
  if (err) {
    if (err.code === "23505") {
      return [null, new ConflictError({ key: "user_exists", params: { user: email || phone } })]
    }
    return [null, new InternalError()]
  }

  return [result.rows[0].id, null]
}

export async function get_by_email(email) {
  let [result, err] = await option(pool.query("select id, email, password from users where email = $1", [email]))

  if (err) {
    return [null, err]
  }

  return [result.rows[0], null]
}

export async function get_by_phone(phone) {
  let [result, err] = await option(pool.query("select id, phone, password from users where phone = $1", [phone]))

  if (err) {
    return [null, err]
  }

  return [result.rows[0], null]
}

export async function get_users_by_ids(ids) {
  let [result, err] = await option(pool.query("select id, first_name, last_name, email, picture from users where id = any($1)", [ids]))

  if (err) {
    return [null, err]
  }

  return [result.rows, null]
}
