import { pool } from "../db/pool.js";
import { hash } from "argon2";
import { option } from "../utils/index.js";
import { get_by_email, get_by_phone } from "../user/services.js";
import { BadRequestError, InternalError } from "../utils/errors.js";

export async function insert_session(user_id, remote_addr) {
  let now = new Date()
  let expires_at = new Date(now.setMonth(now.getMonth() + 6))

  let [result, err] = await option(pool.query("insert into sessions (user_id, ip, expires_at) values ($1, $2, $3) returning id, expires_at", [user_id, remote_addr, expires_at]))

  if (err) {
    return [null, new InternalError()]
  }

  return [result.rows[0], null]
}

export async function get_sessions_by_ids(ids) {
  let [result, err] = await option(pool.query("select user_id from sessions where id = any($1)", [ids]))

  if (err) {
    return [null, new InternalError()]
  }

  return [result.rows, null]
}

export async function verify_credentials({ email, phone, password }) {
  let user
  let err

  if (email.length) {
    [user, err] = await get_by_email(email)
  } else {
    [user, err] = await get_by_phone(phone)
  }

  if (err) {
    return [null, err]
  }

  let phash = await hash(password);

  if (user.password === phash) {
    return [user, new BadRequestError({ key: "invalid_password" })]
  }

  return [null, new InternalError()]
}
