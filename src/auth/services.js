import config from "../config/index.js";
import jose from "node-jose";
import { pool } from "../db/pool.js";
import { hash } from "argon2";
import { option } from "../utils/index.js";
import { get_user_by_email, get_user_by_id, get_user_by_phone } from "../user/services.js";
import { BadRequestError, InternalError, ResourceNotFoundError } from "../utils/errors.js";
import { randomInt, createHash } from "crypto";

export async function insert_session(user_id, remote_addr) {
  let expires_at = new Date();
  expires_at.setMonth(expires_at.getMonth() + 6); // 6 months;

  let [result, err] = await option(pool.query("insert into sessions (user_id, ip, expires_at) values ($1, $2, $3) returning id, expires_at", [user_id, remote_addr, expires_at]));

  if (err) {
    return [null, new InternalError()];
  }

  return [result.rows[0], null];
}

export async function get_sessions_by_ids(ids) {
  let [result, err] = await option(pool.query("select user_id from sessions where id = any($1)", [ids]));

  if (err) {
    return [null, new InternalError()];
  }

  return [result.rows, null];
}

export async function insert_auth_req({ redirect_uri, response_type, scope, state, client_id, user_id, code_challenge, code_challenge_method }) {
  let expires_at = new Date();
  expires_at.setMinutes(expires_at.getMinutes() + 10); // 10 minutes;

  let code = randomInt(0, 100_000_000).toString().padStart(8, "0");
  let [result, err] = await option(pool.query(`insert into authorization_requests
                            (redirect_uri, response_type, code_challenge, code_challenge_method, scope, state, code, client_id, user_id, expires_at)
                            values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) returning id`,
                                              [redirect_uri, response_type, code_challenge, code_challenge_method, scope, state, code, client_id, user_id, expires_at]));

  if (err) {
    return [null, new InternalError()];
  }

  return [Object.assign(result.rows[0], { code }), null];
}

export async function get_auth_req({ client_id, redirect_uri, code }) {
  let [result, err] = await option(pool.query("select *, case when now() > expires_at then 1 else 0 end as expired from authorization_requests where used = false and client_id = $1 and redirect_uri = $2 and code = $3", [client_id, redirect_uri, code]));

  if (err) {
    return [null, new InternalError()];
  }

  if (!result.rows.length) {
    return [null, new ResourceNotFoundError()];
  }

  if (result.rows[0].expired || result.rows[0].used) {
    return [null, new BadRequestError({ key: "auth_req_expired_used" })];
  }

  return [result.rows[0], null];
}

export async function update_auth_req(id, { used } = {}) {
  let [result, err] = await option(pool.query("update authorization_requests set used = $1 where id = $2", [used, id]));

  if (err) {
    return [null, new InternalError()];
  }

  return [result.rows[0], null];
}

export async function gen_tokens(auth_req, key) {
  let exp = new Date();
  exp.setSeconds(exp.getSeconds() + config.access_token_exp);
  let [result, err] = await option(pool.query(`insert into tokens
                                              (sub, aud, scope, authorization_request_id, client_id, exp)
                                              values ($1, $2, $3, $4, $5, $6) returning iat, refresh_token`,
                                              [auth_req.user_id, auth_req.client_id, auth_req.scope, auth_req.id, auth_req.client_id, exp]));

  if (err) {
    return [null, new InternalError()];
  }

  let token = {
    iss: config.issuer,
    aud: auth_req.client_id,
    sub: auth_req.user_id,
    exp: Math.floor(new Date(exp).getTime() / 1000),
    client_id: auth_req.client_id,
    iat: Math.floor(new Date(result.rows[0].iat) / 1000),
    scope: auth_req.scope
  };

  let [access_token, aterr] = await sign_access_token(token, key);

  if (aterr) {
    return [null, aterr];
  }

  return [{ access_token, refresh_token: result.rows[0].refresh_token }, null];
}

export async function gen_id_token(auth_req, key) {
  let [user, uerr] = await get_user_by_id(auth_req.user_id);
  if (uerr) {
    return [null, uerr];
  }

  let token = {
    iss: config.issuer,
    aud: auth_req.client_id,
    sub: auth_req.user_id,
    name: `${user.first_name} ${user.last_name}`,
    family_name: user.last_name,
    given_name: user.first_name,
    email: user.email,
    email_verified: user.email_verified,
    iat: Math.floor(Date.now() / 1000),
    auth_time: Math.floor(new Date(auth_req.created_at).getTime() / 1000),
    picture: user.picture,
    exp: Math.floor(Date.now() / 1000) + config.id_token_exp
  };

  let opts = { compact: true, jwk: key, fields: { typ: "jwt" }};

  let [result, err] = await option(jose.JWS.createSign(opts, key).update(JSON.stringify(token)).final());

  if (err) {
    return [null, new InternalError()];
  }

  return [result, null];
}

async function sign_access_token(token, key) {
  let opts = { compact: true, jwk: key, fields: { typ: "at+jwt" }};
  let [result, err] = await option(jose.JWS.createSign(opts, key).update(JSON.stringify(token)).final());

  if (err) {
    return [null, new InternalError()];
  }

  return [result, null];
}

export async function verify_credentials({ email, phone, password } = {}) {
  let user;
  let err;

  if (email.length) {
    [user, err] = await get_user_by_email(email);
  } else {
    [user, err] = await get_user_by_phone(phone);
  }

  if (err) {
    return [null, err];
  }

  let phash = await hash(password);

  if (user.password !== phash) {
    return [user, new BadRequestError({ key: "invalid_password" })];
  }

  return [user, null];
}

export async function verify_code_challenge(auth_req, code_verifier) {
  let valid = false;
  if (auth_req.code_challenge_method === "plain") {
    valid = code_verifier === auth_req.code_challenge;
  }

  if (auth_req.code_challenge_method === "S256") {
    let hash = createHash("sha256").update(code_verifier).digest("base64url");
    valid = hash === auth_req.code_challenge;
  }

  if (valid) {
    return [valid, null];
  }

  return [false, new BadRequestError({ key: "invalid_code_verifier" })];
}

export async function get_refresh_token(token) {
  let [result, err] = await option(pool.query("select * from tokens where refresh_token = $1", token));
  if (!err) {
    return [null, new InternalError()];
  }
}
