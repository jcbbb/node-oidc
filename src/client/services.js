import { pool } from "../db/pool.js";
import { BadRequestError, InternalError, ResourceNotFoundError } from "../utils/errors.js";
import { option, valid_uuid } from "../utils/index.js";

const CONFIDENTAL_CLIENT = "confidential";
const PUBLIC_CLIENT = "public";
const AUTH_METHOD_CLIENT_SECRET_BASIC = "client_secret_basic";
const AUTH_METHOD_CLIENT_SECRET_POST = "client_secret_post";
const AUTH_METHOD_CLIENT_SECRET_NONE = "none";

export async function get_client(id) {
  if (!valid_uuid(id)) {
    return [null, new BadRequestError({ key: "invalid_client_id" })];
  }

  let [result, err] = await option(pool.query("select * from clients where id = $1", [id]));

  if (err) {
    return [null, new InternalError()];
  }

  if (!result.rows.length) {
    return [null, new ResourceNotFoundError({ key: "client_not_found" })];
  }

  return [result.rows[0], null];
}

export async function is_valid_client_scope(scope = "", client_id) {
  let scopes_arr = scope.split(" ").filter(Boolean);
  let [result, err] = await option(pool.query("select count(1)::int from client_scopes where scope_key = any($1) and client_id = $2", [scopes_arr, client_id]));

  if (err) {
    return [false, new InternalError()];
  }

  console.log({ scopes_arr });
  let is_valid = result.rows[0].count === scopes_arr.length;

  if (!is_valid) {
    return [false, new BadRequestError({ key: "invalid_scope", params: { scope } })];
  }

  return [is_valid, null];
}

export async function get_client_scopes(id) {
  let [result, err] = await option(pool.query("select key, icon_uri, description, sensitive from client_scopes cs join scope_translations st on st.scope_key = cs.scope_key join scopes s on s.key = cs.scope_key where cs.client_id = $1 and lang = 'en'", [id]));

  if (err) {
    return [null, new InternalError()];
  }

  return [result.rows, null];
}

export async function get_valid_client_scopes(scope, client_id) {
  let [client_scopes, err] = await get_client_scopes(client_id);

  if (err) {
    return [null, err];
  }

  if (!scope) return [client_scopes, null];
  let scopes_arr = scope.split(" ");
  let valid_scopes = [];

  for (let scope of scopes_arr) {
    let found_scope = client_scopes.find(cs => cs.key === scope);
    if (found_scope) {
      valid_scopes.push(found_scope);
      continue;
    } else {
      return [null, new BadRequestError({ key: "invalid_scope", params: { scope } })];
    }
  }

  return [valid_scopes, null];
}

export async function is_valid_response_type(response_type, client_id) {
  let [result, err] = await option(pool.query("select * from client_response_types where client_id = $1", [client_id]));

  if (err) {
    return new InternalError();
  }

  let is_valid = result.rows.some((row) => row.response_type === response_type);
  if (!is_valid) {
    return new BadRequestError({ key: "invalid_response_type" });
  }

  return null;
}

export async function get_valid_redirect_uri(redirect_uri, client_id) {
  let [result, err] = await option(pool.query("select * from client_redirect_uris where client_id = $1", [client_id]));

  if (err) {
    return [null, new InternalError()];
  }

  if (!redirect_uri) {
    return [result.rows[0].uri, null];
  }

  let is_valid = result.rows.some((row) => row.uri === redirect_uri);

  if (!is_valid) {
    return [null, new BadRequestError({ key: "invalid_redirect_uri" })];
  }

  return [redirect_uri, null];
}

export async function get_verified_client(client_id, client_secret, auth_header) {
  if (auth_header) {
    let [type, b64] = auth_header.split(" ");
    let [id, secret] = Buffer.from(b64, "base64").toString().split(":");
    let [client, err] = await get_client(id);

    if (err) {
      return [null, err];
    }

    if (client.type === CONFIDENTAL_CLIENT && client.token_endpoint_auth_method === AUTH_METHOD_CLIENT_SECRET_BASIC) {
      if (type !== "Basic") {
        return [null, new BadRequestError({ key: "invalid_auth_method", params: { method: "Basic" } })];
      }

      if (client.secret !== secret) {
        return [null, new BadRequestError({ key: "invalid_client_credentials" })];
      }

      return [client, null];
    }
    return [null, new InternalError()];
  }

  let [client, err] = await get_client(client_id);
  if (err) {
    return [null, err];
  }

  if (client.type === CONFIDENTAL_CLIENT && client.token_endpoint_auth_method === AUTH_METHOD_CLIENT_SECRET_POST) {
    if (client.secret !== client_secret) {
      return [null, new BadRequestError({ key: "invalid_client_credentials" })];
    }
    return [client, null];
  } else if (client.type === PUBLIC_CLIENT) {
    return [client, null];
  }

  return [null, new InternalError()];
}
