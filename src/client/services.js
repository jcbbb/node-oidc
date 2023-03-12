import { pool } from "../db/pool.js";
import { BadRequestError, InternalError, ResourceNotFoundError } from "../utils/errors.js";
import { option, valid_uuid } from "../utils/index.js";

export async function get_client(id) {
  if (!valid_uuid(id)) {
    return [null, new BadRequestError({ key: "invalid_client_id" })]
  }

  let [result, err] = await option(pool.query("select * from clients where id = $1", [id]))

  if (err) {
    return [null, new InternalError()];
  }

  if (!result.rows.length) {
    return [null, new ResourceNotFoundError({ key: "client_not_found" })]
  }

  return [result.rows[0], null]
}

export async function get_client_scopes(id) {
  let [result, err] = await option(pool.query("select key, icon_uri, description from client_scopes cs join scope_translations st on st.scope_id = cs.scope_id join scopes s on s.id = cs.scope_id where cs.client_id = $1 and lang = 'en'", [id]))

  if (err) {
    return [null, new InternalError()]
  }

  return [result.rows, null]
}

export function get_valid_client_scopes(scope, client_scopes) {
  let scopes_arr = scope.split(" ");
  let valid_scopes = [];

  for (let scope of scopes_arr) {
    let found_scope = client_scopes.find(cs => cs.key === scope);
    if (found_scope) {
      valid_scopes.push(found_scope)
      continue
    } else {
      return [null, new BadRequestError({ key: "invalid_scope", params: { scope } })]
    }
  }

  return [valid_scopes, null]
}
