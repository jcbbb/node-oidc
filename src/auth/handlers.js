import config from "../config/index.js";
import { get_client, get_valid_client_scopes, get_valid_redirect_uri, get_verified_client, is_valid_client_scope, is_valid_response_type } from "../client/services.js";
import { gen_tokens, get_auth_req, get_auth_req_by_id, get_refresh_token, insert_auth_req, insert_session, update_auth_req, update_refresh_token, verify_code_challenge, verify_credentials } from "./services.js";
import { get_users_by_ids, get_user_by_id, insert_user } from "../user/services.js";
import { ValidationError } from "../utils/errors.js";
import { keystore } from "../utils/jwks.js";

export async function handle_signup_view(req, reply) {
  let flash = reply.flash();
  let { method } = req.query;
  reply.render("auth/signup", { method, title: "Signup", flash });
  return reply;
}

export function handle_login_view(req, reply) {
  let flash = reply.flash();
  let { method } = req.query;
  reply.render("auth/login", { method, title: "Login", flash });
  return reply;
}

export async function handle_signup(req, reply) {
  let { err_to } = req.query;
  let [user_id, uerr] = await insert_user(req.body);

  if (uerr) {
    req.flash("err", uerr.build(req.t));
    reply.redirect(err_to);
    return reply;
  }

  let [session, serr] = await insert_session(user_id, req.ip);

  if (serr) {
    req.flash("err", serr.build(req.t));
    reply.redirect(err_to);
    return reply;
  }

  req.session.set("sid", session.id);
  let uids = req.session.get("uids") || "";
  if (uids.length) {
    uids += "|" + user_id;
  } else {
    uids = String(user_id);
  }
  req.session.set("uids", uids);
}

export async function handle_login(req, reply) {
  let { err_to } = req.query;
  let [user, uerr] = await verify_credentials(req.body);

  if (uerr) {
    req.flash("err", uerr.build(req.t));
    reply.redirect(err_to);
    return reply;
  }

  let [session, serr] = await insert_session(user.id, req.ip);

  if (serr) {
    req.flash("err", serr.build(req.t));
    reply.redirect(err_to);
    return reply;
  }

  req.session.set("sid", session.id);
}

export function handle_error_view(req, reply) {
  let { err } = req.query;
  err = JSON.parse(Buffer.from(err, "base64url").toString());
  reply.render("auth/error", { title: "Error", err });
  return reply;
}

export async function handle_consent_view(req, reply) {
  let { client_id, redirect_uri, code_challenge, code_challenge_method = "plain", scope, response_type, state } = req.query;
  let flash = reply.flash();
  let t = req.t;

  if (req.validationError) {
    let err = new ValidationError({ errors: req.validationError.validation });
    reply.redirect(`/oauth/error?err=${err.b64(t)}`);
    return reply;
  }

  let [client, cerr] = await get_client(client_id);

  if (cerr) {
    reply.redirect(`/oauth/error?err=${cerr.b64(t)}`);
    return reply;
  }

  let [_, vserr] = await is_valid_client_scope(scope, client_id);

  if (vserr) {
    reply.redirect(`/oauth/error?err=${vserr.b64(t)}`);
    return reply;
  }

  let rterr = await is_valid_response_type(response_type, client_id);

  if (rterr) {
    reply.redirect(`/oauth/error?err=${rterr.b64(t)}`);
    return reply;
  }

  let [valid_redirect_uri, vrerr] = await get_valid_redirect_uri(redirect_uri, client_id);

  if (vrerr) {
    reply.redirect(`/oauth/error?err=${vrerr.b64(t)}`);
    return reply;
  }

  let uids = (req.session.get("uids") || "").split("|").filter(Boolean);

  let [users, uerr] = await get_users_by_ids(uids);

  if (uerr) {
    reply.redirect(`/oauth/error?err=${uerr.b64(t)}`);
    return reply;
  }

  reply.render("auth/consent", {
    title: "Choose account",
    client,
    users,
    flash,
    valid_redirect_uri,
    code_challenge,
    code_challenge_method,
    state,
    response_type
  });

  return reply;
}

export async function handle_consent(req, reply) {
  let { client_id, code_challenge, code_challenge_method = "plain", response_type, state, scope } = req.query;
  let { user_id, redirect_uri } = req.body;
  let t = req.t;

  let [valid_scopes, err] = await get_valid_client_scopes(scope, client_id);

  if (err) {
    req.flash("err", err.build(t));
    reply.redirect(req.url);
    return reply;
  }

  let has_sensitive_scopes = valid_scopes.some((scope) => scope.sensitive);

  if (has_sensitive_scopes) {
    let query = req.url.slice(req.url.indexOf("?"));
    req.session.set("suid", user_id);
    reply.redirect(`/oauth/consent-summary${query}`);
    return reply;
  }

  let valid_scope_str = valid_scopes.map((scope) => scope.key).join(" ");
  let [auth_req, aerr] = await insert_auth_req({ client_id, code_challenge, code_challenge_method, response_type, state, scope: valid_scope_str, user_id, redirect_uri });

  if (aerr) {
    req.flash("err", aerr.build(t));
    reply.redirect(req.url);
    return reply;
  }

  let uri = `${redirect_uri}?code=${auth_req.code}`;

  if (state) {
    uri += `&state=${state}`;
  }

  reply.redirect(uri);
  return reply;
}

export async function handle_consent_summary_view(req, reply) {
  let { client_id, code_challenge, code_challenge_method, response_type, state, scope, redirect_uri } = req.query;
  let user_id = req.session.get("suid");
  let t = req.t;

  let [user, uerr] = await get_user_by_id(user_id);
  if (uerr) {
    reply.redirect(`/oauth/error?err=${uerr.b64(t)}`);
    return reply;
  }

  let [client, cerr] = await get_client(client_id);

  if (cerr) {
    reply.redirect(`/oauth/error?err=${cerr.b64(t)}`);
    return reply;
  }

  let [valid_scopes, err] = await get_valid_client_scopes(scope, client_id);

  if (err) {
    req.flash("err", err.build(t));
    reply.redirect(req.url);
    return reply;
  }

  let [valid_redirect_uri, vrerr] = await get_valid_redirect_uri(redirect_uri, client_id);
  if (vrerr) {
    req.flash("err", vrerr.build(t));
    reply.redirect(req.url);
    return reply;
  }

  reply.render("auth/consent-summary", {
    title: "Choose permissions",
    client,
    valid_scopes,
    user,
    valid_redirect_uri
  });

  return reply;
}

export async function handle_consent_summary(req, reply) {
  let { client_id, code_challenge, code_challenge_method = "plain", response_type, state } = req.query;
  let { selected_scopes, redirect_uri, _action } = req.body;
  let user_id = req.session.get("suid");
  let t = req.t;

  if (_action === "cancel") {
    let uri = `${redirect_uri}?error=access_denied`;
    if (state) {
      uri += `&state=${state}`;
    }
    reply.redirect(uri);
    return reply;
  }

  let scope = selected_scopes;
  if (Array.isArray(selected_scopes)) {
    scope = selected_scopes.join(" ");
  }

  let [auth_req, aerr] = await insert_auth_req({ client_id, code_challenge, code_challenge_method, response_type, state, scope, user_id, redirect_uri });
  if (aerr) {
    return aerr.build(t);
  }

  let uri = `${redirect_uri}?code=${auth_req.code}`;

  if (state) {
    uri += `&state=${state}`;
  }

  reply.redirect(uri);
  return reply;
}


export async function handle_token(req, reply) {
  let t = req.t;
  let { grant_type, code, redirect_uri, code_verifier, client_id, client_secret, refresh_token } = req.body;

  let [client, cerr] = await get_verified_client(client_id, client_secret, req.headers["authorization"]);
  if (cerr) {
    reply.code(cerr.status_code);
    return cerr.build(t);
  }

  switch (grant_type) {
    case "authorization_code": {
      let [auth_req, err] = await get_auth_req({ client_id: client.id, code, redirect_uri });
      if (err) {
        reply.code(err.status_code);
        return err.build(t);
      }

      let [valid, verr] = await verify_code_challenge(auth_req, code_verifier);
      if (verr) {
        reply.code(verr.status_code);
        return verr.build(t);
      }

      let [key] = keystore.all({ use: "sig" });

      let [tokens, aterr] = await gen_tokens(auth_req, key);
      if (aterr) {
        reply.code(aterr.status_code);
        return aterr.build(t);
      }

      let [_, uperr] = await update_auth_req(auth_req.id, { used: true });
      if (uperr) {
        reply.code(uperr.status_code);
        return uperr.build(t);
      }

      reply.send(Object.assign(tokens, { token_type: "Bearer", expires_in: config.access_token_exp, scope: auth_req.scope }));
      return reply;
    }

    case "refresh_token": {
      let [token, err] = await get_refresh_token(refresh_token);
      if (err)  {
        reply.code(err.status_code);
        return err.build(t);
      }

      let [auth_req, aerr] = await get_auth_req_by_id(token.auth_req_id);
      if (aerr) {
        reply.code(aerr.status_code);
        return aerr.build(t);
      }

      let [key] = keystore.all({ use: "sig" });
      let [tokens, terr] = await gen_tokens(auth_req, key);
      if (terr) {
        reply.code(terr.code);
        return terr.build(t);
      }

      let [_, uperr] = await update_refresh_token(refresh_token, { active: false });
      if (uperr) {
        reply.code(uperr.code);
        return uperr.build(t);
      }

      reply.send(Object.assign(tokens, { token_type: "Bearer", expires_in: config.access_token_exp, scope: auth_req.scope }));
      return reply;
    }
    default:
      break;
  }
}

export async function handle_get_jwks(req, reply) {
  return keystore.toJSON();
}

export async function handle_oidc_config(req, reply) {
  reply.send({
    issuer: config.issuer,
    authorization_endpoint: config.origin + "/oauth/authorize",
    token_endpoint: config.origin + "/oauth/token",
    userinfo_endpoint: config.origin + "/userinfo",
    jwks_uri: config.origin + "/oauth/jwks",
    response_types_supported: ["code", "token"],
    subject_types_supported: ["public"],
    id_token_signing_alg_values_supported: ["RS256"],
    scopes_supported: ["openid", "profile"],
    token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post"],
    claims_supported: [
      "aud",
      "email",
      "email_verified",
      "exp",
      "family_name",
      "given_name",
      "iat",
      "iss",
      "picture",
      "name",
      "sub"
    ],
    code_challenge_methods_supported: ["plain", "S256"],
    grant_types_supported: ["authorization_code", "refresh_token"]
  });

  return reply;
}

export async function handle_userinfo(req, reply) {
  // not imlemented yet
  reply.send("NOT IMPLEMENTED");
  return reply;
}
