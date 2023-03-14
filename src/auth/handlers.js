import fs from "fs";
import path from "path";
import jose from "node-jose";
import config from "../config/index.js";
import { option } from "../utils/index.js";
import { get_client, get_valid_client_scopes, get_valid_redirect_uri, is_valid_client_scope, is_valid_response_type } from "../client/services.js";
import { gen_id_token, gen_tokens, get_auth_req, insert_auth_req, insert_session, update_auth_req, verify_credentials } from "./services.js";
import { get_users_by_ids, insert_user } from "../user/services.js";
import { ValidationError } from "../utils/errors.js";

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
  let { uidx, redirect_uri } = req.body;
  let t = req.t;
  let uids = (req.session.get("uids") || "").split("|").filter(Boolean);
  let user_id = uids[uidx];

  let [valid_scopes, err] = await get_valid_client_scopes(scope, client_id);

  if (err) {
    req.flash("err", err.build(t));
    reply.redirect(req.url);
    return reply;
  }

  let has_sensitive_scopes = valid_scopes.some((scope) => scope.sensitive);

  if (has_sensitive_scopes) {
    reply.redirect("/oauth/consentsummary");
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

export async function handle_token(req, reply) {
  let t = req.t;
  let { grant_type, code, redirect_uri, code_verifier, client_id } = req.body;

  let [auth_req, err] = await get_auth_req({ client_id, code, redirect_uri });
  if (err) {
    return err.build(t);
  }

  let ks = fs.readFileSync(path.join(process.cwd(), config.jwks_file_name));
  let keystore = await jose.JWK.asKeyStore(ks.toString());
  let [key] = keystore.all({ use: 'sig' });

  let [id_token, iterr] = await gen_id_token(auth_req, key);
  if (iterr) {
    return iterr.build(t);
  }

  let [tokens, aterr] = await gen_tokens(auth_req, key);
  if (aterr) {
    return aterr.build(t);
  }

  let [_, uperr] = await option(update_auth_req(auth_req.id, { used: true }));

  if (uperr) {
    return uperr.build(t);
  }

  reply.send({
    id_token,
    access_token: tokens.access_token,
    refresh_token: tokens.refresh_token,
    token_type: "Bearer",
    expires_in: config.access_token_exp,
    scope: auth_req.scope
  });
  return reply;
}

export async function handle_get_jwks(req, reply) {
  let ks = fs.readFileSync(path.join(process.cwd(), config.jwks_file_name));
  let keystore = await jose.JWK.asKeyStore(ks.toString());

  return keystore.toJSON();
}
