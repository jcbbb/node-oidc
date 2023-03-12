import { get_client, get_client_scopes, get_valid_client_scopes } from "../client/services.js";
import { get_sessions_by_ids, insert_session, verify_credentials } from "./services.js";
import { get_users_by_ids, insert_user } from "../user/services.js";

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
    req.flash("err", uerr.build(req.t))
    reply.redirect(err_to)
    return reply;
  }

  let [session, serr] = await insert_session(user_id, req.ip)

  if (serr) {
    req.flash("err", serr.build(req.t))
    reply.redirect(err_to)
    return reply;
  }

  req.session.set("sid", session.id);
  let sids = req.session.get("sids") || "";
  if (sids.length) {
    sids += "|" + session.id
  } else {
    sids = session.id
  }
  req.session.set("sids", sids);
}

export async function handle_login(req, reply) {
  let [user, uerr] = await verify_credentials(req.body);

  if (uerr) {
    req.flash("err", uerr.build(req.t))
    reply.redirect(err_to)
    return reply;
  }

  let [session, serr] = await insert_session(user.id, req.ip)

  if (serr) {
    req.flash("err", serr.build(req.t))
    reply.redirect(err_to)
    return reply;
  }

  req.session.set("sid", session.id)
}

export function handle_error_view(req, reply) {
  let { err } = req.query;
  err = JSON.parse(Buffer.from(err, "base64").toString())
  reply.render("auth/error", { title: "Error", err })
  return reply;
}

export async function handle_consent_view(req, reply) {
  let { client_id, redirect_uri, code_challenge, code_challenge_method, scope, response_type, state } = req.query;
  let [client, cerr] = await get_client(client_id)
  let flash = reply.flash();
  let t = req.t;

  if (cerr) {
    reply.redirect(`/oauth/error?err=${cerr.b64(t)}`)
    return reply;
  }

  let [client_scopes, cserr] = await get_client_scopes(client_id)

  if (cserr) {
    reply.redirect(`/oauth/error?err=${cserr.b64(t)}`)
    return reply;
  }

  let [valid_scopes, vserr] = get_valid_client_scopes(scope, client_scopes)

  if (vserr) {
    reply.redirect(`/oauth/error?err=${vserr.b64(t)}`)
    return reply;
  }

  let sids = (req.session.get("sids") || "").split("|");

  let [sessions, serr] = await get_sessions_by_ids(sids)

  if (serr) {
    reply.redirect(`/oauth/error?err=${serr.b64(t)}`)
    return reply;
  }

  let [users, uerr] = await get_users_by_ids(sessions.map(s => s.user_id))

  if (uerr) {
    reply.redirect(`/oauth/error?err=${uerr.b64(t)}`)
    return reply;
  }

  reply.render("auth/consent", { client, users, title: "Choose account", flash, valid_scopes })
  return reply;
}

export function handle_consent(req, reply) {}
