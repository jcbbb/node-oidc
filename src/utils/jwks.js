import fs from "fs";
import jose from "node-jose";
import path from "path";
import config from "../config/index.js";

let ks = fs.readFileSync(path.join(process.cwd(), config.jwks_file_name));
export let keystore = await jose.JWK.asKeyStore(ks.toString());
