import { NODE_ENV } from "./secrets.js";
import { configs } from "./configs.js";

let env = NODE_ENV || "development";

export default configs[env];
