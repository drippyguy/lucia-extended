import { hash, verify } from "@node-rs/bcrypt";
class Bcrypt {
  constructor(options) {
    this.cost = options?.cost ?? 10;
  }
  cost;
  async hash(password) {
    return await hash(password.normalize("NFKC"), this.cost);
  }
  async verify(hash2, password) {
    return await verify(password.normalize("NFKC"), hash2);
  }
}
export {
  Bcrypt
};
//# sourceMappingURL=bcrypt.js.map