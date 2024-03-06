async function sha1(data) {
  return await crypto.subtle.digest("SHA-1", data);
}
async function sha256(data) {
  return await crypto.subtle.digest("SHA-256", data);
}
async function sha384(data) {
  return await crypto.subtle.digest("SHA-384", data);
}
async function sha512(data) {
  return await crypto.subtle.digest("SHA-512", data);
}
export {
  sha1,
  sha256,
  sha384,
  sha512
};
//# sourceMappingURL=sha.js.map