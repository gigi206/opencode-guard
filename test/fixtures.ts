// Fake secrets built at run time (no real key, nothing literal for a scanner to flag).
const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
export const rand = (length: number, seed = 7) => {
  let out = ""
  let x = seed
  for (let i = 0; i < length; i++) {
    x = (x * 1103515245 + 12345) % 2147483648
    out += chars[x % chars.length]
  }
  return out
}

export const FAKE = {
  openai: `sk-proj-${rand(40, 1)}`,
  anthropic: `sk-ant-api03-${rand(40, 2)}`,
  github: `ghp_${rand(36, 3)}`,
  aws: `AKIA${rand(16, 4).toUpperCase().replace(/[^A-Z0-9]/g, "Q")}`,
  slack: `xoxb-${rand(12, 5)}-${rand(24, 6)}`,
  google: `AIza${rand(35, 8)}`,
  jwt: `eyJ${rand(20, 9)}.eyJ${rand(30, 10)}.${rand(25, 11)}`,
  password: `Pa55${rand(10, 12)}`,
  privateKey: `-----BEGIN OPENSSH PRIVATE KEY-----\n${rand(64, 13)}\n${rand(64, 14)}\n-----END OPENSSH PRIVATE KEY-----`,
}
