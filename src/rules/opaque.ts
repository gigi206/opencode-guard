// Files the plugin cannot read: OpenCode's `read` or a program that prints raw bytes hands them over, and the redaction
// of text and the output check see at best a part of them. Recognized by the end of the name; `read` also goes by the first
// bytes of the file, as OpenCode does (`credential-content.ts`).

export interface OpaqueRule {
  readonly id: string
  readonly reason: string
  /** Quick look at a command: it may name such a file. */
  readonly hint: RegExp
  /** A word, a pattern (`*.pdf`) or a brace list (`a.{txt,pdf}`, `{a.pdf,b.txt}`) that names such a file. */
  readonly names: (file: string) => boolean
}

function opaque(id: string, reason: string, extensions: readonly string[]): OpaqueRule {
  const list = extensions.join("|")
  const named = new RegExp(`\\.(?:${list})$|\\.\\{(?:[^{},]*,)*(?:${list})(?:,[^{},]*)*\\}$|\\{(?:[^{},]*,)*[^{},]*\\.(?:${list})(?:,[^{},]*)*\\}$`, "i")
  return {
    id,
    reason,
    hint: new RegExp(`\\.(?:\\{|${list})`, "i"),
    names: (file) => named.test(file),
  }
}

/** Evaluation order: a name has one last extension, so at most one rule. */
export const OPAQUE_RULES: readonly OpaqueRule[] = [
  opaque("opaque-document", "the guard plugin cannot see inside this document: answering yes lets it through unchecked", ["pdf", "doc", "docx", "docm", "xls", "xlsx", "xlsm", "ppt", "pptx", "pptm", "odt", "ods", "odp", "rtf"]),
  opaque("opaque-image", "the guard plugin cannot see inside this image: answering yes lets it through unchecked", ["png", "jpg", "jpeg", "gif", "webp", "bmp", "tif", "tiff"]),
]

/** Rule that names the file. */
export const opaqueRule = (path: string): OpaqueRule | undefined => (path ? OPAQUE_RULES.find((rule) => rule.names(path)) : undefined)
