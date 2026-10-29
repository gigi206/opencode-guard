// Renders an ANSI capture of tmux (`capture-pane -e`) with xterm.js in Chromium and saves it as a PNG.
// Usage: node render.cjs <capture.ansi> <out.png> <cols> <rows> [fontSize]; NODE_MODULES: where xterm and playwright are.
const fs = require("fs")
const path = require("path")
const nm = process.env.NODE_MODULES
const { chromium } = require(path.join(nm, "playwright"))
const [ansiFile, out, cols, rows, fontSize = "20"] = process.argv.slice(2)
const font = path.join(__dirname, "..", "..", "node_modules", "@fontsource", "jetbrains-mono", "files")
const b64 = (f) => fs.readFileSync(f).toString("base64")
// Each captured line at its own row: a full-width line would otherwise wrap onto the next one.
const data = fs.readFileSync(ansiFile, "utf8").replace(/\n$/, "").split("\n").map((line, i) => `\x1b[${i + 1};1H\x1b[0m${line}`).join("")
const html = `<!doctype html><html><head><meta charset="utf-8">
<style>
@font-face{font-family:JBM;src:url(data:font/woff2;base64,${b64(font + "/jetbrains-mono-latin-400-normal.woff2")})}
@font-face{font-family:JBM;font-weight:700;src:url(data:font/woff2;base64,${b64(font + "/jetbrains-mono-latin-700-normal.woff2")})}
${fs.readFileSync(nm + "/@xterm/xterm/css/xterm.css", "utf8")}
html,body{margin:0;background:#0a0a0a}#t{display:inline-block;padding:0}
</style></head><body><div id="t"></div>
<script>${fs.readFileSync(nm + "/@xterm/xterm/lib/xterm.js", "utf8")}</script>
<script>${fs.readFileSync(nm + "/@xterm/addon-webgl/lib/addon-webgl.js", "utf8")}</script>
<script>
document.fonts.load("20px JBM").then(()=>document.fonts.load("bold 20px JBM")).then(()=>{
const term=new Terminal({cols:${cols},rows:${rows},fontFamily:"JBM",fontSize:${fontSize},lineHeight:1.0,customGlyphs:true,allowProposedApi:true,
 theme:{background:"#0a0a0a",foreground:"#eeeeee",cursor:"#0a0a0a"},cursorStyle:"bar",cursorInactiveStyle:"none"});
term.open(document.getElementById("t"));
try{term.loadAddon(new WebglAddon.WebglAddon())}catch(e){}
term.write(${JSON.stringify("\x1b[?25l" + data)},()=>{window.done=true})})
</script></body></html>`
;(async () => {
  const browser = await chromium.launch({
    ...(process.env.CHROMIUM ? { executablePath: process.env.CHROMIUM } : {}),
    args: ["--use-gl=angle", "--use-angle=swiftshader", "--enable-unsafe-swiftshader"],
  })
  const page = await browser.newPage()
  await page.setContent(html)
  await page.waitForFunction(() => window.done === true)
  await page.waitForTimeout(400)
  await (await page.$(".xterm-screen")).screenshot({ path: out })
  await browser.close()
})()
