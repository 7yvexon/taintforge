import { createReadStream, existsSync, statSync } from "node:fs";
import { createServer } from "node:http";
import { extname, join, normalize, resolve, sep } from "node:path";
import { analyzeSource, rules } from "./src/analyzer.mjs";
import { fixtures } from "./src/fixtures.mjs";

const port = Number(process.env.PORT ?? 4173);
const publicDirectory = resolve("public");
const maxBodySize = 1_000_000;

const mimeTypes = {
  ".css": "text/css; charset=utf-8",
  ".html": "text/html; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml"
};

const sendJson = (response, status, body) => {
  response.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store"
  });
  response.end(JSON.stringify(body));
};

const withSecurityHeaders = (response) => {
  response.setHeader("X-Content-Type-Options", "nosniff");
  response.setHeader("Referrer-Policy", "no-referrer");
  response.setHeader("X-Frame-Options", "DENY");
  response.setHeader("Cross-Origin-Resource-Policy", "same-origin");
  response.setHeader("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'");
};

const readJsonBody = (request) => new Promise((resolveBody, rejectBody) => {
  let size = 0;
  const chunks = [];

  request.on("data", (chunk) => {
    size += chunk.length;

    if (size > maxBodySize) {
      rejectBody(new Error("Request body exceeds the 1 MB limit."));
      request.destroy();
      return;
    }

    chunks.push(chunk);
  });

  request.on("end", () => {
    try {
      resolveBody(JSON.parse(Buffer.concat(chunks).toString("utf8")));
    } catch {
      rejectBody(new Error("Request body must contain valid JSON."));
    }
  });

  request.on("error", rejectBody);
});

const serveStatic = (response, pathname) => {
  const requestedPath = pathname === "/" ? "index.html" : pathname.replace(/^\/+/, "");
  const filePath = normalize(join(publicDirectory, requestedPath));

  const isInsidePublicDirectory = filePath === publicDirectory || filePath.startsWith(`${publicDirectory}${sep}`);

  if (!isInsidePublicDirectory || !existsSync(filePath) || !statSync(filePath).isFile()) {
    sendJson(response, 404, { error: "Not found" });
    return;
  }

  response.writeHead(200, {
    "Content-Type": mimeTypes[extname(filePath)] ?? "application/octet-stream",
    "Cache-Control": "no-cache"
  });
  createReadStream(filePath).pipe(response);
};

const server = createServer(async (request, response) => {
  withSecurityHeaders(response);
  const requestUrl = new URL(request.url ?? "/", `http://${request.headers.host ?? "localhost"}`);

  if (request.method === "GET" && requestUrl.pathname === "/api/health") {
    sendJson(response, 200, { status: "ok", engine: "taintforge", version: "0.1.0" });
    return;
  }

  if (request.method === "GET" && requestUrl.pathname === "/api/fixtures") {
    sendJson(response, 200, fixtures.map(({ code, ...fixture }) => ({ ...fixture, lines: code.split("\n").length })));
    return;
  }

  if (request.method === "GET" && requestUrl.pathname.startsWith("/api/fixtures/")) {
    const id = requestUrl.pathname.split("/").at(-1);
    const fixture = fixtures.find((candidate) => candidate.id === id);

    if (!fixture) {
      sendJson(response, 404, { error: "Fixture not found" });
      return;
    }

    sendJson(response, 200, fixture);
    return;
  }

  if (request.method === "GET" && requestUrl.pathname === "/api/rules") {
    sendJson(response, 200, rules);
    return;
  }

  if (request.method === "POST" && requestUrl.pathname === "/api/analyze") {
    try {
      const payload = await readJsonBody(request);
      const result = analyzeSource({
        code: payload.code,
        language: payload.language,
        fileName: payload.fileName
      });
      sendJson(response, 200, result);
    } catch (error) {
      sendJson(response, 400, { error: error instanceof Error ? error.message : "Unable to analyze source." });
    }
    return;
  }

  if (request.method === "GET") {
    serveStatic(response, requestUrl.pathname);
    return;
  }

  sendJson(response, 405, { error: "Method not allowed" });
});

server.listen(port, "127.0.0.1", () => {
  process.stdout.write(`TaintForge is running at http://127.0.0.1:${port}\n`);
});
