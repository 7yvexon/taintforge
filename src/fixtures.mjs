export const fixtures = [
  {
    id: "node-gateway",
    name: "Node gateway",
    language: "javascript",
    fileName: "gateway.js",
    description: "A deliberately vulnerable API gateway fixture.",
    code: `import express from "express";
import { exec } from "node:child_process";
import fs from "node:fs";

const app = express();
app.use(express.json());

app.get("/proxy", async (req, res) => {
  const endpoint = req.query.target;
  const response = await fetch(endpoint);
  res.send(await response.text());
});

app.get("/search", async (req, res) => {
  const term = req.query.q;
  const result = await db.query("SELECT * FROM users WHERE name = '" + term + "'");
  res.json(result.rows);
});

app.post("/archive", (req, res) => {
  const archive = req.body.file;
  exec("tar -xf " + archive);
  res.sendStatus(202);
});

app.get("/download", (req, res) => {
  const requestedFile = req.query.file;
  res.sendFile("/srv/public/" + requestedFile);
});

app.post("/preview", (req, res) => {
  const markup = req.body.content;
  preview.innerHTML = markup;
  res.sendStatus(204);
});

app.listen(3000);`
  },
  {
    id: "python-worker",
    name: "Python worker",
    language: "python",
    fileName: "worker.py",
    description: "A deliberately vulnerable Python service fixture.",
    code: `from flask import Flask, request
import requests
import subprocess

app = Flask(__name__)

@app.get("/relay")
def relay():
    target = request.args.get("target")
    return requests.get(target).text

@app.get("/users")
def users():
    term = request.args.get("q")
    return cursor.execute("SELECT * FROM users WHERE name = '" + term + "'")

@app.post("/extract")
def extract():
    archive = request.json.get("archive")
    subprocess.run("tar -xf " + archive, shell=True)
    return {"queued": True}

@app.get("/file")
def read_file():
    name = request.args.get("name")
    return open("/srv/public/" + name).read()`
  },
  {
    id: "safe-service",
    name: "Hardened service",
    language: "javascript",
    fileName: "hardened-service.js",
    description: "A safer reference fixture with validated inputs.",
    code: `import express from "express";

const app = express();
const allowedHosts = new Set(["api.github.com", "api.example.com"]);

app.get("/proxy", async (req, res) => {
  const target = new URL(String(req.query.target));

  if (!allowedHosts.has(target.hostname)) {
    return res.status(400).json({ error: "Blocked host" });
  }

  const response = await fetch(target);
  res.send(await response.text());
});

app.get("/search", async (req, res) => {
  const term = String(req.query.q ?? "");
  const result = await db.query("SELECT * FROM users WHERE name = $1", [term]);
  res.json(result.rows);
});

app.listen(3000);`
  }
];

export const getFixture = (id) => fixtures.find((fixture) => fixture.id === id);
