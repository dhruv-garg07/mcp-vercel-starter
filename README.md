# MCP Server — Vercel (FastAPI)

This is a minimal MCP server ready for **Vercel Serverless Functions**.

## Routes (public)
- `GET /mcp` — Manifest (name, version, tools)
- `POST /mcp/validate` — Checks bearer token and returns your phone (digits only)
- `POST /mcp/run` — Runs `ping` or `echo`

Vercel serves Python functions from `/api/*`. We keep the code in `api/mcp.py` and use `vercel.json` to **rewrite** `/mcp*` to `/api/mcp*`, so Puch can call `/mcp` directly.

## Env Vars (set in Vercel → Project → Settings → Environment Variables)
- `AUTH_TOKEN` — your secret (aka *devtoken*)
- `PHONE_E164` — your phone like `919876543210` (digits only)

## Deploy (3 steps)
1. Push these files to a GitHub repo.
2. On Vercel: **New Project → Import** your repo → Deploy.
3. After deploy, add the two env vars above and redeploy.

## Connect from WhatsApp (Puch)
```
/mcp connect https://<your-vercel-domain>.vercel.app/mcp <AUTH_TOKEN>
```
On success, you'll receive a share link like `https://puch.ai/mcp/<server_id>` — submit `<server_id>` to the hackathon.