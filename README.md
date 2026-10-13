# Sara - Smart Recruitment Scam Detection

Zero-dependency full-stack app: Node.js 22.5+ (built-in HTTP + SQLite) and a vanilla JS front end.

## Run
    node --no-warnings server.js        # then open http://localhost:3000

The SQLite database and uploads are created in `data/` on first start.

## Admin
Default admin (change before deploying, via env vars):
- URL: `/#/admin-login`
- Email `admin@sara.local`, password `Admin@12345`
- Override with `ADMIN_EMAIL` / `ADMIN_PASSWORD` before the first start. `PORT` sets the port.

## Features
Sign up / sign in / sign out, profile (edit details, change password, delete account), ChatGPT-style scan
interface with + upload (photos via in-browser OCR, PDF/DOCX/TXT/CSV/HTML/EML read on the server), speedometer
risk gauge, per-user search history (reopen, search, delete, clear), community fraud alerts,
admin panel (stats, post/edit/delete alerts, manage users), blue cursor-slicing background effect.
