# Cybermesh Security Dashboard

A React + Vite dashboard connected to the local CyberMesh scanner and file-based hash-chain ledger.

## Requirements
- Node.js (LTS)
- VS Code (recommended)

## Run locally
1. Open two terminals from the project folder.
2. In `Blockchain`, run `npm install` once, then `npm start`. The scanner listens on `http://127.0.0.1:3001`.
3. In `Cybermesh-Security-Dashboard-Source`, run `npm install` once, then `npm run dev`.
4. Open the local address Vite prints (usually `http://localhost:5173`).

## Deploy with Docker
From the project root, build the single-container app with `docker build -t cybermesh .`, then run it with a persistent volume and a private admin password:

```sh
docker run --name cybermesh -p 3001:3001 -v cybermesh-data:/data -e ADMIN_ID=admin -e ADMIN_PASSWORD="replace-with-a-private-password-of-12-or-more-characters" cybermesh
```

The container serves both the dashboard and API on port 3001. Keep the `/data` volume attached between restarts. The first start creates the local admin password hash on that volume. Run one replica because login sessions are held in process memory. Set the hosting platform's persistent disk mount to `/data` and configure `ADMIN_PASSWORD` as a private environment secret.

## What is included
- Responsive dark security dashboard UI
- Navigation sidebar
- Search/filter for websites and scan results
- Register websites and scan them through the backend
- SHA-256 HTML fingerprints and change detection against saved baselines
- Local JSON hash-chain records and integrity verification
- Scan history and change alerts backed by local files
- Local sign-in with a default account and an eight-hour browser session

## Important
Default local sign-in: **ID `admin`**, **password `CyberMesh@123`**. The account hash is in `Blockchain/local-auth.json`; successful sessions are held in backend memory and the browser stores a local session token. For Docker deployments, set `ADMIN_ID` and a private `ADMIN_PASSWORD`; the known local default is not included in the image. Restarting the backend signs the browser out.

The scanner performs basic HTTP page inspection. It crawls up to ten same-origin HTML pages and records raw-page SHA-256 hashes in `Blockchain/scan-records.json` and `Blockchain/blockchain.json`. Registered sites and scan history are stored in `Blockchain/monitored-sites.json` and `Blockchain/scan-history.json`. No database or remote account service is used. The local hash chain is not a decentralized blockchain, and a changed hash indicates a page change rather than proving malicious activity. Only scan websites you are authorized to inspect. The old standalone crawler in `cybermesh (2)/cybermesh` is independent and is not required by this dashboard.
