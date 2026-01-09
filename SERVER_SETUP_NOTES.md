# Server Setup Issues & Solutions

## Issue 1: better-sqlite3 Native Bindings Missing

### Problem
```
Error: Could not locate the bindings file
```

### Root Cause
`better-sqlite3` requires native C++ bindings that need to be compiled for your system. pnpm was blocking the build scripts by default for security reasons.

### Solution
```bash
# Manually build the native bindings
cd node_modules/.pnpm/better-sqlite3@11.10.0/node_modules/better-sqlite3
npm run build-release
```

## Issue 2: File API Not Defined in Node.js

### Problem
```
ReferenceError: File is not defined
```

### Root Cause
The `File` API is a browser-only API. The shared schema (`shared/schema/auth/index.ts`) uses `zfd.file()` from `zod-form-data`, which expects the `File` class to exist globally. This works in the browser but fails in Node.js.

### Solution
Created a polyfill that runs before the application starts:

**1. Created `server/polyfill.js`:**
```javascript
// Polyfill File for Node.js environment
const { File } = require("buffer");
globalThis.File = File;
```

**2. Modified `server/package.json`:**
```json
"dev": "tsx watch --clear-screen=false --require ./polyfill.js ./index.ts"
```

The `--require` flag ensures the polyfill loads before any other code, making the `File` class available globally in Node.js.

## Commands Successfully Executed

```bash
# 1. Generate migrations (no changes detected)
pnpm drizzle:generate

# 2. Apply migrations
pnpm drizzle:migrate

# 3. Seed database
pnpm drizzle:seed

# 4. Start dev server
pnpm dev
```

## Key Takeaway

When sharing schemas between client and browser that use browser-specific APIs (like `File`, `FormData`, etc.), you need to polyfill them in Node.js using the appropriate Node.js equivalents (available in the `buffer` module since Node.js v18+).

