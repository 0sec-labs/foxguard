# foxguard.dev

Marketing site for foxguard, built with Astro.

## Requirements

- Node `22.23.4` or newer
- `nvm use` from the repo root if your shell picks an older Node binary

## Commands

Run from `www/`:

```sh
npm ci
npm run dev
npm run build
npm run preview
```

## Notes

- CI builds this site with Node `22.23.4`
- If `npm run build` reports Node `18.x`, your PATH is resolving the wrong `node` binary for npm scripts
