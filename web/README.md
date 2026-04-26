# MAADIF Web Dashboard

A modern React-based web interface for the MAADIF (Mobile & Application Analysis Docker Image Framework) system.

## Features

- **Dashboard** - Overview of tracked packages, analysis status, and system health
- **Version Tracker** - Track app versions from APKPure & Uptodown, filter by stable/beta
- **APK Library** - Browse downloaded APKs and trigger analysis
- **Analysis Jobs** - Track job progress and view detailed analysis results
- **Settings** - System configuration and tool status

## Tech Stack

- **React 19** + TypeScript
- **Vite** - Fast build tool with HMR
- **Tailwind CSS 4** - Utility-first styling
- **TanStack Query** - Data fetching and caching
- **Lucide React** - Beautiful icons
- **Axios** - HTTP client

## Prerequisites

- Node.js 18+
- MAADIF Java API server running on port 8080

## Quick Start

### 1. Install Dependencies

```bash
cd web
npm install
```

### 2. Start the API Server

In a separate terminal, start the MAADIF Java API server:

```bash
# From the maadif root directory
./run_server.sh
# Or with Docker
docker run -p 8080:8080 maadif
```

### 3. Start the Dev Server

```bash
npm run dev
```

The web app will be available at **http://localhost:5173**

## Project Structure

```
web/
├── src/
│   ├── api/
│   │   └── client.ts       # API client with all endpoints
│   ├── components/
│   │   ├── Layout.tsx      # Main layout with sidebar
│   │   ├── Dashboard.tsx   # Overview dashboard
│   │   ├── VersionTracker.tsx  # Version tracking UI
│   │   ├── ApkLibrary.tsx  # APK management
│   │   ├── AnalysisJobs.tsx    # Job tracking
│   │   └── Settings.tsx    # System settings
│   ├── types/
│   │   └── index.ts        # TypeScript interfaces
│   ├── App.tsx             # Main app component
│   ├── main.tsx            # Entry point
│   └── index.css           # Global styles + Tailwind
├── vite.config.ts          # Vite config with proxy
├── package.json
└── README.md
```

## API Proxy Configuration

The Vite dev server proxies API requests to the Java backend:

```typescript
// vite.config.ts
server: {
  proxy: {
    '/api': {
      target: 'http://localhost:8080',
      rewrite: (path) => path.replace(/^\/api/, '')
    }
  }
}
```

This means:
- Frontend: `fetch('/api/track/versions')`
- Proxies to: `http://localhost:8080/track/versions`

## Available Scripts

```bash
# Development with hot reload
npm run dev

# Type checking
npm run typecheck

# Build for production
npm run build

# Preview production build
npm run preview

# Lint code
npm run lint
```

## API Endpoints Used

### Version Tracking
- `GET /api/track/status` - Database status
- `GET /api/track/versions?package=com.whatsapp&channel=all` - List versions
- `GET /api/track/scrape?package=com.whatsapp` - Scrape new versions
- `POST /api/track/add` - Add package to track

### APK Management
- `GET /api/apks` - List available APKs
- `POST /api/download` - Download APK
- `GET /api/download/versions?package=...` - Get available versions

### Analysis
- `POST /api/analyze` - Start APK analysis
- `GET /api/status/{jobId}` - Get job status
- `GET /api/analysis/{jobId}` - Get analysis results
- `POST /api/native` - Analyze specific native library

### Health
- `GET /api/health` - System health check

## Customization

### Theming

Edit `src/index.css` to customize colors:

```css
@theme {
  --color-primary: #6366f1;
  --color-accent: #10b981;
  /* ... */
}
```

### Adding New Views

1. Create component in `src/components/`
2. Add to `Layout.tsx` nav items
3. Add case in `App.tsx` renderView()

## Production Build

```bash
npm run build
```

Output will be in `dist/` directory. Serve with any static file server:

```bash
npx serve dist
```

For production, configure your web server (nginx, etc.) to:
1. Serve static files from `dist/`
2. Proxy `/api/*` requests to the Java backend

### Example Nginx Config

```nginx
server {
    listen 80;

    location / {
        root /path/to/dist;
        try_files $uri $uri/ /index.html;
    }

    location /api/ {
        proxy_pass http://localhost:8080/;
    }
}
```

## Troubleshooting

### API Connection Failed
- Ensure Java server is running on port 8080
- Check CORS settings if running on different ports
- Verify network connectivity

### Build Errors
```bash
# Clear node_modules and reinstall
rm -rf node_modules package-lock.json
npm install
```

### Tailwind Not Working
Ensure `@import "tailwindcss"` is at the top of `index.css`

## License

MIT
