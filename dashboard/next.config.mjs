// Static export served by the Spring server on the admin port (DECISIONS #47).
// In `next dev`, /api is proxied to the admin listener so the dashboard can be developed against bootRun.
const isDev = process.env.NODE_ENV !== "production";

/** @type {import('next').NextConfig} */
const config = {
  output: isDev ? undefined : "export",
  trailingSlash: true,
  images: { unoptimized: true },
  poweredByHeader: false,
  reactStrictMode: true,
  ...(isDev
    ? {
        async rewrites() {
          return [{ source: "/api/:path*", destination: "http://127.0.0.1:8445/api/:path*" }];
        },
      }
    : {}),
};

export default config;
