import preprocess from "svelte-preprocess";
import vercel from '@sveltejs/adapter-vercel';
import path from 'path'

/** @type {import('@sveltejs/kit').Config} */
const config = {
  kit: {
    // hydrate the <div id="svelte"> element in src/app.html
    target: '#svelte',
    adapter: vercel(),
    vite: {
      server: {
        hmr: {
          host: 'localhost',
          port: 15000,
          protocol: 'ws'
        }
      },
      resolve: {
        alias: {
          $fabo: path.resolve('./src/lib/.fabo/'),
        }
      }
    }
  },
  preprocess: [preprocess({
      "postcss": true
  })]
};

export default config;
