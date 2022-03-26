import preprocess from "svelte-preprocess";
import path from "path";
import adapter from "@sveltejs/adapter-auto";

/** @type {import('@sveltejs/kit').Config} */
const config = {
  kit: {
    // hydrate the <div id="svelte"> element in src/app.html
    adapter: adapter(),
    vite: {
      // server: {
      //   hmr: {
      //     host: 'localhost',
      //     port: 15000,
      //     protocol: 'ws'
      //   }
      // },
      resolve: {
        alias: {
          $macchina: path.resolve("./src/lib/.macchina/"),
        },
      },
    },
  },

  preprocess: [
    preprocess({
      postcss: true,
    }),
  ],
};

export default config;
