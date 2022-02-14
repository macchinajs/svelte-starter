// import { rollupPlugin as externals } from "serverless-externals-plugin";
import externals from 'rollup-plugin-node-externals'
import nodeResolve from "@rollup/plugin-node-resolve";

/** @type {import('rollup').RollupOptions} */
const config = {
  input: "handler.js",
  output: {
    file: "./.dist/bundle.js",
    format: "esm",
    exports: "default",
  },
  treeshake: {
    moduleSideEffects: "no-external",
  },
  plugins: [
    externals(__dirname, { modules: ["aws-sdk"] }),
    // commonjs(),
    // nodeResolve({ preferBuiltins: true, exportConditions: ["node"] }),
  ],
};

export default config;
