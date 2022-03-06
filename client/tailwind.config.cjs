module.exports = {
  purge: ["./src/**/*.{html,js,svelte,ts}"],

  // or 'media' or 'class'
  darkMode: false,

  theme: {
    extend: {},
  },

  variants: {
    extend: {},
  },

  plugins: [require("daisyui")],
  content: ["./src/**/*.{html,js,svelte,ts}"],
};
