export default [
  {
    ignores: [
      "node_modules/**",
      "public/**",
      "uploads/**",
      "views/**",
      "locales/**",
      "database.db",
      "eslint.config.js",
    ],
  },
  {
    files: ["**/*.js"],
    languageOptions: {
      ecmaVersion: "latest",
      sourceType: "commonjs",
      globals: {
        require: "readonly",
        module: "readonly",
        __dirname: "readonly",
        process: "readonly",
        console: "readonly",
        Buffer: "readonly",
      },
    },
    rules: {},
  },
];
