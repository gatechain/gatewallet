const path = require("path");

module.exports = {
  entry: ["./src/createWallet.js"],
  mode: "production",
  resolve: {
    extensions: [".js"],
  },
  target: "web",
  output: {
    filename: "gate-wallet.js",
    path: path.resolve(__dirname, "dist"),
    globalObject: "this",
    library: "gateWallet",
    libraryTarget: "umd",
  },
};
