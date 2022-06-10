const path = require('path')

module.exports = {
  entry: ['./src/index.js'],
  // devtool: 'source-map',
  mode: 'production',
  resolve: {
    extensions: ['.tsx', '.ts', '.js']
  },
  output: {
    filename: 'gate-wallet.js',
    path: path.resolve(__dirname, 'dist'),
    globalObject: "this",
    library: 'gateWallet',
    libraryTarget: 'umd'
  },
};