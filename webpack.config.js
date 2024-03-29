const path = require('path')

module.exports = {
  entry: ['./src/createWallet.js'],
  // devtool: 'source-map',
  mode: 'production',
  resolve: {
    extensions: ['.tsx', '.ts', '.js']
  },
  target: 'web',
  output: {
    filename: 'gate-wallet.js',
    path: path.resolve(__dirname, 'dist'),
    globalObject: "this",
    library: 'gateWallet',
    libraryTarget: 'umd'
  }
};
