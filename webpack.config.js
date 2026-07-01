const path = require('path');
const CopyPlugin = require('copy-webpack-plugin');
const HtmlWebpackPlugin = require('html-webpack-plugin');
const MiniCssExtractPlugin = require('mini-css-extract-plugin');
const TerserPlugin = require('terser-webpack-plugin');

module.exports = {
  entry: {
    'background/service-worker': './src/background/service-worker.ts',
    'content/scanner':           './src/content/scanner.ts',
    'content/monitor':           './src/content/monitor.ts',
    'content/overlay':           './src/content/overlay.ts',
    'popup/popup':               './src/popup/popup.ts',
    'popup/settings':            './src/popup/settings.ts',
    'sidepanel/sidepanel':       './src/sidepanel/sidepanel.ts',
    'offscreen/offscreen':       './src/offscreen/offscreen.ts',
  },

  output: {
    path: path.resolve(__dirname, 'dist'),
    filename: '[name].js',
    clean: true,
    environment: {
      arrowFunction: true,
      const: true,
    },
  },

  resolve: {
    extensions: ['.ts', '.tsx', '.js'],
    alias: {
      '@types': path.resolve(__dirname, 'src/types'),
      '@utils': path.resolve(__dirname, 'src/utils'),
      '@ml': path.resolve(__dirname, 'src/ml-inference'),
    },
  },

  module: {
    rules: [
      {
        test: /\.tsx?$/,
        use: 'ts-loader',
        exclude: /node_modules/,
      },
      {
        test: /\.css$/,
        use: [MiniCssExtractPlugin.loader, 'css-loader'],
      },
    ],
  },

  plugins: [
    new MiniCssExtractPlugin({
      filename: '[name].css',
    }),
    new CopyPlugin({
      patterns: [
        { from: 'manifest.json', to: '.' },
        { from: 'public/icons', to: 'icons' },
        { from: 'models', to: 'models' },
        // settings.html is now handled by HtmlWebpackPlugin (inline script removed, compiled settings.js injected)
        {
          from: 'node_modules/@tensorflow/tfjs-backend-wasm/dist/*.wasm',
          to: '[name][ext]',
          noErrorOnMissing: true,
        },
      ],
    }),
    new HtmlWebpackPlugin({
      template: './src/popup/popup.html',
      filename: 'popup/popup.html',
      chunks: ['popup/popup'],
      inject: true,
    }),
    new HtmlWebpackPlugin({
      template: './src/sidepanel/sidepanel.html',
      filename: 'sidepanel/sidepanel.html',
      chunks: ['sidepanel/sidepanel'],
      inject: true,
    }),
    new HtmlWebpackPlugin({
      template: './src/offscreen/offscreen.html',
      filename: 'offscreen/offscreen.html',
      chunks: ['offscreen/offscreen'],
      inject: true,
    }),
    new HtmlWebpackPlugin({
      template: './src/popup/settings.html',
      filename: 'popup/settings.html',
      chunks: ['popup/settings'],
      inject: true,
    }),
  ],

  // Chrome extensions cannot use eval — required for MV3
  devtool: false,

  optimization: {
    minimize: true,
    minimizer: [
      new TerserPlugin({
        parallel: false,
        exclude: /node_modules/,
        terserOptions: {
          compress: { passes: 1 },
          mangle: true,
        },
      }),
    ],
  },
};
